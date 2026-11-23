import Foundation
import Darwin

final class IPChecker {
    private let clashClient = ClashSocketClient()

    private func makeFreshSession(timeout: TimeInterval = 8) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout + 4
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpShouldSetCookies = false
        return URLSession(configuration: config)
    }

    func runFullCheck(reason: String) async -> DetectionSnapshot {
        let session = makeFreshSession(timeout: 8)
        let fastSession = makeFreshSession(timeout: 3)
        defer {
            session.finishTasksAndInvalidate()
            fastSession.finishTasksAndInvalidate()
        }

        let clashState = clashClient.fetchState()

        // Run all primary network probes concurrently
        async let claudeTraceTask = fetchCloudflareTrace(session: session, urlString: "https://claude.ai/cdn-cgi/trace")
        async let anthropicApiTraceTask = fetchCloudflareTrace(session: session, urlString: "https://api.anthropic.com/cdn-cgi/trace")
        async let cfTraceTask = fetchCloudflareTrace(session: session, urlString: "https://1.1.1.1/cdn-cgi/trace")
        async let dnsTask = fetchDNSLeak(session: session)
        async let directTask = fetchDirectIP(session: session)
        async let ipv6Task = fetchIPv6Raw(session: fastSession)
        async let stunTask = fetchSTUNMappedIPAsync()

        let (claude, anthropicApi, cf, rawDNS, direct, rawIPv6, rawStunIP) = await (
            claudeTraceTask, anthropicApiTraceTask, cfTraceTask, dnsTask, directTask, ipv6Task, stunTask
        )

        var claudeExit = claude
        var cfExit = cf
        let targetIP = !claudeExit.ip.isEmpty ? claudeExit.ip : cfExit.ip

        var risk = RiskAssessment()
        if !targetIP.isEmpty {
            async let ipqueryTask = fetchIPQuery(session: session, ip: targetIP)
            async let proxycheckTask = fetchProxyCheck(session: session, ip: targetIP)
            async let ipapiTask = fetchFromIPApi(session: session, ip: targetIP)

            let (iq, pc, ia) = await (ipqueryTask, proxycheckTask, ipapiTask)
            let (mergedMeta, mergedRisk) = combineIPIntelligence(ip: targetIP, ipquery: iq, proxycheck: pc, ipapi: ia)
            risk = mergedRisk
            if !claudeExit.ip.isEmpty {
                claudeExit = mergeDetail(base: claudeExit, meta: mergedMeta)
            } else {
                cfExit = mergeDetail(base: cfExit, meta: mergedMeta)
            }
        }

        if !cfExit.ip.isEmpty && cfExit.ip == claudeExit.ip {
            var same = claudeExit
            same.colo = cfExit.colo
            same.latencyMs = cfExit.latencyMs
            cfExit = same
        }

        // Evaluate DNS leak
        var dns = rawDNS
        dns.countryCode = ClaudeRegionChecker.countryCodeFromName(dns.country)
        dns.countryMatchesExit = dns.countryCode.isEmpty || claudeExit.countryCode.isEmpty || dns.countryCode == claudeExit.countryCode
        dns.status = evaluateDNSStatus(dns: dns, exitCountryCode: claudeExit.countryCode)

        // Evaluate IPv6 leak
        let ipv6 = await evaluateIPv6(session: fastSession, rawIPv6: rawIPv6, exitCountryCode: claudeExit.countryCode)

        // Evaluate UDP STUN / WebRTC leak
        let stun = evaluateSTUN(mappedIP: rawStunIP, claudeIP: claudeExit.ip, directIP: direct.ip)

        // Evaluate Cross-Domain Route Consistency
        let routeConsistency = evaluateRouteConsistency(
            claudeWeb: claudeExit,
            anthropicApi: anthropicApi,
            cf: cfExit
        )

        // Evaluate Timezone offset
        let tzCheck = evaluateTimezone(ipTimezone: claudeExit.timezone)

        let effectiveCode = claudeExit.countryCode.isEmpty ? cfExit.countryCode : claudeExit.countryCode
        let claudeSupported = ClaudeRegionChecker.isSupported(countryCode: effectiveCode)

        let (level, summary, alerts) = evaluateOverall(
            claudeExit: claudeExit,
            claudeSupported: claudeSupported,
            dns: dns,
            ipv6: ipv6,
            stun: stun,
            routeConsistency: routeConsistency,
            risk: risk
        )

        let now = Date()
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]

        return DetectionSnapshot(
            overallLevel: level,
            overallSummary: summary,
            riskAlerts: alerts,
            claudeSupported: claudeSupported,
            claudeExit: claudeExit,
            anthropicApiExit: anthropicApi,
            cloudflareExit: cfExit,
            directExit: direct,
            dns: dns,
            ipv6: ipv6,
            stun: stun,
            routeConsistency: routeConsistency,
            risk: risk,
            timezoneCheck: tzCheck,
            stability: IPStabilityInfo(),
            clash: clashState,
            triggerReason: reason,
            updatedAt: now,
            updatedAtISO: iso.string(from: now),
            errorMessage: claudeExit.ip.isEmpty ? "无法连接 claude.ai 检测出口" : nil
        )
    }

    // MARK: - Probes

    private func fetchCloudflareTrace(session: URLSession, urlString: String) async -> IPDetail {
        guard let url = URL(string: urlString) else { return IPDetail() }
        var req = URLRequest(url: url)
        req.setValue("ClaudeIPGuard/2.0", forHTTPHeaderField: "User-Agent")

        let start = CFAbsoluteTimeGetCurrent()
        do {
            let (data, _) = try await session.data(for: req)
            let elapsedMs = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
            guard let text = String(data: data, encoding: .utf8) else { return IPDetail() }

            var kv: [String: String] = [:]
            for line in text.split(separator: "\n") {
                let parts = line.split(separator: "=", maxSplits: 1)
                if parts.count == 2 {
                    kv[String(parts[0]).trimmingCharacters(in: .whitespaces)] =
                        String(parts[1]).trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }

            var detail = IPDetail()
            detail.ip = kv["ip"] ?? ""
            detail.countryCode = (kv["loc"] ?? "").uppercased()
            detail.colo = kv["colo"] ?? ""
            detail.latencyMs = elapsedMs
            return detail
        } catch {
            return IPDetail()
        }
    }

    private func fetchDNSLeak(session: URLSession) async -> DNSCheckResult {
        for attempt in 0..<2 {
            let result = await fetchDNSLeakOnce(session: session)
            if !result.ip.isEmpty {
                return result
            }
            if attempt == 0 {
                try? await Task.sleep(nanoseconds: 450_000_000)
            }
        }
        return DNSCheckResult()
    }

    private func fetchDNSLeakOnce(session: URLSession) async -> DNSCheckResult {
        let randHex = (0..<16).map { _ in String(format: "%02x", UInt8.random(in: 0...255)) }.joined()
        guard let url = URL(string: "https://\(randHex).edns.ip-api.com/json") else {
            return DNSCheckResult()
        }
        var req = URLRequest(url: url)
        req.setValue("ClaudeIPGuard/2.1", forHTTPHeaderField: "User-Agent")

        do {
            let (data, _) = try await session.data(for: req)
            guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let dnsObj = root["dns"] as? [String: Any] else {
                return DNSCheckResult()
            }
            let ip = (dnsObj["ip"] as? String) ?? ""
            let geo = (dnsObj["geo"] as? String) ?? ""

            var country = ""
            var provider = geo
            if let dashRange = geo.range(of: " - ") {
                country = String(geo[..<dashRange.lowerBound]).trimmingCharacters(in: .whitespaces)
                provider = String(geo[dashRange.upperBound...]).trimmingCharacters(in: .whitespaces)
            }

            let lowerGeo = geo.lowercased()
            let lowerCountry = country.lowercased()
            let chinaKeywords = [
                "china unicom", "china telecom", "china mobile", "chinanet", "cmnet",
                "china169", "alibaba", "aliyun", "tencent", "dnspod", "cnnic", "cernet", "baidu"
            ]
            let isMainlandCountry = (lowerCountry == "china" || lowerCountry == "cn")
            let hasChinaISP = chinaKeywords.contains(where: { lowerGeo.contains($0) })
            let isChinaDNS = isMainlandCountry || hasChinaISP

            return DNSCheckResult(
                status: .unknown,
                ip: ip,
                geo: geo,
                country: country,
                countryCode: "",
                provider: provider,
                isChinaDNS: isChinaDNS,
                countryMatchesExit: true
            )
        } catch {
            return DNSCheckResult()
        }
    }

    private func fetchDirectIP(session: URLSession) async -> DirectIPInfo {
        guard let url = URL(string: "https://myip.ipip.net/json") else { return DirectIPInfo() }
        var req = URLRequest(url: url)
        req.setValue("ClaudeIPGuard/2.0", forHTTPHeaderField: "User-Agent")

        do {
            let (data, _) = try await session.data(for: req)
            guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let payload = root["data"] as? [String: Any] else {
                return DirectIPInfo()
            }
            let ip = (payload["ip"] as? String) ?? ""
            let locArr = (payload["location"] as? [String]) ?? []
            let loc = locArr.filter { !$0.isEmpty }.joined(separator: " ")
            return DirectIPInfo(ip: ip, location: loc)
        } catch {
            return DirectIPInfo()
        }
    }

    private func fetchIPv6Raw(session: URLSession) async -> String? {
        guard let url = URL(string: "https://api6.ipify.org?format=json") else { return nil }
        do {
            let (data, _) = try await session.data(from: url)
            if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
               let ip = json["ip"] as? String,
               ip.contains(":") {
                return ip
            }
        } catch {
            return nil
        }
        return nil
    }

    // Native RFC 5389 UDP STUN Binding Request
    private func fetchSTUNMappedIPAsync() async -> String? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let ip = Self.querySTUN(host: "stun.cloudflare.com", port: 3478)
                    ?? Self.querySTUN(host: "stun.l.google.com", port: 19302)
                continuation.resume(returning: ip)
            }
        }
    }

    private static func querySTUN(host: String, port: UInt16) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        let portStr = String(port)
        guard getaddrinfo(host, portStr, &hints, &res) == 0, let info = res else {
            return nil
        }
        defer { freeaddrinfo(res) }

        let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 2, tv_usec: 500_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        // Build 20-byte RFC 5389 STUN Binding Request
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0x00; packet[1] = 0x01 // Binding Request
        packet[2] = 0x00; packet[3] = 0x00 // Length 0
        packet[4] = 0x21; packet[5] = 0x12; packet[6] = 0xA4; packet[7] = 0x42 // Magic Cookie
        for i in 8..<20 {
            packet[i] = UInt8.random(in: 0...255)
        }

        let sent = sendto(fd, packet, packet.count, 0, info.pointee.ai_addr, info.pointee.ai_addrlen)
        guard sent == packet.count else { return nil }

        var buffer = [UInt8](repeating: 0, count: 512)
        let received = recvfrom(fd, &buffer, buffer.count, 0, nil, nil)
        guard received >= 28 else { return nil }

        var idx = 20
        while idx + 4 <= received {
            let attrType = (UInt16(buffer[idx]) << 8) | UInt16(buffer[idx + 1])
            let attrLen = Int((UInt16(buffer[idx + 2]) << 8) | UInt16(buffer[idx + 3]))
            let valStart = idx + 4
            guard valStart + attrLen <= received else { break }

            if attrType == 0x0020 && attrLen >= 8 && buffer[valStart + 1] == 0x01 {
                // XOR-MAPPED-ADDRESS IPv4
                let b0 = buffer[valStart + 4] ^ 0x21
                let b1 = buffer[valStart + 5] ^ 0x12
                let b2 = buffer[valStart + 6] ^ 0xA4
                let b3 = buffer[valStart + 7] ^ 0x42
                return "\(b0).\(b1).\(b2).\(b3)"
            } else if attrType == 0x0001 && attrLen >= 8 && buffer[valStart + 1] == 0x01 {
                // MAPPED-ADDRESS IPv4
                let b0 = buffer[valStart + 4]
                let b1 = buffer[valStart + 5]
                let b2 = buffer[valStart + 6]
                let b3 = buffer[valStart + 7]
                return "\(b0).\(b1).\(b2).\(b3)"
            }

            let paddedLen = (attrLen + 3) & ~3
            idx = valStart + paddedLen
        }
        return nil
    }

    // MARK: - Dual-Engine IP Risk & Metadata

    private func fetchIPQuery(session: URLSession, ip: String) async -> [String: Any]? {
        guard let url = URL(string: "https://api.ipquery.io/\(ip)") else { return nil }
        do {
            let (data, _) = try await session.data(from: url)
            return try JSONSerialization.jsonObject(with: data) as? [String: Any]
        } catch {
            return nil
        }
    }

    private func fetchProxyCheck(session: URLSession, ip: String) async -> [String: Any]? {
        guard let url = URL(string: "https://proxycheck.io/v2/\(ip)?vpn=1&asn=1&risk=1") else { return nil }
        do {
            let (data, _) = try await session.data(from: url)
            guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (root["status"] as? String) == "ok",
                  let entry = root[ip] as? [String: Any] else {
                return nil
            }
            return entry
        } catch {
            return nil
        }
    }

    private func fetchFromIPApi(session: URLSession, ip: String) async -> [String: Any]? {
        let urlString = "http://ip-api.com/json/\(ip)?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,timezone,mobile,proxy,hosting,query"
        guard let url = URL(string: urlString) else { return nil }
        do {
            let (data, _) = try await session.data(from: url)
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (json["status"] as? String) == "success" else {
                return nil
            }
            return json
        } catch {
            return nil
        }
    }

    private func combineIPIntelligence(
        ip: String,
        ipquery: [String: Any]?,
        proxycheck: [String: Any]?,
        ipapi: [String: Any]?
    ) -> (IPDetail, RiskAssessment) {
        var detail = IPDetail(ip: ip)
        var risk = RiskAssessment()

        // 1. ip-api.com baseline
        if let ia = ipapi {
            detail.country = (ia["country"] as? String) ?? ""
            detail.countryCode = ((ia["countryCode"] as? String) ?? "").uppercased()
            detail.region = (ia["regionName"] as? String) ?? ""
            detail.city = (ia["city"] as? String) ?? ""
            detail.isp = (ia["isp"] as? String) ?? ""
            detail.org = (ia["org"] as? String) ?? ""
            detail.timezone = (ia["timezone"] as? String) ?? ""
            if let lat = ia["lat"] as? Double, let lon = ia["lon"] as? Double {
                detail.latitude = lat
                detail.longitude = lon
            }
            if let asField = ia["as"] as? String {
                detail.asn = asField.split(separator: " ").first.map(String.init) ?? asField
            }
            detail.isMobile = (ia["mobile"] as? Bool) ?? false
            detail.isProxy = (ia["proxy"] as? Bool) ?? false
            detail.isHosting = (ia["hosting"] as? Bool) ?? false
            risk.isMobile = risk.isMobile || detail.isMobile
            risk.isProxy = risk.isProxy || detail.isProxy
            risk.isDatacenter = risk.isDatacenter || detail.isHosting
            risk.sources.append("ip-api")
        }

        // 2. ipquery.io risk intelligence
        if let iq = ipquery {
            if let ispObj = iq["isp"] as? [String: Any] {
                if detail.asn.isEmpty, let asn = ispObj["asn"] as? String { detail.asn = asn }
                if detail.isp.isEmpty, let isp = ispObj["isp"] as? String { detail.isp = isp }
                if detail.org.isEmpty, let org = ispObj["org"] as? String { detail.org = org }
            }
            if let loc = iq["location"] as? [String: Any] {
                if detail.country.isEmpty, let c = loc["country"] as? String { detail.country = c }
                if detail.countryCode.isEmpty, let cc = loc["country_code"] as? String { detail.countryCode = cc.uppercased() }
                if detail.region.isEmpty, let st = loc["state"] as? String { detail.region = st }
                if detail.city.isEmpty, let city = loc["city"] as? String { detail.city = city }
                if detail.timezone.isEmpty, let tz = loc["timezone"] as? String { detail.timezone = tz }
                if detail.latitude == nil, let lat = loc["latitude"] as? Double, let lon = loc["longitude"] as? Double {
                    detail.latitude = lat
                    detail.longitude = lon
                }
            }
            if let r = iq["risk"] as? [String: Any] {
                let score = (r["risk_score"] as? Int) ?? 0
                risk.ipqueryScore = score
                risk.isVPN = risk.isVPN || ((r["is_vpn"] as? Bool) ?? false)
                risk.isProxy = risk.isProxy || ((r["is_proxy"] as? Bool) ?? false)
                risk.isTor = risk.isTor || ((r["is_tor"] as? Bool) ?? false)
                risk.isDatacenter = risk.isDatacenter || ((r["is_datacenter"] as? Bool) ?? false)
                risk.isMobile = risk.isMobile || ((r["is_mobile"] as? Bool) ?? false)
            }
            risk.sources.append("ipquery")
        }

        // 3. proxycheck.io risk intelligence + rDNS
        if let pc = proxycheck {
            if detail.asn.isEmpty, let asn = pc["asn"] as? String { detail.asn = asn }
            if detail.isp.isEmpty, let prov = pc["provider"] as? String { detail.isp = prov }
            if detail.country.isEmpty, let c = pc["country"] as? String { detail.country = c }
            if detail.countryCode.isEmpty, let cc = pc["isocode"] as? String { detail.countryCode = cc.uppercased() }
            if detail.region.isEmpty, let reg = pc["region"] as? String { detail.region = reg }
            if detail.city.isEmpty, let city = pc["city"] as? String { detail.city = city }
            if detail.timezone.isEmpty, let tz = pc["timezone"] as? String { detail.timezone = tz }
            if detail.latitude == nil, let lat = pc["latitude"] as? Double, let lon = pc["longitude"] as? Double {
                detail.latitude = lat
                detail.longitude = lon
            }
            if let host = pc["hostname"] as? String, !host.isEmpty {
                risk.rdns = host
            }
            if let pcRisk = pc["risk"] as? Int {
                risk.proxycheckScore = pcRisk
            }
            let isProxyStr = ((pc["proxy"] as? String) ?? "no").lowercased()
            let typeStr = ((pc["type"] as? String) ?? "").lowercased()
            if isProxyStr == "yes" {
                risk.isProxy = true
            }
            if typeStr.contains("vpn") {
                risk.isVPN = true
            }
            if typeStr.contains("hosting") || typeStr.contains("datacenter") {
                risk.isDatacenter = true
            }
            risk.sources.append("proxycheck")
        }

        // Final risk score (max of available engines)
        let scores = [risk.ipqueryScore, risk.proxycheckScore].compactMap { $0 }
        risk.score = scores.max() ?? (risk.isProxy || risk.isVPN ? 65 : (risk.isDatacenter ? 35 : 0))

        detail.isHosting = risk.isDatacenter
        detail.isProxy = risk.isProxy || risk.isVPN || risk.isTor
        detail.isMobile = risk.isMobile

        if risk.isTor || risk.isVPN || risk.isProxy {
            detail.ipType = .proxy
        } else if risk.isDatacenter {
            detail.ipType = .datacenter
        } else if risk.isMobile {
            detail.ipType = .mobile
        } else if !risk.sources.isEmpty {
            detail.ipType = .residential
        } else {
            detail.ipType = .unknown
        }

        return (detail, risk)
    }

    private func mergeDetail(base: IPDetail, meta: IPDetail) -> IPDetail {
        var merged = meta
        merged.ip = base.ip.isEmpty ? meta.ip : base.ip
        if !base.countryCode.isEmpty {
            merged.countryCode = base.countryCode
        }
        merged.colo = base.colo
        merged.latencyMs = base.latencyMs
        return merged
    }

    // MARK: - Evaluators

    private func evaluateDNSStatus(dns: DNSCheckResult, exitCountryCode: String) -> DNSLeakStatus {
        guard !dns.ip.isEmpty else { return .unknown }
        if dns.isChinaDNS { return .leaked }

        let lowerProvider = dns.provider.lowercased()
        let trustedGlobalResolvers = ["cloudflare", "google", "quad9", "opendns", "cisco", "nextdns", "adguard"]
        if !dns.countryCode.isEmpty && !exitCountryCode.isEmpty && dns.countryCode != exitCountryCode {
            if trustedGlobalResolvers.contains(where: { lowerProvider.contains($0) }) {
                return .warning
            }
            return .warning
        }
        return .safe
    }

    private func evaluateIPv6(session: URLSession, rawIPv6: String?, exitCountryCode: String) async -> IPv6CheckResult {
        guard let v6 = rawIPv6, !v6.isEmpty else {
            return IPv6CheckResult(
                status: .safe,
                ip: "",
                label: "已屏蔽 / 无泄露",
                detail: "IPv6 未暴露"
            )
        }
        // Check country of leaked IPv6
        if let meta = await fetchFromIPApi(session: session, ip: v6) {
            let cc = ((meta["countryCode"] as? String) ?? "").uppercased()
            let country = (meta["country"] as? String) ?? cc
            if !ClaudeRegionChecker.isSupported(countryCode: cc) {
                return IPv6CheckResult(
                    status: .danger,
                    ip: v6,
                    label: "IPv6 泄露(\(cc))",
                    detail: "\(v6) · \(country)"
                )
            }
            if !exitCountryCode.isEmpty && cc != exitCountryCode {
                return IPv6CheckResult(
                    status: .warning,
                    ip: v6,
                    label: "双栈跨区(\(cc))",
                    detail: "\(v6) · \(country)"
                )
            }
            return IPv6CheckResult(
                status: .safe,
                ip: v6,
                label: "同区双栈(\(cc))",
                detail: "\(v6) · \(country)"
            )
        }
        return IPv6CheckResult(
            status: .warning,
            ip: v6,
            label: "检测到 IPv6",
            detail: v6
        )
    }

    private func evaluateSTUN(mappedIP: String?, claudeIP: String, directIP: String) -> STUNCheckResult {
        guard let stunIP = mappedIP, !stunIP.isEmpty else {
            return STUNCheckResult(
                status: .safe,
                mappedIP: "",
                label: "UDP 受控/未泄露",
                detail: "STUN 未返回本地公网 IP"
            )
        }
        if !directIP.isEmpty && stunIP == directIP && stunIP != claudeIP {
            return STUNCheckResult(
                status: .danger,
                mappedIP: stunIP,
                label: "UDP 本地泄露",
                detail: "STUN 暴露国内 IP: \(stunIP)"
            )
        }
        if !claudeIP.isEmpty && stunIP == claudeIP {
            return STUNCheckResult(
                status: .safe,
                mappedIP: stunIP,
                label: "无泄露 · 一致",
                detail: stunIP
            )
        }
        return STUNCheckResult(
            status: .warning,
            mappedIP: stunIP,
            label: "出口不一致",
            detail: "STUN: \(stunIP)"
        )
    }

    private func evaluateRouteConsistency(
        claudeWeb: IPDetail,
        anthropicApi: IPDetail,
        cf: IPDetail
    ) -> RouteConsistencyResult {
        let webIP = claudeWeb.ip
        let apiIP = anthropicApi.ip
        let cfIP = cf.ip

        if webIP.isEmpty {
            return RouteConsistencyResult(
                status: .danger,
                claudeWebIP: webIP,
                anthropicApiIP: apiIP,
                cloudflareIP: cfIP,
                allMatch: false,
                label: "Claude 不可达",
                detail: "claude.ai 探测失败"
            )
        }

        if !apiIP.isEmpty && apiIP != webIP {
            let webLoc = claudeWeb.countryCode
            let apiLoc = anthropicApi.countryCode
            let crossCountry = !webLoc.isEmpty && !apiLoc.isEmpty && webLoc != apiLoc
            return RouteConsistencyResult(
                status: crossCountry ? .danger : .warning,
                claudeWebIP: webIP,
                anthropicApiIP: apiIP,
                cloudflareIP: cfIP,
                allMatch: false,
                label: crossCountry ? "跨国分流异常" : "API 出口不同",
                detail: "Web: \(webIP)(\(webLoc)) vs API: \(apiIP)(\(apiLoc))"
            )
        }

        if !cfIP.isEmpty && cfIP != webIP {
            return RouteConsistencyResult(
                status: .warning,
                claudeWebIP: webIP,
                anthropicApiIP: apiIP,
                cloudflareIP: cfIP,
                allMatch: false,
                label: "CF 出口分流",
                detail: "Claude: \(webIP) / CF: \(cfIP)"
            )
        }

        return RouteConsistencyResult(
            status: .safe,
            claudeWebIP: webIP,
            anthropicApiIP: apiIP,
            cloudflareIP: cfIP,
            allMatch: true,
            label: "全站一致",
            detail: "Web / API / CF 出口完全一致"
        )
    }

    private func evaluateTimezone(ipTimezone: String) -> TimezoneCheckResult {
        let localTZ = TimeZone.current
        guard !ipTimezone.isEmpty, let remoteTZ = TimeZone(identifier: ipTimezone) else {
            return TimezoneCheckResult(localTimezone: localTZ.identifier, ipTimezone: ipTimezone, hourDiff: nil, label: "")
        }
        let diffHours = Double(remoteTZ.secondsFromGMT() - localTZ.secondsFromGMT()) / 3600.0
        let label: String
        if abs(diffHours) < 0.01 {
            label = "时区一致"
        } else {
            let sign = diffHours > 0 ? "+" : ""
            let formatted = diffHours.truncatingRemainder(dividingBy: 1) == 0
                ? String(format: "%.0f", diffHours)
                : String(format: "%.1f", diffHours)
            label = "时差 \(sign)\(formatted)h"
        }
        return TimezoneCheckResult(
            localTimezone: localTZ.identifier,
            ipTimezone: ipTimezone,
            hourDiff: diffHours,
            label: label
        )
    }

    private func evaluateOverall(
        claudeExit: IPDetail,
        claudeSupported: Bool,
        dns: DNSCheckResult,
        ipv6: IPv6CheckResult,
        stun: STUNCheckResult,
        routeConsistency: RouteConsistencyResult,
        risk: RiskAssessment
    ) -> (OverallLevel, String, [String]) {
        var dangers: [String] = []
        var warnings: [String] = []

        if claudeExit.ip.isEmpty {
            dangers.append("无法连接 Claude 出口")
        }
        if dns.status == .leaked {
            dangers.append("DNS 泄露至中国大陆（\(dns.provider)）")
        } else if dns.status == .warning {
            warnings.append("DNS 出口（\(dns.countryCode)）与节点跨区")
        } else if dns.status == .unknown {
            warnings.append("DNS 检测失败，无法确认是否存在泄露")
        }
        if !claudeExit.ip.isEmpty && !claudeSupported {
            dangers.append("当前出口地区（\(claudeExit.countryCode)）不支持 Claude")
        }
        if ipv6.status == .danger {
            dangers.append("检测到 IPv6 泄露（\(ipv6.label)）")
        } else if ipv6.status == .warning {
            warnings.append("IPv6 出口与 IPv4 跨区")
        }
        if stun.status == .danger {
            dangers.append("UDP / WebRTC 泄露本地真实 IP")
        } else if stun.status == .warning {
            warnings.append("UDP STUN 出口与主代理不一致")
        }
        if routeConsistency.status == .danger {
            dangers.append("Anthropic 网页与 API 跨国分流")
        } else if routeConsistency.status == .warning {
            warnings.append(routeConsistency.label)
        }

        if risk.isTor {
            dangers.append("出口 IP 被标记为 Tor 节点")
        } else if risk.score >= 60 {
            dangers.append("IP 风险分过高（\(risk.score)/100）")
        } else if risk.isVPN || risk.isProxy {
            warnings.append("IP 存在 VPN/Proxy 标记（风险分 \(risk.score)）")
        } else if risk.isDatacenter || risk.score >= 20 {
            warnings.append("当前为机房 IP 或风险分偏高（\(risk.score)/100）")
        }

        if let firstDanger = dangers.first {
            return (.danger, firstDanger, dangers + warnings)
        }
        if let firstWarning = warnings.first {
            return (.warning, firstWarning, warnings)
        }

        let place = claudeExit.country.isEmpty ? claudeExit.countryCode : claudeExit.country
        let shortType: String
        switch claudeExit.ipType {
        case .residential: shortType = "住宅 IP"
        case .mobile: shortType = "移动 IP"
        case .datacenter: shortType = "机房 IP"
        case .proxy: shortType = "代理 IP"
        case .unknown: shortType = "常规 IP"
        }
        return (.safe, "\(shortType) · \(place) · 风险分 \(risk.score) · 无泄露", [])
    }
}
