import Foundation
import Network
import Combine
import AppKit

enum RefreshIntervalOption: Int, CaseIterable, Identifiable {
    case onChangeOnly = 0
    case oneMinute = 60
    case fiveMinutes = 300
    case tenMinutes = 600

    var id: Int { rawValue }

    var label: String {
        switch self {
        case .onChangeOnly: return "仅节点/网络变化时"
        case .oneMinute: return "每 1 分钟"
        case .fiveMinutes: return "每 5 分钟（推荐）"
        case .tenMinutes: return "每 10 分钟"
        }
    }
}

enum MenuBarDisplayStyle: String, CaseIterable {
    case compact
    case withIP

    var label: String {
        switch self {
        case .compact: return "简洁（地区 + 状态）"
        case .withIP: return "完整（地区 + IP）"
        }
    }
}

@MainActor
final class MonitorStore: ObservableObject {
    @Published var snapshot: DetectionSnapshot = .initial
    @Published var isChecking: Bool = false
    @Published var copiedToast: String? = nil
    @Published var isFloatingVisible: Bool = false
    @Published var floatingAlwaysOnTop: Bool = true {
        didSet {
            UserDefaults.standard.set(floatingAlwaysOnTop, forKey: "floatingAlwaysOnTop")
            onFloatingStyleChanged?()
        }
    }
    @Published var alertsEnabled: Bool = true {
        didSet {
            UserDefaults.standard.set(alertsEnabled, forKey: "alertsEnabled")
        }
    }
    @Published var launchAtLogin: Bool = false {
        didSet {
            guard !isSyncingLaunchAtLogin else { return }
            setLaunchAtLogin(enabled: launchAtLogin)
        }
    }
    private var isSyncingLaunchAtLogin: Bool = false
    @Published var refreshInterval: RefreshIntervalOption = .fiveMinutes {
        didSet {
            UserDefaults.standard.set(refreshInterval.rawValue, forKey: "refreshInterval")
            reschedulePeriodicTimer()
        }
    }
    @Published var menuBarStyle: MenuBarDisplayStyle = .compact {
        didSet {
            UserDefaults.standard.set(menuBarStyle.rawValue, forKey: "menuBarStyle")
            onSnapshotUpdated?(snapshot, isChecking)
        }
    }

    var onSnapshotUpdated: ((DetectionSnapshot, Bool) -> Void)?
    var onToggleFloating: (() -> Void)?
    var onFloatingStyleChanged: (() -> Void)?

    private let checker = IPChecker()
    private let clashClient = ClashSocketClient()
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "com.claudeipguard.nwpath")

    private var clashPollTimer: Timer?
    private var periodicTimer: Timer?
    private var debounceTask: Task<Void, Never>?
    private var checkTask: Task<Void, Never>?
    private var lastClashSignature: String = ""
    private var lastPathSummary: String = ""
    private var httpServer: LocalHTTPServer?

    private struct DriftEvent {
        let timestamp: Date
        let severity: CheckState
        let distanceKm: Int?
        let route: String
        let detail: String
    }

    // IP Stability & Alert tracking
    private var trackedExit: IPDetail? = nil
    private var trackedNodeSig: String = ""
    private var sessionIPChangeCount: Int = 0
    private var unexpectedDriftCount: Int = 0
    private var recentDrifts: [DriftEvent] = []
    private var lastIPChangedAt: String = ""
    private var lastAlertSummary: String = ""
    private var lastAlertTime: Date = .distantPast

    private let stateLock = NSLock()
    private var threadSafeSnapshot: DetectionSnapshot = .initial

    init() {
        if let savedInterval = RefreshIntervalOption(rawValue: UserDefaults.standard.integer(forKey: "refreshInterval")),
           UserDefaults.standard.object(forKey: "refreshInterval") != nil {
            self.refreshInterval = savedInterval
        }
        if let savedStyleRaw = UserDefaults.standard.string(forKey: "menuBarStyle"),
           let savedStyle = MenuBarDisplayStyle(rawValue: savedStyleRaw) {
            self.menuBarStyle = savedStyle
        }
        if UserDefaults.standard.object(forKey: "floatingAlwaysOnTop") != nil {
            self.floatingAlwaysOnTop = UserDefaults.standard.bool(forKey: "floatingAlwaysOnTop")
        }
        if UserDefaults.standard.object(forKey: "alertsEnabled") != nil {
            self.alertsEnabled = UserDefaults.standard.bool(forKey: "alertsEnabled")
        }
        isSyncingLaunchAtLogin = true
        self.launchAtLogin = FileManager.default.fileExists(atPath: Self.launchAgentPlistPath)
        isSyncingLaunchAtLogin = false
    }

    private static var launchAgentPlistPath: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return "\(home)/Library/LaunchAgents/com.claudeipguard.agent.plist"
    }

    private func setLaunchAtLogin(enabled: Bool) {
        let plistPath = Self.launchAgentPlistPath
        let fm = FileManager.default

        if enabled {
            let execPath = Bundle.main.executablePath ?? ProcessInfo.processInfo.arguments.first ?? "/Applications/ClaudeIPGuard.app/Contents/MacOS/ClaudeIPGuard"
            let dir = (plistPath as NSString).deletingLastPathComponent
            try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)

            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.claudeipguard.agent</string>
                <key>ProgramArguments</key>
                <array>
                    <string>\(execPath)</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
                <key>KeepAlive</key>
                <dict>
                    <key>SuccessfulExit</key>
                    <false/>
                </dict>
                <key>ProcessType</key>
                <string>Interactive</string>
            </dict>
            </plist>
            """
            try? plist.write(toFile: plistPath, atomically: true, encoding: .utf8)
            copiedToast = "已开启开机自启"
        } else {
            try? fm.removeItem(atPath: plistPath)
            copiedToast = "已关闭开机自启"
        }

        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 1_600_000_000)
            if self?.copiedToast == "已开启开机自启" || self?.copiedToast == "已关闭开机自启" {
                self?.copiedToast = nil
            }
        }
    }

    func start() {
        startHTTPServer()
        startClashWatcher()
        startNetworkPathWatcher()
        reschedulePeriodicTimer()
        triggerCheck(reason: "启动检测")
    }

    func stop() {
        clashPollTimer?.invalidate()
        periodicTimer?.invalidate()
        pathMonitor.cancel()
        httpServer?.stop()
    }

    func latestThreadSafeSnapshot() -> DetectionSnapshot {
        stateLock.lock()
        defer { stateLock.unlock() }
        return threadSafeSnapshot
    }

    func triggerCheck(reason: String, completion: ((DetectionSnapshot) -> Void)? = nil) {
        debounceTask?.cancel()
        checkTask?.cancel()
        isChecking = true
        onSnapshotUpdated?(snapshot, true)

        checkTask = Task { [weak self] in
            guard let self = self else { return }
            let result = await self.checker.runFullCheck(reason: reason)
            if Task.isCancelled { return }
            let enriched = self.applyStabilityAndAlerts(to: result)
            self.applySnapshot(enriched)
            completion?(enriched)
        }
    }

    private static func haversineKm(lat1: Double, lon1: Double, lat2: Double, lon2: Double) -> Int {
        let r = 6371.0
        let dLat = (lat2 - lat1) * .pi / 180.0
        let dLon = (lon2 - lon1) * .pi / 180.0
        let a = sin(dLat / 2) * sin(dLat / 2)
            + cos(lat1 * .pi / 180.0) * cos(lat2 * .pi / 180.0) * sin(dLon / 2) * sin(dLon / 2)
        let c = 2 * atan2(sqrt(a), sqrt(max(0, 1 - a)))
        return Int((r * c).rounded())
    }

    private func applyStabilityAndAlerts(to raw: DetectionSnapshot) -> DetectionSnapshot {
        var result = raw
        let now = result.updatedAt
        let newExit = result.claudeExit
        let newIP = newExit.ip
        let newNodeSig = result.clash.signature

        // Keep only drift events within the trailing 60-minute sliding window
        recentDrifts = recentDrifts.filter { now.timeIntervalSince($0.timestamp) <= 3600 }

        if !newIP.isEmpty {
            if let prev = trackedExit, !prev.ip.isEmpty, newIP != prev.ip {
                sessionIPChangeCount += 1
                let f = DateFormatter()
                f.dateFormat = "HH:mm:ss"
                lastIPChangedAt = f.string(from: now)

                let nodeChanged = (newNodeSig != trackedNodeSig)
                if nodeChanged {
                    // User manually switched proxy node: reset automatic drift history for the new node
                    recentDrifts.removeAll()
                } else {
                    unexpectedDriftCount += 1
                    let crossCountry = !prev.countryCode.isEmpty && !newExit.countryCode.isEmpty
                        && prev.countryCode != newExit.countryCode
                    let asnChanged = !prev.asn.isEmpty && !newExit.asn.isEmpty && prev.asn != newExit.asn
                    let regionChanged = !prev.region.isEmpty && !newExit.region.isEmpty
                        && prev.region.lowercased() != newExit.region.lowercased()

                    var distKm: Int? = nil
                    if let lat1 = prev.latitude, let lon1 = prev.longitude,
                       let lat2 = newExit.latitude, let lon2 = newExit.longitude {
                        distKm = Self.haversineKm(lat1: lat1, lon1: lon1, lat2: lat2, lon2: lon2)
                    }

                    let fromLabel = regionChanged
                        ? (prev.region.isEmpty ? prev.city : prev.region)
                        : (!prev.city.isEmpty ? prev.city : (!prev.region.isEmpty ? prev.region : prev.countryCode))
                    let toLabel = regionChanged
                        ? (newExit.region.isEmpty ? newExit.city : newExit.region)
                        : (!newExit.city.isEmpty ? newExit.city : (!newExit.region.isEmpty ? newExit.region : newExit.countryCode))
                    let routeText = (!fromLabel.isEmpty && !toLabel.isEmpty) ? "\(fromLabel) → \(toLabel)" : ""

                    let severity: CheckState
                    let detail: String
                    if crossCountry {
                        severity = .danger
                        detail = "跨国漂移：\(prev.countryCode) → \(newExit.countryCode)"
                    } else if let km = distKm, km > 500 {
                        severity = .danger
                        detail = "超远跨城：\(routeText)（约 \(km)km）"
                    } else if let km = distKm, km > 80 {
                        severity = .warning
                        detail = "跨城漂移：\(routeText)（约 \(km)km）"
                    } else if distKm == nil && regionChanged {
                        severity = .warning
                        detail = "跨区漂移：\(routeText)"
                    } else if asnChanged {
                        severity = .warning
                        detail = "跨运营商漂移（\(prev.asn) → \(newExit.asn)）"
                    } else {
                        severity = .safe
                        let distPart = distKm.map { "约 \($0)km · " } ?? ""
                        detail = "同城微漂移（\(distPart)正常家宽波动）"
                    }

                    recentDrifts.append(DriftEvent(
                        timestamp: now,
                        severity: severity,
                        distanceKm: distKm,
                        route: routeText,
                        detail: detail
                    ))
                }
            }
            trackedExit = newExit
            trackedNodeSig = newNodeSig
        }

        var stability = IPStabilityInfo()
        stability.sessionChangeCount = sessionIPChangeCount
        stability.unexpectedDriftCount = unexpectedDriftCount
        stability.recentDriftCount1h = recentDrifts.count
        stability.lastChangedAt = lastIPChangedAt

        let latestEvent = recentDrifts.last
        let worstDanger = recentDrifts.last(where: { $0.severity == .danger })
        let worstWarning = recentDrifts.last(where: { $0.severity == .warning })

        if let best = worstDanger ?? worstWarning ?? latestEvent {
            stability.lastDriftDistanceKm = best.distanceKm
            stability.lastDriftRoute = best.route
        }

        if recentDrifts.isEmpty {
            stability.status = .safe
            stability.label = sessionIPChangeCount > 0
                ? "稳定 · 手动切换 \(sessionIPChangeCount) 次"
                : "稳定 · 无异常跳变"
        } else if let dangerEvt = worstDanger {
            stability.status = .danger
            stability.label = dangerEvt.detail
            result.riskAlerts.append(dangerEvt.detail)
            if result.overallLevel != .danger {
                result.overallLevel = .danger
                result.overallSummary = dangerEvt.detail
            }
        } else if recentDrifts.count >= 4 {
            stability.status = .danger
            stability.label = "高频漂移（\(recentDrifts.count)次/1h）"
            result.riskAlerts.append("1 小时内出口 IP 自动漂移 \(recentDrifts.count) 次（疑似动态轮换池）")
            if result.overallLevel != .danger {
                result.overallLevel = .danger
                result.overallSummary = "1 小时内高频漂移 \(recentDrifts.count) 次"
            }
        } else if let warnEvt = worstWarning {
            stability.status = .warning
            stability.label = warnEvt.detail
            result.riskAlerts.append(warnEvt.detail)
            if result.overallLevel == .safe {
                result.overallLevel = .warning
                result.overallSummary = warnEvt.detail
            }
        } else if recentDrifts.count >= 2 {
            stability.status = .warning
            stability.label = "同城较频漂移（\(recentDrifts.count)次/1h）"
            result.riskAlerts.append("1 小时内同城 IP 变动 \(recentDrifts.count) 次")
            if result.overallLevel == .safe {
                result.overallLevel = .warning
                result.overallSummary = "1 小时内同城漂移 \(recentDrifts.count) 次"
            }
        } else {
            // Single intra-city, same-ASN drift within 1 hour: safe normal residential behavior
            stability.status = .safe
            let kmStr = latestEvent?.distanceKm.map { "约 \($0)km · " } ?? ""
            stability.label = "同城微漂移（\(kmStr)1次/1h · 正常）"
        }

        result.stability = stability

        // Trigger macOS notification on red-line danger with cooldown
        if alertsEnabled && result.overallLevel == .danger {
            let nowDate = Date()
            let shouldNotify = (result.overallSummary != lastAlertSummary) || (nowDate.timeIntervalSince(lastAlertTime) > 180)
            if shouldNotify {
                lastAlertSummary = result.overallSummary
                lastAlertTime = nowDate
                sendSystemAlert(title: "ClaudeIPGuard 高危预警", body: result.overallSummary)
            }
        } else if result.overallLevel == .safe {
            lastAlertSummary = ""
        }

        return result
    }

    private func sendSystemAlert(title: String, body: String) {
        let escapedTitle = title.replacingOccurrences(of: "\"", with: "\\\"")
        let escapedBody = body.replacingOccurrences(of: "\"", with: "\\\"")
        let script = "display notification \"\(escapedBody)\" with title \"\(escapedTitle)\" sound name \"Basso\""
        DispatchQueue.global(qos: .utility).async {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            proc.arguments = ["-e", script]
            try? proc.run()
        }
    }

    private func scheduleDebouncedCheck(reason: String, delaySeconds: Double = 1.2) {
        debounceTask?.cancel()
        debounceTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delaySeconds * 1_000_000_000))
            if Task.isCancelled { return }
            self?.triggerCheck(reason: reason)
        }
    }

    private func applySnapshot(_ result: DetectionSnapshot) {
        self.snapshot = result
        self.isChecking = false
        self.lastClashSignature = result.clash.signature

        stateLock.lock()
        self.threadSafeSnapshot = result
        stateLock.unlock()

        self.onSnapshotUpdated?(result, false)
    }

    private func startClashWatcher() {
        let initialState = clashClient.fetchState()
        lastClashSignature = initialState.signature

        clashPollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                let client = self.clashClient
                DispatchQueue.global(qos: .utility).async {
                    let current = client.fetchState()
                    let sig = current.signature
                    Task { @MainActor [weak self] in
                        guard let self = self else { return }
                        if !self.lastClashSignature.isEmpty && sig != self.lastClashSignature {
                            self.lastClashSignature = sig
                            let reason = current.running
                                ? "节点切换 → \(current.activeNode)"
                                : "Clash 状态变动"
                            self.scheduleDebouncedCheck(reason: reason, delaySeconds: 1.0)
                        } else if self.lastClashSignature.isEmpty {
                            self.lastClashSignature = sig
                        }
                    }
                }
            }
        }
    }

    private func startNetworkPathWatcher() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let interfaces = path.availableInterfaces.map { $0.name }.sorted().joined(separator: ",")
            let summary = "\(path.status)|\(interfaces)"
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if !self.lastPathSummary.isEmpty && summary != self.lastPathSummary {
                    self.lastPathSummary = summary
                    self.scheduleDebouncedCheck(reason: "系统网络变动", delaySeconds: 1.8)
                } else {
                    self.lastPathSummary = summary
                }
            }
        }
        pathMonitor.start(queue: pathQueue)
    }

    private func reschedulePeriodicTimer() {
        periodicTimer?.invalidate()
        periodicTimer = nil
        guard refreshInterval.rawValue > 0 else { return }
        periodicTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(refreshInterval.rawValue), repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.triggerCheck(reason: "定时刷新")
            }
        }
    }

    private func startHTTPServer() {
        let server = LocalHTTPServer(
            port: 17899,
            getSnapshot: { [weak self] in
                self?.latestThreadSafeSnapshot() ?? .initial
            },
            triggerRefresh: { [weak self] reply in
                Task { @MainActor [weak self] in
                    guard let self = self else {
                        reply(.initial)
                        return
                    }
                    self.triggerCheck(reason: "API 触发刷新") { updated in
                        reply(updated)
                    }
                }
            }
        )
        server.start()
        self.httpServer = server
    }

    func copyToClipboard(_ text: String, label: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        copiedToast = "已复制 \(label)"
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 1_600_000_000)
            if self?.copiedToast == "已复制 \(label)" {
                self?.copiedToast = nil
            }
        }
    }

    func menuBarText() -> String {
        if isChecking && snapshot.claudeExit.ip.isEmpty {
            return "检测中..."
        }
        let code = snapshot.claudeExit.countryCode.isEmpty ? "--" : snapshot.claudeExit.countryCode

        if snapshot.dns.status == .leaked {
            return "DNS泄露"
        }
        if snapshot.ipv6.status == .danger {
            return "IPv6泄露"
        }
        if snapshot.stun.status == .danger {
            return "STUN泄露"
        }
        if snapshot.routeConsistency.status == .danger {
            return "路由分叉"
        }
        if !snapshot.claudeExit.ip.isEmpty && !snapshot.claudeSupported {
            return "\(code) 不支持"
        }
        if snapshot.risk.score >= 60 {
            return "\(code) 高风险(\(snapshot.risk.score))"
        }

        switch menuBarStyle {
        case .compact:
            if snapshot.dns.status == .unknown {
                return "\(code) · DNS失败"
            }
            let tag = snapshot.overallLevel == .safe ? "安全" : (snapshot.overallLevel == .warning ? "注意" : "离线")
            return "\(code) · \(tag)"
        case .withIP:
            let ip: String
            if snapshot.claudeExit.ip.isEmpty {
                ip = "离线"
            } else if snapshot.claudeExit.ip.count > 18 {
                ip = String(snapshot.claudeExit.ip.prefix(15)) + "…"
            } else {
                ip = snapshot.claudeExit.ip
            }
            if snapshot.dns.status == .unknown {
                return "\(code) · \(ip) (DNS?)"
            }
            return "\(code) · \(ip)"
        }
    }

    func menuBarDotColor() -> NSColor {
        if isChecking && snapshot.claudeExit.ip.isEmpty {
            return .systemBlue
        }
        switch snapshot.overallLevel {
        case .safe: return .systemGreen
        case .warning: return .systemOrange
        case .danger: return .systemRed
        case .checking: return .systemBlue
        }
    }
}
