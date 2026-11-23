import Foundation

enum FixPromptGenerator {
    static func generate(from snap: DetectionSnapshot) -> String {
        let levelTag: String
        let levelAdvice: String
        switch snap.overallLevel {
        case .danger:
            levelTag = "🔴 红色高危警报（建议立即修复后再使用 Claude）"
            levelAdvice = "当前存在高危封控/泄露红线，请优先帮我排查并彻底修复以下问题。"
        case .warning:
            levelTag = "🟡 黄色风险预警（存在潜在风控风险）"
            levelAdvice = "当前环境存在一定风险或不确定项，请帮我优化节点或网络配置以达到全绿安全状态。"
        case .safe:
            levelTag = "🟢 当前环境正常（常规体检/备份诊断）"
            levelAdvice = "当前各项指标均已通过，如需进一步优化延迟或稳定性可参考以下环境信息。"
        case .checking:
            levelTag = "⏳ 正在检测中"
            levelAdvice = "检测尚未完成，请先执行一次刷新接口获取最新状态后再排查。"
        }

        var issues: [String] = []
        var repairSteps: [String] = []

        // 1. Offline / unreachable
        if snap.claudeExit.ip.isEmpty {
            issues.append("🔴 **无法连接 Claude 出口**：探测 `claude.ai` 超时或失败。")
            repairSteps.append("""
            - **排查代理连通性**：检查 Clash Verge（或其他代理软件）是否正常运行、系统代理/TUN 是否开启；通过本地控制接口（如 `/tmp/verge/verge-mihomo.sock` 或 `127.0.0.1:9097`）检查当前节点延迟，切换到一个可用的海外节点。
            """)
        }

        // 2. Unsupported region
        if !snap.claudeExit.ip.isEmpty && !snap.claudeSupported {
            issues.append("🔴 **出口地区不支持 Claude**：当前 `claude.ai` 出口位于 `\(snap.claudeExit.countryCode)`（\(snap.claudeExit.country)），属于 Anthropic 受限地区。")
            repairSteps.append("""
            - **切换 Clash 节点至支持地区（最常见原因）**：读取 Clash Verge 策略组列表（`/tmp/verge/verge-mihomo.sock` 的 `/proxies`），筛选并切换到 **日本（JP）、台湾（TW）、美国（US）、新加坡（SG）或欧洲** 等 Claude 支持地区节点，**严禁选择香港（HK）/ 澳门（MO）/ 中国大陆（CN）/ 俄罗斯（RU）**，优先选择标注「家宽 / 住宅 / ISP / 原生」的节点。
            """)
        }

        // 3. DNS Leak / Unknown / Cross-region
        switch snap.dns.status {
        case .leaked:
            issues.append("🔴 **中国大陆 DNS 泄露**：DNS 出口为 `\(snap.dns.ip)`（\(snap.dns.geo)），暴露了本地运营商 DNS。")
            repairSteps.append("""
            - **修复 Clash Verge DNS 泄露**：
              1. 检查 `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml`，确保开启 DNS 覆写：`enable_dns_settings: true`。
              2. 检查同目录下 `dns_config.yaml`：确保 `enable: true`、`enhanced-mode: fake-ip`、`respect-rules: true`、`ipv6: false`，`nameserver` 设为 `https://1.1.1.1/dns-query` 和 `https://8.8.8.8/dns-query`，`direct-nameserver` 和 `proxy-server-nameserver` 使用国内 DoH（如 `https://dns.alidns.com/dns-query`、`https://doh.pub/dns-query`）。
              3. 重启 Clash Verge 使运行时配置重新生成。
            """)
        case .unknown:
            issues.append("🟡 **DNS 泄露检测失败**：未能获取 DNS 出口 IP，无法确认是否存在 DNS 泄露。")
            repairSteps.append("""
            - **排查 DNS 探测失败原因**：
              1. 优先排查当前代理节点是否丢包或拦截了 `edns.ip-api.com` / `1.1.1.1`，尝试在 Clash Verge 中切换一个延迟更稳定、丢包更低的节点。
              2. 检查 Clash Verge 的 `dns_config.yaml` 是否正常配置了海外加密 DNS（`https://1.1.1.1/dns-query` / `https://8.8.8.8/dns-query`）以及 `respect-rules: true`。
            """)
        case .warning:
            issues.append("🟡 **DNS 出口与节点跨区**：代理出口在 `\(snap.claudeExit.countryCode)`，而 DNS 出口在 `\(snap.dns.countryCode)`（\(snap.dns.provider)）。")
            repairSteps.append("""
            - **让 DNS 解析与代理节点同区**：检查 Clash Verge `dns_config.yaml` 中是否开启了 `respect-rules: true`（确保加密 DNS 请求通过当前代理节点出口发出，而非走其他出口或直连）。
            """)
        case .safe:
            break
        }

        // 4. IPv6 Leak
        if snap.ipv6.status == .danger || snap.ipv6.status == .warning {
            let icon = snap.ipv6.status == .danger ? "🔴" : "🟡"
            issues.append("\(icon) **IPv6 异常（\(snap.ipv6.label)）**：检测到 IPv6 出口 `\(snap.ipv6.ip)`（\(snap.ipv6.detail)）。")
            repairSteps.append("""
            - **关闭系统公网 IPv6 防泄露**：
              1. 在 macOS 上执行 `networksetup -setv6linklocal Wi-Fi`（将当前 Wi-Fi 的 IPv6 设为「仅本地链路」）。
              2. 确保 Clash Verge 的 `dns_config.yaml` 中 `ipv6: false`。
            """)
        }

        // 5. STUN / UDP WebRTC Leak
        if snap.stun.status == .danger || snap.stun.status == .warning {
            let icon = snap.stun.status == .danger ? "🔴" : "🟡"
            issues.append("\(icon) **UDP / WebRTC（STUN）异常（\(snap.stun.label)）**：STUN 映射 IP 为 `\(snap.stun.mappedIP)`，与 Claude 代理出口 `\(snap.claudeExit.ip)` 不一致。")
            repairSteps.append("""
            - **修复 UDP / WebRTC 泄露**：
              1. 检查当前 Clash 节点是否开启并支持 UDP 转发（`udp: true`），若不支持请更换支持 UDP 的节点。
              2. 确认 Clash Verge 已开启 TUN 模式，并检查 `fake-ip-filter` 或分流规则是否误将 `stun.*.*` 放行直连。
            """)
        }

        // 6. Cross-domain Route Consistency
        if snap.routeConsistency.status == .danger || snap.routeConsistency.status == .warning {
            let icon = snap.routeConsistency.status == .danger ? "🔴" : "🟡"
            issues.append("\(icon) **Anthropic 全站路由不一致（\(snap.routeConsistency.label)）**：\(snap.routeConsistency.detail)。")
            repairSteps.append("""
            - **统一 Anthropic 相关域名分流规则**：检查 Clash 分流规则，确保 `DOMAIN-SUFFIX,claude.ai`、`DOMAIN-SUFFIX,anthropic.com` 以及 `DOMAIN-SUFFIX,claude.com` 全部命中**同一个**干净的代理策略组/固定节点，避免网页端与 API 端跨节点/跨国分叉。
            """)
        }

        // 7. IP Risk Score / Datacenter / VPN / Proxy / Tor
        if snap.risk.score >= 20 || snap.risk.isVPN || snap.risk.isProxy || snap.risk.isTor || snap.risk.isDatacenter {
            let icon = (snap.risk.score >= 60 || snap.risk.isTor) ? "🔴" : "🟡"
            let flagsText = snap.risk.riskFlags.isEmpty ? "风险分偏高" : snap.risk.riskFlags.joined(separator: " / ")
            issues.append("\(icon) **出口 IP 纯净度风险**：双引擎风险分 `\(snap.risk.score)/100`，IP 属性为「\(snap.claudeExit.ipType.label)」，命中标记：`\(flagsText)`。")
            repairSteps.append("""
            - **更换更纯净的住宅 / 家宽节点（最有效方案）**：
              1. 当前问题核心在于代理节点出口 IP 纯净度不够高（被识别为机房/VPN/高风险段）。
              2. 请查看 Clash Verge 当前策略组下的全部可用节点，**优先挑选名称包含「家宽 / 住宅 / ISP / 原生 / 静态」且位于日本/台湾/美国/新加坡的节点**逐一切换测试。
              3. 每切换一个节点后，等待 1~2 秒并调用 `curl -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/refresh` 检查 `risk.score`（目标 `< 20`）和 `claudeExit.ipType`（目标 `residential`），帮我挑出一个最干净的节点固定下来。
            """)
        }

        // 8. IP Drift / Stability
        if snap.stability.status == .danger || snap.stability.status == .warning {
            let icon = snap.stability.status == .danger ? "🔴" : "🟡"
            let distNote = snap.stability.lastDriftDistanceKm.map { "，漂移距离约 \($0)km" } ?? ""
            issues.append("\(icon) **出口 IP 异常漂移 / 跨城跳变**：\(snap.stability.label)\(distNote)。")
            repairSteps.append("""
            - **锁定单一城市的固定住宅节点**：当前节点发生了远距离跨城漂移（超过同城 80km 范围）或短时高频轮换；请检查 Clash Verge 是否选用了负载均衡/自动测速组或跨城动态池节点，帮我切换为**锁定单一城市（如 Tokyo）的固定住宅/家宽节点**，并避免使用 Claude 期间发生远距离城市跳变。
            """)
        }

        let issuesBlock = issues.isEmpty
            ? "- 暂无异常告警项。"
            : issues.joined(separator: "\n")

        let stepsBlock = repairSteps.isEmpty
            ? "- 如需优化节点速度或地区，可查看 Clash Verge 节点列表并切换后复测。"
            : repairSteps.joined(separator: "\n")

        let clashInfo = snap.clash.running
            ? "运行中（模式：\(snap.clash.mode.uppercased())，TUN：\(snap.clash.tunEnabled ? "开启" : "关闭")，节点链：\(snap.clash.nodeChain)）"
            : "未检测到 Clash 本地控制接口（可能使用了其他代理软件，或未开启控制端口）"

        let exitLocation = [snap.claudeExit.country, snap.claudeExit.city].filter { !$0.isEmpty }.joined(separator: " · ")

        return """
        请帮我排查并修复本机（macOS）使用 Claude AI 时的网络环境风险。

        ## 1. 警报等级
        \(levelTag)
        \(levelAdvice)

        ## 2. 检测到的问题
        \(issuesBlock)

        ## 3. 当前实时检测快照（来自 ClaudeIPGuard）
        - **综合摘要**：\(snap.overallSummary)
        - **Claude 出口 IP**：`\(snap.claudeExit.ip.isEmpty ? "无" : snap.claudeExit.ip)`（地区：\(exitLocation.isEmpty ? snap.claudeExit.countryCode : exitLocation)，支持状态：\(snap.claudeSupported ? "支持" : "不支持")，延迟：\(snap.claudeExit.latencyMs)ms）
        - **IP 纯净度**：\(snap.claudeExit.ipType.label)｜双引擎风险分：`\(snap.risk.score)/100`｜标记：\(snap.risk.riskFlags.isEmpty ? "无" : snap.risk.riskFlags.joined(separator: ", "))｜ASN/运营商：\(snap.claudeExit.asn) \(snap.claudeExit.isp)
        - **DNS 泄露检测**：\(snap.dns.status.label)（出口：`\(snap.dns.ip.isEmpty ? "未获取" : snap.dns.ip)`，\(snap.dns.geo.isEmpty ? "无" : snap.dns.geo)）
        - **IPv6 检测**：\(snap.ipv6.label)\(snap.ipv6.ip.isEmpty ? "" : "（\(snap.ipv6.ip)）")
        - **UDP / STUN 检测**：\(snap.stun.label)\(snap.stun.mappedIP.isEmpty ? "" : "（\(snap.stun.mappedIP)）")
        - **全站路由一致性**：\(snap.routeConsistency.label)（\(snap.routeConsistency.detail)）
        - **IP 稳定性**：\(snap.stability.label)
        - **代理软件状态**：\(clashInfo)

        ## 4. 建议排查与修复方向
        \(stepsBlock)

        ## 5. 执行要求与验收标准
        1. 修改任何本机配置文件前请先备份原文件；如果涉及切换 Clash Verge 节点，请优先选择纯净度高、延迟稳定的家宽/住宅节点。
        2. 修复完成后，请直接运行以下命令触发实时复测并核对结果：
           ```bash
           curl -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/refresh
           ```
        3. 验收目标：`overallLevel` 变为 `"safe"`、`claudeSupported` 为 `true`、`dns.status` 为 `"safe"`、`ipv6.status` 为 `"safe"`、`stun.status` 为 `"safe"`、`routeConsistency.status` 为 `"safe"` 且 `risk.score < 20`。
        """
    }
}
