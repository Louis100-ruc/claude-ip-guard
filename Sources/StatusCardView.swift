import SwiftUI
import AppKit

struct StatusCardView: View {
    static let cardWidth: CGFloat = 424
    static let cardHeight: CGFloat = 608

    @ObservedObject var store: MonitorStore
    var isFloatingWindow: Bool = false

    private var snap: DetectionSnapshot { store.snapshot }

    var body: some View {
        VStack(spacing: 10) {
            headerBanner
            leakMatrixCard
            claudePurityCard
            routingCard
            lastRefreshBar
            Spacer(minLength: 0)
            footerBar
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(
            isFloatingWindow
                ? AnyView(VisualEffectBlur(material: .hudWindow, blendingMode: .behindWindow))
                : AnyView(Color.clear)
        )
        .overlay(alignment: .bottom) {
            if let toast = store.copiedToast {
                Text(toast)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Capsule().fill(Color.black.opacity(0.78)))
                    .padding(.bottom, 18)
                    .transition(.opacity)
            }
        }
    }

    // MARK: - Top Banner
    private var headerBanner: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle()
                    .fill(levelColor(snap.overallLevel).opacity(0.18))
                    .frame(width: 34, height: 34)
                Image(systemName: levelSymbol(snap.overallLevel))
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundColor(levelColor(snap.overallLevel))
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(snap.overallLevel.title)
                    .font(.system(size: 12.5, weight: .semibold))
                    .lineLimit(1)
                Text(snap.overallSummary)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 4)

            HStack(spacing: 6) {
                Button(action: { store.triggerCheck(reason: "手动刷新") }) {
                    if store.isChecking {
                        ProgressView()
                            .controlSize(.small)
                            .scaleEffect(0.75)
                            .frame(width: 24, height: 24)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 12, weight: .medium))
                            .frame(width: 24, height: 24)
                    }
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help("立即重新检测")

                Button(action: { store.onToggleFloating?() }) {
                    Image(systemName: store.isFloatingVisible ? "pin.fill" : "pin")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(store.isFloatingVisible ? .accentColor : .primary)
                        .frame(width: 24, height: 24)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .help(store.isFloatingVisible ? "关闭桌面悬浮窗" : "钉在桌面角落（常驻浮窗）")
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(levelColor(snap.overallLevel).opacity(0.08))
                .overlay(
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .stroke(levelColor(snap.overallLevel).opacity(0.25), lineWidth: 1)
                )
        )
    }

    // MARK: - 2x2 Leak Guard Matrix
    private var leakMatrixCard: some View {
        let columns = [
            GridItem(.flexible(), spacing: 8),
            GridItem(.flexible(), spacing: 8)
        ]

        let allClear = (snap.dns.status == .safe &&
                        snap.ipv6.status == .safe &&
                        snap.stun.status == .safe &&
                        snap.routeConsistency.status == .safe)

        return CardContainer(title: "泄露与分流红线体检", icon: "shield.lefthalf.filled") {
            BadgeView(
                text: allClear ? "4/4 全部通过" : (snap.overallLevel == .danger ? "发现泄露风险" : "需关注"),
                color: allClear ? .green : (snap.overallLevel == .danger ? .red : .orange)
            )
        } content: {
            LazyVGrid(columns: columns, spacing: 8) {
                // 1. DNS Leak
                LeakTile(
                    title: "DNS 泄露",
                    statusColor: dnsColor(snap.dns.status),
                    value: snap.dns.status.label,
                    subtext: snap.dns.ip.isEmpty
                        ? "未获取到出口"
                        : "\(ClaudeRegionChecker.flagEmoji(for: snap.dns.countryCode)) \(snap.dns.provider.isEmpty ? snap.dns.ip : snap.dns.provider)",
                    tooltip: snap.dns.ip.isEmpty ? "" : "DNS IP: \(snap.dns.ip) (\(snap.dns.geo)) · 点击复制"
                )
                .onTapGesture {
                    if !snap.dns.ip.isEmpty {
                        store.copyToClipboard(snap.dns.ip, label: "DNS IP")
                    }
                }

                // 2. IPv6 Leak
                LeakTile(
                    title: "IPv6 泄露",
                    statusColor: checkStateColor(snap.ipv6.status),
                    value: snap.ipv6.label,
                    subtext: snap.ipv6.detail.isEmpty ? "IPv6 已隔离" : snap.ipv6.detail,
                    tooltip: snap.ipv6.ip.isEmpty ? "无 IPv6 出口暴露" : "IPv6: \(snap.ipv6.ip)"
                )

                // 3. UDP STUN / WebRTC Leak
                LeakTile(
                    title: "UDP / STUN",
                    statusColor: checkStateColor(snap.stun.status),
                    value: snap.stun.label,
                    subtext: snap.stun.detail.isEmpty ? "检测中" : snap.stun.detail,
                    tooltip: "RFC 5389 UDP STUN 映射 IP 检测（防 WebRTC 泄露）"
                )

                // 4. Cross-domain Route Consistency
                LeakTile(
                    title: "全站路由一致",
                    statusColor: checkStateColor(snap.routeConsistency.status),
                    value: snap.routeConsistency.label,
                    subtext: snap.routeConsistency.detail.isEmpty ? "Web / API / CF" : snap.routeConsistency.detail,
                    tooltip: "对比 claude.ai、api.anthropic.com 与 1.1.1.1 出口 IP"
                )
            }
        }
    }

    // MARK: - Claude Exit IP & Purity Card
    private var claudePurityCard: some View {
        CardContainer(title: "Claude AI 出口与纯净度", icon: "network") {
            HStack(spacing: 5) {
                BadgeView(
                    text: "风险分 \(snap.risk.score)/100",
                    color: checkStateColor(snap.risk.scoreLevel)
                )
                BadgeView(
                    text: snap.claudeExit.ip.isEmpty ? "离线" : (snap.claudeSupported ? "支持地区" : "不支持地区"),
                    color: snap.claudeExit.ip.isEmpty ? .gray : (snap.claudeSupported ? .green : .red)
                )
            }
        } content: {
            InfoRow(label: "出口 IP") {
                if snap.claudeExit.ip.isEmpty {
                    Text("-")
                        .font(.system(size: 11.5))
                        .foregroundColor(.secondary)
                } else {
                    HStack(spacing: 6) {
                        Text(ClaudeRegionChecker.flagEmoji(for: snap.claudeExit.countryCode))
                            .font(.system(size: 12))
                        Text(snap.claudeExit.ip)
                            .font(.system(size: 12, weight: .semibold, design: .monospaced))
                            .onTapGesture {
                                store.copyToClipboard(snap.claudeExit.ip, label: "Claude 出口 IP")
                            }
                            .help("点击复制 Claude 出口 IP")
                        if snap.claudeExit.latencyMs > 0 {
                            Text("\(String(snap.claudeExit.latencyMs))ms")
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.secondary)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(Color.secondary.opacity(0.12)))
                        }
                    }
                }
            }
            Divider().opacity(0.35)
            InfoRow(label: "地区 / 时区") {
                HStack(spacing: 6) {
                    let loc = [snap.claudeExit.country, snap.claudeExit.city].filter { !$0.isEmpty }.joined(separator: " · ")
                    Text(loc.isEmpty ? (snap.claudeExit.countryCode.isEmpty ? "-" : snap.claudeExit.countryCode) : loc)
                        .font(.system(size: 11.5))
                        .lineLimit(1)
                    if !snap.timezoneCheck.label.isEmpty {
                        let diff = abs(snap.timezoneCheck.hourDiff ?? 0)
                        BadgeView(
                            text: snap.timezoneCheck.label,
                            color: diff <= 2 ? .green : (diff <= 6 ? .blue : .orange)
                        )
                        .help("本机: \(snap.timezoneCheck.localTimezone) / IP: \(snap.timezoneCheck.ipTimezone)")
                    }
                }
            }
            Divider().opacity(0.35)
            InfoRow(label: "IP 属性") {
                HStack(spacing: 5) {
                    BadgeView(
                        text: snap.claudeExit.ipType.label,
                        color: ipTypeColor(snap.claudeExit.ipType)
                    )
                    if snap.risk.riskFlags.isEmpty {
                        BadgeView(text: "无匿名标记", color: .green)
                    } else {
                        ForEach(snap.risk.riskFlags.prefix(2), id: \.self) { flag in
                            BadgeView(text: flag, color: flag == "Tor" || flag == "VPN" || flag == "Proxy" ? .red : .orange)
                        }
                    }
                }
            }
            Divider().opacity(0.35)
            InfoRow(label: "ASN / 运营商") {
                let ispText = [snap.claudeExit.asn, snap.claudeExit.isp].filter { !$0.isEmpty }.joined(separator: " · ")
                Text(ispText.isEmpty ? "-" : ispText)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(snap.risk.rdns.isEmpty ? ispText : "\(ispText)\nrDNS: \(snap.risk.rdns)")
            }
            Divider().opacity(0.35)
            InfoRow(label: "IP 稳定性") {
                HStack(spacing: 5) {
                    Circle()
                        .fill(checkStateColor(snap.stability.status))
                        .frame(width: 6, height: 6)
                    Text(snap.stability.label)
                        .font(.system(size: 11))
                        .foregroundColor(snap.stability.status == .safe ? .secondary : checkStateColor(snap.stability.status))
                        .lineLimit(1)
                }
            }
        }
    }

    // MARK: - Clash & Direct Card
    private var routingCard: some View {
        CardContainer(title: "代理节点与直连对比", icon: "arrow.triangle.branch") {
            if snap.clash.running {
                BadgeView(
                    text: "\(snap.clash.mode.uppercased())\(snap.clash.tunEnabled ? " · TUN" : "")",
                    color: .blue
                )
            } else {
                BadgeView(text: "系统代理 / 通用模式", color: .secondary)
            }
        } content: {
            InfoRow(label: "当前节点") {
                Text(snap.clash.running ? (snap.clash.activeNode.isEmpty ? "-" : snap.clash.activeNode) : "未连接 Clash API（通用检测生效）")
                    .font(.system(size: 11.5, weight: snap.clash.running ? .medium : .regular))
                    .foregroundColor(snap.clash.running ? .primary : .secondary)
                    .lineLimit(1)
                    .help(snap.clash.nodeChain)
            }
            Divider().opacity(0.35)
            InfoRow(label: "国内直连") {
                let directText = snap.directExit.ip.isEmpty
                    ? "-"
                    : "\(snap.directExit.ip) · \(snap.directExit.location)"
                Text(directText)
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
        }
    }

    // MARK: - Last Refresh Bar
    private var lastRefreshBar: some View {
        TimelineView(.periodic(from: .now, by: 1.0)) { context in
            HStack(spacing: 6) {
                Image(systemName: "clock.arrow.circlepath")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.secondary)
                Text("上次刷新")
                    .font(.system(size: 11.5))
                    .foregroundColor(.secondary)
                Spacer(minLength: 4)
                if store.isChecking {
                    Text("正在刷新...")
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundColor(.accentColor)
                } else {
                    Text("\(formattedTime(snap.updatedAt))（\(relativeTimeString(from: snap.updatedAt, now: context.date))）")
                        .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                        .foregroundColor(.primary)
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(Color(NSColor.controlBackgroundColor).opacity(0.65))
                    .overlay(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .stroke(Color.primary.opacity(0.06), lineWidth: 1)
                    )
            )
        }
    }

    // MARK: - Footer
    private var footerBar: some View {
        HStack(spacing: 8) {
            Button(action: {
                store.copyToClipboard("http://127.0.0.1:17899/api/status", label: "本地 API 地址")
            }) {
                HStack(spacing: 4) {
                    Image(systemName: "link")
                        .font(.system(size: 10))
                    Text("127.0.0.1:17899/api/status")
                        .font(.system(size: 10.5, design: .monospaced))
                }
                .foregroundColor(.accentColor)
            }
            .buttonStyle(.plain)
            .help("点击复制本地 JSON API 地址")

            Spacer()

            Menu {
                Section("自动刷新频率") {
                    ForEach(RefreshIntervalOption.allCases) { opt in
                        Button(action: { store.refreshInterval = opt }) {
                            HStack {
                                Text(opt.label)
                                if store.refreshInterval == opt {
                                    Image(systemName: "checkmark")
                                }
                            }
                        }
                    }
                }
                Section("菜单栏显示") {
                    ForEach(MenuBarDisplayStyle.allCases, id: \.rawValue) { style in
                        Button(action: { store.menuBarStyle = style }) {
                            HStack {
                                Text(style.label)
                                if store.menuBarStyle == style {
                                    Image(systemName: "checkmark")
                                }
                            }
                        }
                    }
                }
                Divider()
                Toggle("开机自动启动", isOn: $store.launchAtLogin)
                Toggle("高危风险时发送系统通知", isOn: $store.alertsEnabled)
                Toggle("桌面悬浮窗始终置顶", isOn: $store.floatingAlwaysOnTop)
                Button("在浏览器打开 ip.net.coffee") {
                    if let url = URL(string: "https://ip.net.coffee/claude/") {
                        NSWorkspace.shared.open(url)
                    }
                }
                Button("复制完整 JSON 报告") {
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                    encoder.dateEncodingStrategy = .iso8601
                    if let data = try? encoder.encode(snap),
                       let text = String(data: data, encoding: .utf8) {
                        store.copyToClipboard(text, label: "JSON 报告")
                    }
                }
                Divider()
                Button("退出 ClaudeIPGuard") {
                    NSApp.terminate(nil)
                }
            } label: {
                Image(systemName: "gearshape")
                    .font(.system(size: 12))
                    .foregroundColor(.secondary)
                    .frame(width: 24, height: 24)
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
        .padding(.top, 2)
    }

    // MARK: - Helpers
    private func formattedTime(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: date)
    }

    private func relativeTimeString(from date: Date, now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(date)))
        if seconds < 5 {
            return "刚刚"
        } else if seconds < 60 {
            return "\(seconds)秒前"
        } else if seconds < 3600 {
            return "\(seconds / 60)分钟前"
        } else {
            return "\(seconds / 3600)小时前"
        }
    }

    private func levelColor(_ level: OverallLevel) -> Color {
        switch level {
        case .safe: return .green
        case .warning: return .orange
        case .danger: return .red
        case .checking: return .blue
        }
    }

    private func checkStateColor(_ state: CheckState) -> Color {
        switch state {
        case .safe: return .green
        case .warning: return .orange
        case .danger: return .red
        case .unknown: return .gray
        }
    }

    private func levelSymbol(_ level: OverallLevel) -> String {
        switch level {
        case .safe: return "checkmark.shield.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .danger: return "xmark.shield.fill"
        case .checking: return "waveform.path.ecg"
        }
    }

    private func dnsColor(_ status: DNSLeakStatus) -> Color {
        switch status {
        case .safe: return .green
        case .warning: return .orange
        case .leaked: return .red
        case .unknown: return .orange
        }
    }

    private func ipTypeColor(_ type: IPTypeCategory) -> Color {
        switch type {
        case .residential: return .green
        case .mobile: return .mint
        case .datacenter: return .orange
        case .proxy: return .red
        case .unknown: return .gray
        }
    }
}

private struct LeakTile: View {
    let title: String
    let statusColor: Color
    let value: String
    let subtext: String
    let tooltip: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 5) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 6.5, height: 6.5)
                Text(title)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(.secondary)
                Spacer(minLength: 2)
            }
            Text(value)
                .font(.system(size: 11.5, weight: .semibold))
                .foregroundColor(statusColor == .green ? .primary : statusColor)
                .lineLimit(1)
            Text(subtext)
                .font(.system(size: 10))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.tail)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(statusColor.opacity(0.07))
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(statusColor.opacity(0.22), lineWidth: 0.8)
                )
        )
        .help(tooltip)
    }
}

private struct CardContainer<Trailing: View, Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let trailing: () -> Trailing
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                HStack(spacing: 5) {
                    Image(systemName: icon)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                    Text(title)
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                Spacer()
                trailing()
            }
            VStack(spacing: 6) {
                content()
            }
        }
        .padding(10)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color(NSColor.controlBackgroundColor).opacity(0.82))
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(Color.primary.opacity(0.07), lineWidth: 1)
                )
        )
    }
}

private struct InfoRow<Value: View>: View {
    let label: String
    @ViewBuilder let value: () -> Value

    var body: some View {
        HStack(alignment: .center, spacing: 8) {
            Text(label)
                .font(.system(size: 11.5))
                .foregroundColor(.secondary)
                .fixedSize(horizontal: true, vertical: false)
                .frame(minWidth: 74, alignment: .leading)
            Spacer(minLength: 6)
            value()
        }
    }
}

private struct BadgeView: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundColor(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 2.5)
            .background(
                Capsule()
                    .fill(color.opacity(0.14))
            )
    }
}

private struct VisualEffectBlur: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    let blendingMode: NSVisualEffectView.BlendingMode

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}
