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

    // IP Stability & Alert tracking
    private var trackedExitIP: String = ""
    private var trackedExitCountry: String = ""
    private var trackedNodeSig: String = ""
    private var sessionIPChangeCount: Int = 0
    private var unexpectedDriftCount: Int = 0
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

    private func applyStabilityAndAlerts(to raw: DetectionSnapshot) -> DetectionSnapshot {
        var result = raw
        let newIP = result.claudeExit.ip
        let newCountry = result.claudeExit.countryCode
        let newNodeSig = result.clash.signature

        var unexpectedCrossCountry = false
        var unexpectedIPDrift = false

        if !newIP.isEmpty {
            if !trackedExitIP.isEmpty && newIP != trackedExitIP {
                sessionIPChangeCount += 1
                let f = DateFormatter()
                f.dateFormat = "HH:mm:ss"
                lastIPChangedAt = f.string(from: result.updatedAt)

                let nodeChanged = (newNodeSig != trackedNodeSig)
                if !nodeChanged {
                    unexpectedDriftCount += 1
                    unexpectedIPDrift = true
                    if !trackedExitCountry.isEmpty && !newCountry.isEmpty && newCountry != trackedExitCountry {
                        unexpectedCrossCountry = true
                    }
                }
            }
            trackedExitIP = newIP
            trackedExitCountry = newCountry
            trackedNodeSig = newNodeSig
        }

        var stability = IPStabilityInfo()
        stability.sessionChangeCount = sessionIPChangeCount
        stability.unexpectedDriftCount = unexpectedDriftCount
        stability.lastChangedAt = lastIPChangedAt

        if unexpectedCrossCountry {
            stability.status = .danger
            stability.label = "未切节点发生跨国漂移（\(unexpectedDriftCount)次）"
            result.riskAlerts.append("未切节点但出口 IP 跨国漂移至 \(newCountry)")
            if result.overallLevel != .danger {
                result.overallLevel = .danger
                result.overallSummary = "出口 IP 异常跨国漂移（\(newCountry)）"
            }
        } else if unexpectedDriftCount > 0 {
            stability.status = .warning
            stability.label = "自动漂移 \(unexpectedDriftCount) 次\(lastIPChangedAt.isEmpty ? "" : " · \(lastIPChangedAt)")"
            if unexpectedIPDrift {
                result.riskAlerts.append("当前节点出口 IP 自动更换（动态/负载均衡）")
            }
            if result.overallLevel == .safe {
                result.overallLevel = .warning
                result.overallSummary = "地区正常，但节点 IP 存在自动漂移"
            }
        } else if sessionIPChangeCount > 0 {
            stability.status = .safe
            stability.label = "稳定 · 手动切换 \(sessionIPChangeCount) 次"
        } else {
            stability.status = .safe
            stability.label = "稳定 · 无异常跳变"
        }

        result.stability = stability

        // Trigger macOS notification on red-line danger with cooldown
        if alertsEnabled && result.overallLevel == .danger {
            let now = Date()
            let shouldNotify = (result.overallSummary != lastAlertSummary) || (now.timeIntervalSince(lastAlertTime) > 180)
            if shouldNotify {
                lastAlertSummary = result.overallSummary
                lastAlertTime = now
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
