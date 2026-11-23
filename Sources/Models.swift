import Foundation

enum OverallLevel: String, Codable {
    case safe
    case warning
    case danger
    case checking

    var emoji: String {
        switch self {
        case .safe: return "🟢"
        case .warning: return "🟡"
        case .danger: return "🔴"
        case .checking: return "⏳"
        }
    }

    var title: String {
        switch self {
        case .safe: return "环境安全 · 可用 Claude"
        case .warning: return "存在风险 · 建议关注"
        case .danger: return "高危环境 · 暂停使用"
        case .checking: return "正在实时检测网络..."
        }
    }
}

enum CheckState: String, Codable {
    case safe
    case warning
    case danger
    case unknown
}

enum DNSLeakStatus: String, Codable {
    case safe
    case warning
    case leaked
    case unknown

    var label: String {
        switch self {
        case .safe: return "无泄露"
        case .warning: return "跨区解析"
        case .leaked: return "中国DNS泄露"
        case .unknown: return "检测失败"
        }
    }
}

enum IPTypeCategory: String, Codable {
    case residential
    case mobile
    case datacenter
    case proxy
    case unknown

    var label: String {
        switch self {
        case .residential: return "家庭住宅 IP"
        case .mobile: return "移动蜂窝 IP"
        case .datacenter: return "机房 / IDC IP"
        case .proxy: return "代理 / VPN IP"
        case .unknown: return "常规 / 未知 IP"
        }
    }
}

struct DNSCheckResult: Codable, Equatable {
    var status: DNSLeakStatus = .unknown
    var ip: String = ""
    var geo: String = ""
    var country: String = ""
    var countryCode: String = ""
    var provider: String = ""
    var isChinaDNS: Bool = false
    var countryMatchesExit: Bool = true
}

struct IPv6CheckResult: Codable, Equatable {
    var status: CheckState = .unknown
    var ip: String = ""
    var label: String = "检测中"
    var detail: String = ""
}

struct STUNCheckResult: Codable, Equatable {
    var status: CheckState = .unknown
    var mappedIP: String = ""
    var label: String = "检测中"
    var detail: String = ""
}

struct RouteConsistencyResult: Codable, Equatable {
    var status: CheckState = .unknown
    var claudeWebIP: String = ""
    var anthropicApiIP: String = ""
    var cloudflareIP: String = ""
    var allMatch: Bool = true
    var label: String = "检测中"
    var detail: String = ""
}

struct RiskAssessment: Codable, Equatable {
    var score: Int = 0                 // 0-100 (max of dual engines)
    var ipqueryScore: Int? = nil
    var proxycheckScore: Int? = nil
    var isVPN: Bool = false
    var isProxy: Bool = false
    var isTor: Bool = false
    var isDatacenter: Bool = false
    var isMobile: Bool = false
    var rdns: String = ""
    var sources: [String] = []

    var riskFlags: [String] {
        var flags: [String] = []
        if isTor { flags.append("Tor") }
        if isVPN { flags.append("VPN") }
        if isProxy { flags.append("Proxy") }
        if isDatacenter { flags.append("机房") }
        if isMobile { flags.append("移动网") }
        return flags
    }

    var scoreLevel: CheckState {
        if score >= 60 || isTor { return .danger }
        if score >= 20 || isVPN || isProxy || isDatacenter { return .warning }
        return .safe
    }
}

struct TimezoneCheckResult: Codable, Equatable {
    var localTimezone: String = ""
    var ipTimezone: String = ""
    var hourDiff: Double? = nil
    var label: String = ""
}

struct IPStabilityInfo: Codable, Equatable {
    var status: CheckState = .safe
    var sessionChangeCount: Int = 0
    var unexpectedDriftCount: Int = 0
    var recentDriftCount1h: Int = 0
    var lastDriftDistanceKm: Int? = nil
    var lastDriftRoute: String = ""
    var lastChangedAt: String = ""
    var label: String = "稳定 · 无异常跳变"
}

struct IPDetail: Codable, Equatable {
    var ip: String = ""
    var country: String = ""
    var countryCode: String = ""
    var region: String = ""
    var city: String = ""
    var isp: String = ""
    var org: String = ""
    var asn: String = ""
    var timezone: String = ""
    var latitude: Double? = nil
    var longitude: Double? = nil
    var ipType: IPTypeCategory = .unknown
    var isHosting: Bool = false
    var isProxy: Bool = false
    var isMobile: Bool = false
    var colo: String = ""
    var latencyMs: Int = 0
}

struct DirectIPInfo: Codable, Equatable {
    var ip: String = ""
    var location: String = ""
}

struct ClashState: Codable, Equatable {
    var running: Bool = false
    var mode: String = ""
    var tunEnabled: Bool = false
    var activeGroup: String = ""
    var activeNode: String = ""
    var nodeChain: String = ""

    var signature: String {
        "\(running)|\(mode)|\(tunEnabled)|\(activeNode)"
    }
}

struct DetectionSnapshot: Codable, Equatable {
    var overallLevel: OverallLevel = .checking
    var overallSummary: String = "等待首次检测"
    var riskAlerts: [String] = []
    var claudeSupported: Bool = false
    var claudeExit: IPDetail = IPDetail()
    var anthropicApiExit: IPDetail = IPDetail()
    var cloudflareExit: IPDetail = IPDetail()
    var directExit: DirectIPInfo = DirectIPInfo()
    var dns: DNSCheckResult = DNSCheckResult()
    var ipv6: IPv6CheckResult = IPv6CheckResult()
    var stun: STUNCheckResult = STUNCheckResult()
    var routeConsistency: RouteConsistencyResult = RouteConsistencyResult()
    var risk: RiskAssessment = RiskAssessment()
    var timezoneCheck: TimezoneCheckResult = TimezoneCheckResult()
    var stability: IPStabilityInfo = IPStabilityInfo()
    var clash: ClashState = ClashState()
    var triggerReason: String = "启动检测"
    var updatedAt: Date = Date()
    var updatedAtISO: String = ""
    var errorMessage: String? = nil

    static let initial = DetectionSnapshot()
}

enum ClaudeRegionChecker {
    static let unsupportedCodes: Set<String> = [
        "CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU", "VE", "AF", "SD", "SS", "CF", "CD", "LY", "ML", "SO", "YE", "ZW", "MM", "ER"
    ]

    static func isSupported(countryCode: String) -> Bool {
        let code = countryCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard code.count == 2 else { return false }
        return !unsupportedCodes.contains(code)
    }

    static func flagEmoji(for countryCode: String) -> String {
        let code = countryCode.uppercased()
        guard code.count == 2 else { return "🌐" }
        var scalarString = ""
        for scalar in code.unicodeScalars {
            guard scalar.value >= 65 && scalar.value <= 90,
                  let flagScalar = UnicodeScalar(127397 + scalar.value) else {
                return "🌐"
            }
            scalarString.unicodeScalars.append(flagScalar)
        }
        return scalarString
    }

    static func countryCodeFromName(_ name: String) -> String {
        let lower = name.lowercased()
        let map: [(String, String)] = [
            ("taiwan", "TW"), ("japan", "JP"), ("united states", "US"), ("usa", "US"),
            ("singapore", "SG"), ("hong kong", "HK"), ("south korea", "KR"), ("korea", "KR"),
            ("united kingdom", "GB"), ("germany", "DE"), ("france", "FR"), ("canada", "CA"),
            ("australia", "AU"), ("netherlands", "NL"), ("switzerland", "CH"), ("india", "IN"),
            ("malaysia", "MY"), ("philippines", "PH"), ("macao", "MO"), ("macau", "MO"),
            ("russia", "RU"), ("china", "CN")
        ]
        for (keyword, code) in map {
            if lower.contains(keyword) { return code }
        }
        return ""
    }
}
