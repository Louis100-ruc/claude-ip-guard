using System;
using System.Collections.Generic;

namespace ClaudeIPGuard
{
    public enum OverallLevel
    {
        Safe,
        Warning,
        Danger,
        Checking
    }

    public enum CheckState
    {
        Safe,
        Warning,
        Danger,
        Unknown
    }

    public enum DNSLeakStatus
    {
        Safe,
        Warning,
        Leaked,
        Unknown
    }

    public enum IPTypeCategory
    {
        Residential,
        Mobile,
        Datacenter,
        Proxy,
        Unknown
    }

    public class DNSCheckResult
    {
        public DNSLeakStatus Status = DNSLeakStatus.Unknown;
        public string Ip = "";
        public string Geo = "";
        public string Country = "";
        public string CountryCode = "";
        public string Provider = "";
        public bool IsChinaDNS = false;
        public bool CountryMatchesExit = true;

        public string StatusLabel
        {
            get
            {
                switch (Status)
                {
                    case DNSLeakStatus.Safe: return "无泄露";
                    case DNSLeakStatus.Warning: return "跨区解析";
                    case DNSLeakStatus.Leaked: return "中国DNS泄露";
                    default: return "检测失败";
                }
            }
        }
    }

    public class IPv6CheckResult
    {
        public CheckState Status = CheckState.Unknown;
        public string Ip = "";
        public string Label = "检测中";
        public string Detail = "";
    }

    public class STUNCheckResult
    {
        public CheckState Status = CheckState.Unknown;
        public string MappedIP = "";
        public string Label = "检测中";
        public string Detail = "";
    }

    public class RouteConsistencyResult
    {
        public CheckState Status = CheckState.Unknown;
        public string ClaudeWebIP = "";
        public string AnthropicApiIP = "";
        public string CloudflareIP = "";
        public bool AllMatch = true;
        public string Label = "检测中";
        public string Detail = "";
    }

    public class RiskAssessment
    {
        public int Score = 0;
        public int? IpqueryScore = null;
        public int? ProxycheckScore = null;
        public bool IsVPN = false;
        public bool IsProxy = false;
        public bool IsTor = false;
        public bool IsDatacenter = false;
        public bool IsMobile = false;
        public string Rdns = "";
        public List<string> Sources = new List<string>();

        public List<string> RiskFlags
        {
            get
            {
                var list = new List<string>();
                if (IsTor) list.Add("Tor");
                if (IsVPN) list.Add("VPN");
                if (IsProxy) list.Add("Proxy");
                if (IsDatacenter) list.Add("机房");
                if (IsMobile) list.Add("移动网");
                return list;
            }
        }

        public CheckState ScoreLevel
        {
            get
            {
                if (Score >= 60 || IsTor) return CheckState.Danger;
                if (Score >= 20 || IsVPN || IsProxy || IsDatacenter) return CheckState.Warning;
                return CheckState.Safe;
            }
        }
    }

    public class TimezoneCheckResult
    {
        public string LocalTimezone = "";
        public string IpTimezone = "";
        public double? HourDiff = null;
        public string Label = "";
    }

    public class IPStabilityInfo
    {
        public CheckState Status = CheckState.Safe;
        public int SessionChangeCount = 0;
        public int UnexpectedDriftCount = 0;
        public int RecentDriftCount1h = 0;
        public int? LastDriftDistanceKm = null;
        public string LastDriftRoute = "";
        public string LastChangedAt = "";
        public string Label = "稳定 · 无异常跳变";
    }

    public class IPDetail
    {
        public string Ip = "";
        public string Country = "";
        public string CountryCode = "";
        public string Region = "";
        public string City = "";
        public string Isp = "";
        public string Org = "";
        public string Asn = "";
        public string Timezone = "";
        public double? Latitude = null;
        public double? Longitude = null;
        public IPTypeCategory IpType = IPTypeCategory.Unknown;
        public bool IsHosting = false;
        public bool IsProxy = false;
        public bool IsMobile = false;
        public string Colo = "";
        public int LatencyMs = 0;

        public string IpTypeLabel
        {
            get
            {
                switch (IpType)
                {
                    case IPTypeCategory.Residential: return "家庭住宅 IP";
                    case IPTypeCategory.Mobile: return "移动蜂窝 IP";
                    case IPTypeCategory.Datacenter: return "机房 / IDC IP";
                    case IPTypeCategory.Proxy: return "代理 / VPN IP";
                    default: return "常规 / 未知 IP";
                }
            }
        }
    }

    public class DirectIPInfo
    {
        public string Ip = "";
        public string Location = "";
    }

    public class ClashState
    {
        public bool Running = false;
        public string Mode = "";
        public bool TunEnabled = false;
        public string ActiveGroup = "";
        public string ActiveNode = "";
        public string NodeChain = "";

        public string Signature
        {
            get { return string.Format("{0}|{1}|{2}|{3}", Running, Mode, TunEnabled, ActiveNode); }
        }
    }

    public class DetectionSnapshot
    {
        public OverallLevel OverallLevel = OverallLevel.Checking;
        public string OverallSummary = "等待首次检测";
        public List<string> RiskAlerts = new List<string>();
        public bool ClaudeSupported = false;
        public IPDetail ClaudeExit = new IPDetail();
        public IPDetail AnthropicApiExit = new IPDetail();
        public IPDetail CloudflareExit = new IPDetail();
        public DirectIPInfo DirectExit = new DirectIPInfo();
        public DNSCheckResult Dns = new DNSCheckResult();
        public IPv6CheckResult Ipv6 = new IPv6CheckResult();
        public STUNCheckResult Stun = new STUNCheckResult();
        public RouteConsistencyResult RouteConsistency = new RouteConsistencyResult();
        public RiskAssessment Risk = new RiskAssessment();
        public TimezoneCheckResult TimezoneCheck = new TimezoneCheckResult();
        public IPStabilityInfo Stability = new IPStabilityInfo();
        public ClashState Clash = new ClashState();
        public string TriggerReason = "启动检测";
        public DateTime UpdatedAt = DateTime.Now;
        public string UpdatedAtISO = "";
        public string ErrorMessage = null;

        public string LevelTitle
        {
            get
            {
                switch (OverallLevel)
                {
                    case OverallLevel.Safe: return "环境安全 · 可用 Claude";
                    case OverallLevel.Warning: return "存在风险 · 建议关注";
                    case OverallLevel.Danger: return "高危环境 · 暂停使用";
                    default: return "正在实时检测网络...";
                }
            }
        }
    }

    public static class ClaudeRegionChecker
    {
        private static readonly HashSet<string> UnsupportedCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU", "VE", "AF",
            "SD", "SS", "CF", "CD", "LY", "ML", "SO", "YE", "ZW", "MM", "ER"
        };

        public static bool IsSupported(string countryCode)
        {
            if (string.IsNullOrWhiteSpace(countryCode)) return false;
            var code = countryCode.Trim().ToUpperInvariant();
            if (code.Length != 2) return false;
            return !UnsupportedCodes.Contains(code);
        }

        public static string CountryCodeFromName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";
            var lower = name.ToLowerInvariant();
            var map = new[]
            {
                new Tuple<string, string>("taiwan", "TW"),
                new Tuple<string, string>("japan", "JP"),
                new Tuple<string, string>("united states", "US"),
                new Tuple<string, string>("usa", "US"),
                new Tuple<string, string>("singapore", "SG"),
                new Tuple<string, string>("hong kong", "HK"),
                new Tuple<string, string>("south korea", "KR"),
                new Tuple<string, string>("korea", "KR"),
                new Tuple<string, string>("united kingdom", "GB"),
                new Tuple<string, string>("germany", "DE"),
                new Tuple<string, string>("france", "FR"),
                new Tuple<string, string>("canada", "CA"),
                new Tuple<string, string>("australia", "AU"),
                new Tuple<string, string>("netherlands", "NL"),
                new Tuple<string, string>("switzerland", "CH"),
                new Tuple<string, string>("india", "IN"),
                new Tuple<string, string>("malaysia", "MY"),
                new Tuple<string, string>("philippines", "PH"),
                new Tuple<string, string>("macao", "MO"),
                new Tuple<string, string>("macau", "MO"),
                new Tuple<string, string>("russia", "RU"),
                new Tuple<string, string>("china", "CN")
            };
            foreach (var item in map)
            {
                if (lower.Contains(item.Item1)) return item.Item2;
            }
            return "";
        }
    }
}
