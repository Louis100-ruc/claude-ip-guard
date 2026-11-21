using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

namespace ClaudeIPGuard
{
    public static class JsonHelper
    {
        public static Dictionary<string, object> ParseObject(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            try
            {
                var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                return serializer.Deserialize<Dictionary<string, object>>(json);
            }
            catch
            {
                return null;
            }
        }

        public static string GetString(Dictionary<string, object> dict, string key, string fallback = "")
        {
            if (dict == null || !dict.ContainsKey(key) || dict[key] == null) return fallback;
            return Convert.ToString(dict[key]) ?? fallback;
        }

        public static bool GetBool(Dictionary<string, object> dict, string key, bool fallback = false)
        {
            if (dict == null || !dict.ContainsKey(key) || dict[key] == null) return fallback;
            try { return Convert.ToBoolean(dict[key]); } catch { return fallback; }
        }

        public static int? GetNullableInt(Dictionary<string, object> dict, string key)
        {
            if (dict == null || !dict.ContainsKey(key) || dict[key] == null) return null;
            try { return Convert.ToInt32(dict[key]); } catch { return null; }
        }

        public static Dictionary<string, object> GetDict(Dictionary<string, object> dict, string key)
        {
            if (dict == null || !dict.ContainsKey(key)) return null;
            return dict[key] as Dictionary<string, object>;
        }

        public static string SerializeSnapshot(DetectionSnapshot s)
        {
            var payload = new Dictionary<string, object>
            {
                ["overallLevel"] = s.OverallLevel.ToString().ToLowerInvariant(),
                ["overallSummary"] = s.OverallSummary,
                ["riskAlerts"] = s.RiskAlerts,
                ["claudeSupported"] = s.ClaudeSupported,
                ["claudeExit"] = IpDetailToDict(s.ClaudeExit),
                ["anthropicApiExit"] = IpDetailToDict(s.AnthropicApiExit),
                ["cloudflareExit"] = IpDetailToDict(s.CloudflareExit),
                ["directExit"] = new Dictionary<string, object>
                {
                    ["ip"] = s.DirectExit.Ip,
                    ["location"] = s.DirectExit.Location
                },
                ["dns"] = new Dictionary<string, object>
                {
                    ["status"] = s.Dns.Status.ToString().ToLowerInvariant(),
                    ["ip"] = s.Dns.Ip,
                    ["geo"] = s.Dns.Geo,
                    ["country"] = s.Dns.Country,
                    ["countryCode"] = s.Dns.CountryCode,
                    ["provider"] = s.Dns.Provider,
                    ["isChinaDNS"] = s.Dns.IsChinaDNS,
                    ["countryMatchesExit"] = s.Dns.CountryMatchesExit
                },
                ["ipv6"] = new Dictionary<string, object>
                {
                    ["status"] = s.Ipv6.Status.ToString().ToLowerInvariant(),
                    ["ip"] = s.Ipv6.Ip,
                    ["label"] = s.Ipv6.Label,
                    ["detail"] = s.Ipv6.Detail
                },
                ["stun"] = new Dictionary<string, object>
                {
                    ["status"] = s.Stun.Status.ToString().ToLowerInvariant(),
                    ["mappedIP"] = s.Stun.MappedIP,
                    ["label"] = s.Stun.Label,
                    ["detail"] = s.Stun.Detail
                },
                ["routeConsistency"] = new Dictionary<string, object>
                {
                    ["status"] = s.RouteConsistency.Status.ToString().ToLowerInvariant(),
                    ["claudeWebIP"] = s.RouteConsistency.ClaudeWebIP,
                    ["anthropicApiIP"] = s.RouteConsistency.AnthropicApiIP,
                    ["cloudflareIP"] = s.RouteConsistency.CloudflareIP,
                    ["allMatch"] = s.RouteConsistency.AllMatch,
                    ["label"] = s.RouteConsistency.Label,
                    ["detail"] = s.RouteConsistency.Detail
                },
                ["risk"] = new Dictionary<string, object>
                {
                    ["score"] = s.Risk.Score,
                    ["ipqueryScore"] = s.Risk.IpqueryScore,
                    ["proxycheckScore"] = s.Risk.ProxycheckScore,
                    ["isVPN"] = s.Risk.IsVPN,
                    ["isProxy"] = s.Risk.IsProxy,
                    ["isTor"] = s.Risk.IsTor,
                    ["isDatacenter"] = s.Risk.IsDatacenter,
                    ["isMobile"] = s.Risk.IsMobile,
                    ["rdns"] = s.Risk.Rdns,
                    ["sources"] = s.Risk.Sources
                },
                ["timezoneCheck"] = new Dictionary<string, object>
                {
                    ["localTimezone"] = s.TimezoneCheck.LocalTimezone,
                    ["ipTimezone"] = s.TimezoneCheck.IpTimezone,
                    ["hourDiff"] = s.TimezoneCheck.HourDiff,
                    ["label"] = s.TimezoneCheck.Label
                },
                ["stability"] = new Dictionary<string, object>
                {
                    ["status"] = s.Stability.Status.ToString().ToLowerInvariant(),
                    ["sessionChangeCount"] = s.Stability.SessionChangeCount,
                    ["unexpectedDriftCount"] = s.Stability.UnexpectedDriftCount,
                    ["lastChangedAt"] = s.Stability.LastChangedAt,
                    ["label"] = s.Stability.Label
                },
                ["clash"] = new Dictionary<string, object>
                {
                    ["running"] = s.Clash.Running,
                    ["mode"] = s.Clash.Mode,
                    ["tunEnabled"] = s.Clash.TunEnabled,
                    ["activeGroup"] = s.Clash.ActiveGroup,
                    ["activeNode"] = s.Clash.ActiveNode,
                    ["nodeChain"] = s.Clash.NodeChain
                },
                ["triggerReason"] = s.TriggerReason,
                ["updatedAtISO"] = s.UpdatedAtISO
            };
            return SerializePretty(payload);
        }

        private static Dictionary<string, object> IpDetailToDict(IPDetail d)
        {
            return new Dictionary<string, object>
            {
                ["ip"] = d.Ip,
                ["country"] = d.Country,
                ["countryCode"] = d.CountryCode,
                ["region"] = d.Region,
                ["city"] = d.City,
                ["isp"] = d.Isp,
                ["org"] = d.Org,
                ["asn"] = d.Asn,
                ["timezone"] = d.Timezone,
                ["ipType"] = d.IpType.ToString().ToLowerInvariant(),
                ["isHosting"] = d.IsHosting,
                ["isProxy"] = d.IsProxy,
                ["isMobile"] = d.IsMobile,
                ["colo"] = d.Colo,
                ["latencyMs"] = d.LatencyMs
            };
        }

        public static string SerializePretty(object obj)
        {
            var serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            var compact = serializer.Serialize(obj);
            return FormatJson(compact);
        }

        private static string FormatJson(string json)
        {
            var sb = new StringBuilder(json.Length * 2);
            bool inQuotes = false;
            bool escaped = false;
            int indent = 0;

            for (int i = 0; i < json.Length; i++)
            {
                char ch = json[i];
                if (inQuotes)
                {
                    sb.Append(ch);
                    if (escaped) escaped = false;
                    else if (ch == '\\') escaped = true;
                    else if (ch == '"') inQuotes = false;
                    continue;
                }

                switch (ch)
                {
                    case '"':
                        inQuotes = true;
                        sb.Append(ch);
                        break;
                    case '{':
                    case '[':
                        sb.Append(ch);
                        sb.Append("\r\n");
                        indent++;
                        sb.Append(new string(' ', indent * 2));
                        break;
                    case '}':
                    case ']':
                        sb.Append("\r\n");
                        indent = Math.Max(0, indent - 1);
                        sb.Append(new string(' ', indent * 2));
                        sb.Append(ch);
                        break;
                    case ',':
                        sb.Append(ch);
                        sb.Append("\r\n");
                        sb.Append(new string(' ', indent * 2));
                        break;
                    case ':':
                        sb.Append(": ");
                        break;
                    default:
                        if (!char.IsWhiteSpace(ch)) sb.Append(ch);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
