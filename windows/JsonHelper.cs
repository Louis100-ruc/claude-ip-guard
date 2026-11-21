using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ClaudeIPGuard
{
    public static class JsonHelper
    {
        public static Dictionary<string, object> ParseObject(string json)
        {
            if (string.IsNullOrWhiteSpace(json)) return null;
            try
            {
                int pos = 0;
                var val = ParseValue(json, ref pos);
                return val as Dictionary<string, object>;
            }
            catch
            {
                return null;
            }
        }

        public static string GetString(Dictionary<string, object> dict, string key, string fallback = "")
        {
            if (dict == null || !dict.ContainsKey(key) || dict[key] == null) return fallback;
            return Convert.ToString(dict[key], CultureInfo.InvariantCulture) ?? fallback;
        }

        public static bool GetBool(Dictionary<string, object> dict, string key, bool fallback = false)
        {
            if (dict == null || !dict.ContainsKey(key) || dict[key] == null) return fallback;
            try { return Convert.ToBoolean(dict[key], CultureInfo.InvariantCulture); } catch { return fallback; }
        }

        public static int? GetNullableInt(Dictionary<string, object> dict, string key)
        {
            if (dict == null || !dict.ContainsKey(key) || dict[key] == null) return null;
            try { return Convert.ToInt32(dict[key], CultureInfo.InvariantCulture); } catch { return null; }
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

        // MARK: - Self-contained JSON Serializer
        public static string SerializePretty(object obj)
        {
            var sb = new StringBuilder();
            WriteValue(sb, obj, 0);
            sb.Append("\r\n");
            return sb.ToString();
        }

        private static void WriteValue(StringBuilder sb, object value, int indent)
        {
            if (value == null)
            {
                sb.Append("null");
                return;
            }
            if (value is string s)
            {
                WriteString(sb, s);
                return;
            }
            if (value is bool b)
            {
                sb.Append(b ? "true" : "false");
                return;
            }
            if (value is int || value is long || value is short || value is byte)
            {
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }
            if (value is double d)
            {
                if (double.IsNaN(d) || double.IsInfinity(d)) sb.Append("null");
                else sb.Append(d.ToString("G", CultureInfo.InvariantCulture));
                return;
            }
            if (value is float f)
            {
                if (float.IsNaN(f) || float.IsInfinity(f)) sb.Append("null");
                else sb.Append(f.ToString("G", CultureInfo.InvariantCulture));
                return;
            }
            if (value is IDictionary dict)
            {
                sb.Append("{");
                bool first = true;
                foreach (DictionaryEntry entry in dict)
                {
                    if (!first) sb.Append(",");
                    sb.Append("\r\n");
                    sb.Append(' ', (indent + 1) * 2);
                    WriteString(sb, Convert.ToString(entry.Key, CultureInfo.InvariantCulture) ?? "");
                    sb.Append(": ");
                    WriteValue(sb, entry.Value, indent + 1);
                    first = false;
                }
                if (!first)
                {
                    sb.Append("\r\n");
                    sb.Append(' ', indent * 2);
                }
                sb.Append("}");
                return;
            }
            if (value is IEnumerable list)
            {
                sb.Append("[");
                bool first = true;
                foreach (var item in list)
                {
                    if (!first) sb.Append(",");
                    sb.Append("\r\n");
                    sb.Append(' ', (indent + 1) * 2);
                    WriteValue(sb, item, indent + 1);
                    first = false;
                }
                if (!first)
                {
                    sb.Append("\r\n");
                    sb.Append(' ', indent * 2);
                }
                sb.Append("]");
                return;
            }
            WriteString(sb, Convert.ToString(value, CultureInfo.InvariantCulture) ?? "");
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char ch in s)
            {
                switch (ch)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (ch < 32) sb.AppendFormat("\\u{0:x4}", (int)ch);
                        else sb.Append(ch);
                        break;
                }
            }
            sb.Append('"');
        }

        // MARK: - Self-contained JSON Parser
        private static void SkipWS(string s, ref int pos)
        {
            while (pos < s.Length && char.IsWhiteSpace(s[pos])) pos++;
        }

        private static object ParseValue(string s, ref int pos)
        {
            SkipWS(s, ref pos);
            if (pos >= s.Length) return null;
            char ch = s[pos];
            if (ch == '{') return ParseDict(s, ref pos);
            if (ch == '[') return ParseArray(s, ref pos);
            if (ch == '"') return ParseString(s, ref pos);
            if (ch == 't' && pos + 4 <= s.Length && s.Substring(pos, 4) == "true") { pos += 4; return true; }
            if (ch == 'f' && pos + 5 <= s.Length && s.Substring(pos, 5) == "false") { pos += 5; return false; }
            if (ch == 'n' && pos + 4 <= s.Length && s.Substring(pos, 4) == "null") { pos += 4; return null; }
            return ParseNumber(s, ref pos);
        }

        private static Dictionary<string, object> ParseDict(string s, ref int pos)
        {
            var dict = new Dictionary<string, object>(StringComparer.Ordinal);
            pos++; // '{'
            SkipWS(s, ref pos);
            if (pos < s.Length && s[pos] == '}') { pos++; return dict; }

            while (pos < s.Length)
            {
                SkipWS(s, ref pos);
                if (pos >= s.Length || s[pos] != '"') break;
                var key = ParseString(s, ref pos);
                SkipWS(s, ref pos);
                if (pos < s.Length && s[pos] == ':') pos++;
                var val = ParseValue(s, ref pos);
                dict[key] = val;
                SkipWS(s, ref pos);
                if (pos < s.Length && s[pos] == ',') { pos++; continue; }
                if (pos < s.Length && s[pos] == '}') { pos++; break; }
                break;
            }
            return dict;
        }

        private static List<object> ParseArray(string s, ref int pos)
        {
            var list = new List<object>();
            pos++; // '['
            SkipWS(s, ref pos);
            if (pos < s.Length && s[pos] == ']') { pos++; return list; }

            while (pos < s.Length)
            {
                var val = ParseValue(s, ref pos);
                list.Add(val);
                SkipWS(s, ref pos);
                if (pos < s.Length && s[pos] == ',') { pos++; continue; }
                if (pos < s.Length && s[pos] == ']') { pos++; break; }
                break;
            }
            return list;
        }

        private static string ParseString(string s, ref int pos)
        {
            var sb = new StringBuilder();
            pos++; // opening '"'
            while (pos < s.Length)
            {
                char ch = s[pos++];
                if (ch == '"') break;
                if (ch == '\\' && pos < s.Length)
                {
                    char esc = s[pos++];
                    switch (esc)
                    {
                        case '"': sb.Append('"'); break;
                        case '\\': sb.Append('\\'); break;
                        case '/': sb.Append('/'); break;
                        case 'b': sb.Append('\b'); break;
                        case 'f': sb.Append('\f'); break;
                        case 'n': sb.Append('\n'); break;
                        case 'r': sb.Append('\r'); break;
                        case 't': sb.Append('\t'); break;
                        case 'u':
                            if (pos + 4 <= s.Length)
                            {
                                var hex = s.Substring(pos, 4);
                                int code;
                                if (int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out code))
                                    sb.Append((char)code);
                                pos += 4;
                            }
                            break;
                        default:
                            sb.Append(esc);
                            break;
                    }
                }
                else
                {
                    sb.Append(ch);
                }
            }
            return sb.ToString();
        }

        private static object ParseNumber(string s, ref int pos)
        {
            int start = pos;
            if (pos < s.Length && s[pos] == '-') pos++;
            while (pos < s.Length && (char.IsDigit(s[pos]) || s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E' || s[pos] == '+' || s[pos] == '-'))
            {
                if ((s[pos] == '+' || s[pos] == '-') && pos > start && s[pos - 1] != 'e' && s[pos - 1] != 'E') break;
                pos++;
            }
            var token = s.Substring(start, pos - start);
            long lVal;
            if (!token.Contains(".") && !token.Contains("e") && !token.Contains("E")
                && long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out lVal))
            {
                if (lVal >= int.MinValue && lVal <= int.MaxValue) return (int)lVal;
                return lVal;
            }
            double dVal;
            if (double.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out dVal))
                return dVal;
            return 0;
        }
    }
}
