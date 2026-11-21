using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ClaudeIPGuard
{
    public class IPChecker
    {
        private readonly ClashClient _clashClient = new ClashClient();

        private static HttpClient CreateFreshClient(int timeoutSeconds)
        {
            var handler = new HttpClientHandler
            {
                UseProxy = true,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
            };
            var client = new HttpClient(handler, true)
            {
                Timeout = TimeSpan.FromSeconds(timeoutSeconds)
            };
            client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "ClaudeIPGuard/2.3 (Windows)");
            client.DefaultRequestHeaders.ConnectionClose = true;
            return client;
        }

        public async Task<DetectionSnapshot> RunFullCheckAsync(string reason)
        {
            using (var client = CreateFreshClient(8))
            using (var fastClient = CreateFreshClient(3))
            {
                var clashState = await Task.Run(() => _clashClient.FetchState());

                var claudeTask = FetchCloudflareTraceAsync(client, "https://claude.ai/cdn-cgi/trace");
                var apiTask = FetchCloudflareTraceAsync(client, "https://api.anthropic.com/cdn-cgi/trace");
                var cfTask = FetchCloudflareTraceAsync(client, "https://1.1.1.1/cdn-cgi/trace");
                var dnsTask = FetchDNSLeakAsync(client);
                var directTask = FetchDirectIPAsync(client);
                var ipv6Task = FetchIPv6RawAsync(fastClient);
                var stunTask = Task.Run(() => QuerySTUN());

                await Task.WhenAll(claudeTask, apiTask, cfTask, dnsTask, directTask, ipv6Task, stunTask);

                var claudeExit = claudeTask.Result;
                var anthropicApi = apiTask.Result;
                var cfExit = cfTask.Result;
                var dns = dnsTask.Result;
                var direct = directTask.Result;
                var rawIPv6 = ipv6Task.Result;
                var rawStunIP = stunTask.Result;

                var targetIP = !string.IsNullOrEmpty(claudeExit.Ip) ? claudeExit.Ip : cfExit.Ip;
                var risk = new RiskAssessment();
                string ipLocalTimeStr = "";

                if (!string.IsNullOrEmpty(targetIP))
                {
                    var iqTask = FetchJsonDictAsync(client, "https://api.ipquery.io/" + targetIP);
                    var pcTask = FetchProxyCheckAsync(client, targetIP);
                    var iaTask = FetchIPApiAsync(client, targetIP);

                    await Task.WhenAll(iqTask, pcTask, iaTask);

                    var combined = CombineIPIntelligence(targetIP, iqTask.Result, pcTask.Result, iaTask.Result, out ipLocalTimeStr);
                    risk = combined.Item2;

                    if (!string.IsNullOrEmpty(claudeExit.Ip))
                        claudeExit = MergeDetail(claudeExit, combined.Item1);
                    else
                        cfExit = MergeDetail(cfExit, combined.Item1);
                }

                if (!string.IsNullOrEmpty(cfExit.Ip) && cfExit.Ip == claudeExit.Ip)
                {
                    var colo = cfExit.Colo;
                    var ms = cfExit.LatencyMs;
                    cfExit = CloneDetail(claudeExit);
                    cfExit.Colo = colo;
                    cfExit.LatencyMs = ms;
                }

                dns.CountryCode = ClaudeRegionChecker.CountryCodeFromName(dns.Country);
                dns.CountryMatchesExit = string.IsNullOrEmpty(dns.CountryCode)
                                         || string.IsNullOrEmpty(claudeExit.CountryCode)
                                         || string.Equals(dns.CountryCode, claudeExit.CountryCode, StringComparison.OrdinalIgnoreCase);
                dns.Status = EvaluateDNSStatus(dns, claudeExit.CountryCode);

                var ipv6 = await EvaluateIPv6Async(fastClient, rawIPv6, claudeExit.CountryCode);
                var stun = EvaluateSTUN(rawStunIP, claudeExit.Ip, direct.Ip);
                var routeConsistency = EvaluateRouteConsistency(claudeExit, anthropicApi, cfExit);
                var tzCheck = EvaluateTimezone(claudeExit.Timezone, ipLocalTimeStr);

                var effectiveCode = !string.IsNullOrEmpty(claudeExit.CountryCode) ? claudeExit.CountryCode : cfExit.CountryCode;
                var claudeSupported = ClaudeRegionChecker.IsSupported(effectiveCode);

                var eval = EvaluateOverall(claudeExit, claudeSupported, dns, ipv6, stun, routeConsistency, risk);
                var now = DateTime.Now;

                return new DetectionSnapshot
                {
                    OverallLevel = eval.Item1,
                    OverallSummary = eval.Item2,
                    RiskAlerts = eval.Item3,
                    ClaudeSupported = claudeSupported,
                    ClaudeExit = claudeExit,
                    AnthropicApiExit = anthropicApi,
                    CloudflareExit = cfExit,
                    DirectExit = direct,
                    Dns = dns,
                    Ipv6 = ipv6,
                    Stun = stun,
                    RouteConsistency = routeConsistency,
                    Risk = risk,
                    TimezoneCheck = tzCheck,
                    Stability = new IPStabilityInfo(),
                    Clash = clashState,
                    TriggerReason = reason,
                    UpdatedAt = now,
                    UpdatedAtISO = now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ErrorMessage = string.IsNullOrEmpty(claudeExit.Ip) ? "无法连接 claude.ai 检测出口" : null
                };
            }
        }

        private async Task<IPDetail> FetchCloudflareTraceAsync(HttpClient client, string url)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var text = await client.GetStringAsync(url);
                sw.Stop();
                var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in text.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var idx = line.IndexOf('=');
                    if (idx > 0)
                    {
                        kv[line.Substring(0, idx).Trim()] = line.Substring(idx + 1).Trim();
                    }
                }
                return new IPDetail
                {
                    Ip = kv.ContainsKey("ip") ? kv["ip"] : "",
                    CountryCode = kv.ContainsKey("loc") ? kv["loc"].ToUpperInvariant() : "",
                    Colo = kv.ContainsKey("colo") ? kv["colo"] : "",
                    LatencyMs = (int)sw.ElapsedMilliseconds
                };
            }
            catch
            {
                return new IPDetail();
            }
        }

        private async Task<DNSCheckResult> FetchDNSLeakAsync(HttpClient client)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                var res = await FetchDNSLeakOnceAsync(client);
                if (!string.IsNullOrEmpty(res.Ip)) return res;
                if (attempt == 0) await Task.Delay(450);
            }
            return new DNSCheckResult();
        }

        private async Task<DNSCheckResult> FetchDNSLeakOnceAsync(HttpClient client)
        {
            try
            {
                var bytes = new byte[16];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
                var hex = BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
                var json = await client.GetStringAsync("https://" + hex + ".edns.ip-api.com/json");
                var root = JsonHelper.ParseObject(json);
                var dnsObj = JsonHelper.GetDict(root, "dns");
                if (dnsObj == null) return new DNSCheckResult();

                var ip = JsonHelper.GetString(dnsObj, "ip");
                var geo = JsonHelper.GetString(dnsObj, "geo");
                var country = "";
                var provider = geo;
                var dashIdx = geo.IndexOf(" - ", StringComparison.Ordinal);
                if (dashIdx > 0)
                {
                    country = geo.Substring(0, dashIdx).Trim();
                    provider = geo.Substring(dashIdx + 3).Trim();
                }

                var lowerGeo = geo.ToLowerInvariant();
                var lowerCountry = country.ToLowerInvariant();
                var chinaKeywords = new[]
                {
                    "china unicom", "china telecom", "china mobile", "chinanet", "cmnet",
                    "china169", "alibaba", "aliyun", "tencent", "dnspod", "cnnic", "cernet", "baidu"
                };
                bool isMainland = lowerCountry == "china" || lowerCountry == "cn";
                bool hasChinaISP = chinaKeywords.Any(k => lowerGeo.Contains(k));

                return new DNSCheckResult
                {
                    Status = DNSLeakStatus.Unknown,
                    Ip = ip,
                    Geo = geo,
                    Country = country,
                    Provider = provider,
                    IsChinaDNS = isMainland || hasChinaISP
                };
            }
            catch
            {
                return new DNSCheckResult();
            }
        }

        private async Task<DirectIPInfo> FetchDirectIPAsync(HttpClient client)
        {
            try
            {
                var json = await client.GetStringAsync("https://myip.ipip.net/json");
                var root = JsonHelper.ParseObject(json);
                var data = JsonHelper.GetDict(root, "data");
                if (data == null) return new DirectIPInfo();

                var ip = JsonHelper.GetString(data, "ip");
                var locParts = new List<string>();
                if (data.ContainsKey("location") && data["location"] is IEnumerable arr)
                {
                    foreach (var item in arr)
                    {
                        var s = Convert.ToString(item);
                        if (!string.IsNullOrWhiteSpace(s)) locParts.Add(s.Trim());
                    }
                }
                return new DirectIPInfo { Ip = ip, Location = string.Join(" ", locParts) };
            }
            catch
            {
                return new DirectIPInfo();
            }
        }

        private async Task<string> FetchIPv6RawAsync(HttpClient client)
        {
            try
            {
                var json = await client.GetStringAsync("https://api6.ipify.org?format=json");
                var root = JsonHelper.ParseObject(json);
                var ip = JsonHelper.GetString(root, "ip");
                return ip.Contains(":") ? ip : null;
            }
            catch
            {
                return null;
            }
        }

        private static string QuerySTUN()
        {
            return QuerySTUNHost("stun.cloudflare.com", 3478)
                   ?? QuerySTUNHost("stun.l.google.com", 19302);
        }

        private static string QuerySTUNHost(string host, int port)
        {
            try
            {
                var addrs = Dns.GetHostAddresses(host);
                var v4 = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (v4 == null) return null;

                using (var udp = new UdpClient(AddressFamily.InterNetwork))
                {
                    udp.Client.ReceiveTimeout = 2500;
                    udp.Client.SendTimeout = 2500;

                    var packet = new byte[20];
                    packet[0] = 0x00; packet[1] = 0x01; // Binding Request
                    packet[4] = 0x21; packet[5] = 0x12; packet[6] = 0xA4; packet[7] = 0x42; // Magic Cookie
                    var tid = new byte[12];
                    using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(tid);
                    Buffer.BlockCopy(tid, 0, packet, 8, 12);

                    var remote = new IPEndPoint(v4, port);
                    udp.Send(packet, packet.Length, remote);

                    var recvEp = new IPEndPoint(IPAddress.Any, 0);
                    var data = udp.Receive(ref recvEp);
                    if (data == null || data.Length < 28) return null;

                    int idx = 20;
                    while (idx + 4 <= data.Length)
                    {
                        int attrType = (data[idx] << 8) | data[idx + 1];
                        int attrLen = (data[idx + 2] << 8) | data[idx + 3];
                        int valStart = idx + 4;
                        if (valStart + attrLen > data.Length) break;

                        if (attrType == 0x0020 && attrLen >= 8 && data[valStart + 1] == 0x01)
                        {
                            byte b0 = (byte)(data[valStart + 4] ^ 0x21);
                            byte b1 = (byte)(data[valStart + 5] ^ 0x12);
                            byte b2 = (byte)(data[valStart + 6] ^ 0xA4);
                            byte b3 = (byte)(data[valStart + 7] ^ 0x42);
                            return string.Format("{0}.{1}.{2}.{3}", b0, b1, b2, b3);
                        }
                        if (attrType == 0x0001 && attrLen >= 8 && data[valStart + 1] == 0x01)
                        {
                            return string.Format("{0}.{1}.{2}.{3}",
                                data[valStart + 4], data[valStart + 5], data[valStart + 6], data[valStart + 7]);
                        }
                        idx = valStart + ((attrLen + 3) & ~3);
                    }
                }
            }
            catch { }
            return null;
        }

        private async Task<Dictionary<string, object>> FetchJsonDictAsync(HttpClient client, string url)
        {
            try
            {
                var json = await client.GetStringAsync(url);
                return JsonHelper.ParseObject(json);
            }
            catch
            {
                return null;
            }
        }

        private async Task<Dictionary<string, object>> FetchProxyCheckAsync(HttpClient client, string ip)
        {
            var root = await FetchJsonDictAsync(client, "https://proxycheck.io/v2/" + ip + "?vpn=1&asn=1&risk=1");
            if (root == null || JsonHelper.GetString(root, "status") != "ok") return null;
            return JsonHelper.GetDict(root, ip);
        }

        private async Task<Dictionary<string, object>> FetchIPApiAsync(HttpClient client, string ip)
        {
            var url = "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,regionName,city,isp,org,as,asname,timezone,mobile,proxy,hosting,query";
            var root = await FetchJsonDictAsync(client, url);
            if (root == null || JsonHelper.GetString(root, "status") != "success") return null;
            return root;
        }

        private Tuple<IPDetail, RiskAssessment> CombineIPIntelligence(
            string ip,
            Dictionary<string, object> iq,
            Dictionary<string, object> pc,
            Dictionary<string, object> ia,
            out string ipLocalTimeStr)
        {
            var detail = new IPDetail { Ip = ip };
            var risk = new RiskAssessment();
            ipLocalTimeStr = "";

            if (ia != null)
            {
                detail.Country = JsonHelper.GetString(ia, "country");
                detail.CountryCode = JsonHelper.GetString(ia, "countryCode").ToUpperInvariant();
                detail.Region = JsonHelper.GetString(ia, "regionName");
                detail.City = JsonHelper.GetString(ia, "city");
                detail.Isp = JsonHelper.GetString(ia, "isp");
                detail.Org = JsonHelper.GetString(ia, "org");
                detail.Timezone = JsonHelper.GetString(ia, "timezone");
                var asField = JsonHelper.GetString(ia, "as");
                if (!string.IsNullOrEmpty(asField))
                    detail.Asn = asField.Split(' ')[0];

                detail.IsMobile = JsonHelper.GetBool(ia, "mobile");
                detail.IsProxy = JsonHelper.GetBool(ia, "proxy");
                detail.IsHosting = JsonHelper.GetBool(ia, "hosting");
                risk.IsMobile |= detail.IsMobile;
                risk.IsProxy |= detail.IsProxy;
                risk.IsDatacenter |= detail.IsHosting;
                risk.Sources.Add("ip-api");
            }

            if (iq != null)
            {
                var ispObj = JsonHelper.GetDict(iq, "isp");
                if (ispObj != null)
                {
                    if (string.IsNullOrEmpty(detail.Asn)) detail.Asn = JsonHelper.GetString(ispObj, "asn");
                    if (string.IsNullOrEmpty(detail.Isp)) detail.Isp = JsonHelper.GetString(ispObj, "isp");
                    if (string.IsNullOrEmpty(detail.Org)) detail.Org = JsonHelper.GetString(ispObj, "org");
                }
                var locObj = JsonHelper.GetDict(iq, "location");
                if (locObj != null)
                {
                    if (string.IsNullOrEmpty(detail.Country)) detail.Country = JsonHelper.GetString(locObj, "country");
                    if (string.IsNullOrEmpty(detail.CountryCode)) detail.CountryCode = JsonHelper.GetString(locObj, "country_code").ToUpperInvariant();
                    if (string.IsNullOrEmpty(detail.City)) detail.City = JsonHelper.GetString(locObj, "city");
                    if (string.IsNullOrEmpty(detail.Timezone)) detail.Timezone = JsonHelper.GetString(locObj, "timezone");
                    ipLocalTimeStr = JsonHelper.GetString(locObj, "localtime");
                }
                var rObj = JsonHelper.GetDict(iq, "risk");
                if (rObj != null)
                {
                    risk.IpqueryScore = JsonHelper.GetNullableInt(rObj, "risk_score") ?? 0;
                    risk.IsVPN |= JsonHelper.GetBool(rObj, "is_vpn");
                    risk.IsProxy |= JsonHelper.GetBool(rObj, "is_proxy");
                    risk.IsTor |= JsonHelper.GetBool(rObj, "is_tor");
                    risk.IsDatacenter |= JsonHelper.GetBool(rObj, "is_datacenter");
                    risk.IsMobile |= JsonHelper.GetBool(rObj, "is_mobile");
                }
                risk.Sources.Add("ipquery");
            }

            if (pc != null)
            {
                if (string.IsNullOrEmpty(detail.Asn)) detail.Asn = JsonHelper.GetString(pc, "asn");
                if (string.IsNullOrEmpty(detail.Isp)) detail.Isp = JsonHelper.GetString(pc, "provider");
                if (string.IsNullOrEmpty(detail.Country)) detail.Country = JsonHelper.GetString(pc, "country");
                if (string.IsNullOrEmpty(detail.CountryCode)) detail.CountryCode = JsonHelper.GetString(pc, "isocode").ToUpperInvariant();
                if (string.IsNullOrEmpty(detail.City)) detail.City = JsonHelper.GetString(pc, "city");
                if (string.IsNullOrEmpty(detail.Timezone)) detail.Timezone = JsonHelper.GetString(pc, "timezone");
                var host = JsonHelper.GetString(pc, "hostname");
                if (!string.IsNullOrEmpty(host)) risk.Rdns = host;
                risk.ProxycheckScore = JsonHelper.GetNullableInt(pc, "risk");

                var proxyStr = JsonHelper.GetString(pc, "proxy").ToLowerInvariant();
                var typeStr = JsonHelper.GetString(pc, "type").ToLowerInvariant();
                if (proxyStr == "yes") risk.IsProxy = true;
                if (typeStr.Contains("vpn")) risk.IsVPN = true;
                if (typeStr.Contains("hosting") || typeStr.Contains("datacenter")) risk.IsDatacenter = true;
                risk.Sources.Add("proxycheck");
            }

            var scores = new List<int>();
            if (risk.IpqueryScore.HasValue) scores.Add(risk.IpqueryScore.Value);
            if (risk.ProxycheckScore.HasValue) scores.Add(risk.ProxycheckScore.Value);
            risk.Score = scores.Count > 0
                ? scores.Max()
                : (risk.IsProxy || risk.IsVPN ? 65 : (risk.IsDatacenter ? 35 : 0));

            detail.IsHosting = risk.IsDatacenter;
            detail.IsProxy = risk.IsProxy || risk.IsVPN || risk.IsTor;
            detail.IsMobile = risk.IsMobile;

            if (risk.IsTor || risk.IsVPN || risk.IsProxy) detail.IpType = IPTypeCategory.Proxy;
            else if (risk.IsDatacenter) detail.IpType = IPTypeCategory.Datacenter;
            else if (risk.IsMobile) detail.IpType = IPTypeCategory.Mobile;
            else if (risk.Sources.Count > 0) detail.IpType = IPTypeCategory.Residential;
            else detail.IpType = IPTypeCategory.Unknown;

            return Tuple.Create(detail, risk);
        }

        private static IPDetail MergeDetail(IPDetail baseDetail, IPDetail meta)
        {
            var merged = CloneDetail(meta);
            if (!string.IsNullOrEmpty(baseDetail.Ip)) merged.Ip = baseDetail.Ip;
            if (!string.IsNullOrEmpty(baseDetail.CountryCode)) merged.CountryCode = baseDetail.CountryCode;
            merged.Colo = baseDetail.Colo;
            merged.LatencyMs = baseDetail.LatencyMs;
            return merged;
        }

        private static IPDetail CloneDetail(IPDetail d)
        {
            return new IPDetail
            {
                Ip = d.Ip, Country = d.Country, CountryCode = d.CountryCode, Region = d.Region,
                City = d.City, Isp = d.Isp, Org = d.Org, Asn = d.Asn, Timezone = d.Timezone,
                IpType = d.IpType, IsHosting = d.IsHosting, IsProxy = d.IsProxy,
                IsMobile = d.IsMobile, Colo = d.Colo, LatencyMs = d.LatencyMs
            };
        }

        private static DNSLeakStatus EvaluateDNSStatus(DNSCheckResult dns, string exitCountryCode)
        {
            if (string.IsNullOrEmpty(dns.Ip)) return DNSLeakStatus.Unknown;
            if (dns.IsChinaDNS) return DNSLeakStatus.Leaked;
            if (!string.IsNullOrEmpty(dns.CountryCode) && !string.IsNullOrEmpty(exitCountryCode)
                && !string.Equals(dns.CountryCode, exitCountryCode, StringComparison.OrdinalIgnoreCase))
            {
                return DNSLeakStatus.Warning;
            }
            return DNSLeakStatus.Safe;
        }

        private async Task<IPv6CheckResult> EvaluateIPv6Async(HttpClient client, string rawIPv6, string exitCountryCode)
        {
            if (string.IsNullOrEmpty(rawIPv6))
            {
                return new IPv6CheckResult
                {
                    Status = CheckState.Safe,
                    Ip = "",
                    Label = "已屏蔽 / 无泄露",
                    Detail = "IPv6 未暴露"
                };
            }
            var meta = await FetchIPApiAsync(client, rawIPv6);
            if (meta != null)
            {
                var cc = JsonHelper.GetString(meta, "countryCode").ToUpperInvariant();
                var country = JsonHelper.GetString(meta, "country", cc);
                if (!ClaudeRegionChecker.IsSupported(cc))
                {
                    return new IPv6CheckResult
                    {
                        Status = CheckState.Danger,
                        Ip = rawIPv6,
                        Label = "IPv6 泄露(" + cc + ")",
                        Detail = rawIPv6 + " · " + country
                    };
                }
                if (!string.IsNullOrEmpty(exitCountryCode) && cc != exitCountryCode)
                {
                    return new IPv6CheckResult
                    {
                        Status = CheckState.Warning,
                        Ip = rawIPv6,
                        Label = "双栈跨区(" + cc + ")",
                        Detail = rawIPv6 + " · " + country
                    };
                }
                return new IPv6CheckResult
                {
                    Status = CheckState.Safe,
                    Ip = rawIPv6,
                    Label = "同区双栈(" + cc + ")",
                    Detail = rawIPv6 + " · " + country
                };
            }
            return new IPv6CheckResult
            {
                Status = CheckState.Warning,
                Ip = rawIPv6,
                Label = "检测到 IPv6",
                Detail = rawIPv6
            };
        }

        private static STUNCheckResult EvaluateSTUN(string mappedIP, string claudeIP, string directIP)
        {
            if (string.IsNullOrEmpty(mappedIP))
            {
                return new STUNCheckResult
                {
                    Status = CheckState.Safe,
                    MappedIP = "",
                    Label = "UDP 受控/未泄露",
                    Detail = "STUN 未返回本地公网 IP"
                };
            }
            if (!string.IsNullOrEmpty(directIP) && mappedIP == directIP && mappedIP != claudeIP)
            {
                return new STUNCheckResult
                {
                    Status = CheckState.Danger,
                    MappedIP = mappedIP,
                    Label = "UDP 本地泄露",
                    Detail = "STUN 暴露国内 IP: " + mappedIP
                };
            }
            if (!string.IsNullOrEmpty(claudeIP) && mappedIP == claudeIP)
            {
                return new STUNCheckResult
                {
                    Status = CheckState.Safe,
                    MappedIP = mappedIP,
                    Label = "无泄露 · 一致",
                    Detail = mappedIP
                };
            }
            return new STUNCheckResult
            {
                Status = CheckState.Warning,
                MappedIP = mappedIP,
                Label = "出口不一致",
                Detail = "STUN: " + mappedIP
            };
        }

        private static RouteConsistencyResult EvaluateRouteConsistency(IPDetail web, IPDetail api, IPDetail cf)
        {
            if (string.IsNullOrEmpty(web.Ip))
            {
                return new RouteConsistencyResult
                {
                    Status = CheckState.Danger,
                    ClaudeWebIP = web.Ip, AnthropicApiIP = api.Ip, CloudflareIP = cf.Ip,
                    AllMatch = false, Label = "Claude 不可达", Detail = "claude.ai 探测失败"
                };
            }
            if (!string.IsNullOrEmpty(api.Ip) && api.Ip != web.Ip)
            {
                bool crossCountry = !string.IsNullOrEmpty(web.CountryCode) && !string.IsNullOrEmpty(api.CountryCode) && web.CountryCode != api.CountryCode;
                return new RouteConsistencyResult
                {
                    Status = crossCountry ? CheckState.Danger : CheckState.Warning,
                    ClaudeWebIP = web.Ip, AnthropicApiIP = api.Ip, CloudflareIP = cf.Ip,
                    AllMatch = false,
                    Label = crossCountry ? "跨国分流异常" : "API 出口不同",
                    Detail = string.Format("Web: {0}({1}) vs API: {2}({3})", web.Ip, web.CountryCode, api.Ip, api.CountryCode)
                };
            }
            if (!string.IsNullOrEmpty(cf.Ip) && cf.Ip != web.Ip)
            {
                return new RouteConsistencyResult
                {
                    Status = CheckState.Warning,
                    ClaudeWebIP = web.Ip, AnthropicApiIP = api.Ip, CloudflareIP = cf.Ip,
                    AllMatch = false,
                    Label = "CF 出口分流",
                    Detail = string.Format("Claude: {0} / CF: {1}", web.Ip, cf.Ip)
                };
            }
            return new RouteConsistencyResult
            {
                Status = CheckState.Safe,
                ClaudeWebIP = web.Ip, AnthropicApiIP = api.Ip, CloudflareIP = cf.Ip,
                AllMatch = true, Label = "全站一致", Detail = "Web / API / CF 出口完全一致"
            };
        }

        private static TimezoneCheckResult EvaluateTimezone(string ipTimezone, string ipLocalTimeStr)
        {
            var localTz = TimeZoneInfo.Local;
            double? diffHours = null;

            if (!string.IsNullOrEmpty(ipLocalTimeStr))
            {
                DateTime remoteLocal;
                if (DateTime.TryParse(ipLocalTimeStr, CultureInfo.InvariantCulture, DateTimeStyles.None, out remoteLocal))
                {
                    var rawDiff = (remoteLocal - DateTime.Now).TotalHours;
                    diffHours = Math.Round(rawDiff * 2.0) / 2.0;
                }
            }

            if (!diffHours.HasValue && !string.IsNullOrEmpty(ipTimezone))
            {
                var ianaOffsets = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Asia/Tokyo"] = 9, ["Asia/Seoul"] = 9, ["Asia/Taipei"] = 8,
                    ["Asia/Singapore"] = 8, ["Asia/Hong_Kong"] = 8, ["Asia/Shanghai"] = 8,
                    ["America/Los_Angeles"] = -8, ["America/New_York"] = -5, ["America/Chicago"] = -6,
                    ["Europe/London"] = 0, ["Europe/Berlin"] = 1, ["Europe/Paris"] = 1,
                    ["Europe/Amsterdam"] = 1, ["Australia/Sydney"] = 10
                };
                if (ianaOffsets.ContainsKey(ipTimezone))
                {
                    var localOffset = localTz.GetUtcOffset(DateTime.Now).TotalHours;
                    diffHours = ianaOffsets[ipTimezone] - localOffset;
                }
            }

            string label = "";
            if (diffHours.HasValue)
            {
                if (Math.Abs(diffHours.Value) < 0.1)
                {
                    label = "时区一致";
                }
                else
                {
                    var sign = diffHours.Value > 0 ? "+" : "";
                    var num = Math.Abs(diffHours.Value % 1) < 0.01
                        ? diffHours.Value.ToString("0", CultureInfo.InvariantCulture)
                        : diffHours.Value.ToString("0.0", CultureInfo.InvariantCulture);
                    label = "时差 " + sign + num + "h";
                }
            }

            return new TimezoneCheckResult
            {
                LocalTimezone = localTz.Id,
                IpTimezone = ipTimezone,
                HourDiff = diffHours,
                Label = label
            };
        }

        private static Tuple<OverallLevel, string, List<string>> EvaluateOverall(
            IPDetail claudeExit,
            bool claudeSupported,
            DNSCheckResult dns,
            IPv6CheckResult ipv6,
            STUNCheckResult stun,
            RouteConsistencyResult routeConsistency,
            RiskAssessment risk)
        {
            var dangers = new List<string>();
            var warnings = new List<string>();

            if (string.IsNullOrEmpty(claudeExit.Ip))
                dangers.Add("无法连接 Claude 出口");

            if (dns.Status == DNSLeakStatus.Leaked)
                dangers.Add("DNS 泄露至中国大陆（" + dns.Provider + "）");
            else if (dns.Status == DNSLeakStatus.Warning)
                warnings.Add("DNS 出口（" + dns.CountryCode + "）与节点跨区");
            else if (dns.Status == DNSLeakStatus.Unknown)
                warnings.Add("DNS 检测失败，无法确认是否存在泄露");

            if (!string.IsNullOrEmpty(claudeExit.Ip) && !claudeSupported)
                dangers.Add("当前出口地区（" + claudeExit.CountryCode + "）不支持 Claude");

            if (ipv6.Status == CheckState.Danger)
                dangers.Add("检测到 IPv6 泄露（" + ipv6.Label + "）");
            else if (ipv6.Status == CheckState.Warning)
                warnings.Add("IPv6 出口与 IPv4 跨区");

            if (stun.Status == CheckState.Danger)
                dangers.Add("UDP / WebRTC 泄露本地真实 IP");
            else if (stun.Status == CheckState.Warning)
                warnings.Add("UDP STUN 出口与主代理不一致");

            if (routeConsistency.Status == CheckState.Danger)
                dangers.Add("Anthropic 网页与 API 跨国分流");
            else if (routeConsistency.Status == CheckState.Warning)
                warnings.Add(routeConsistency.Label);

            if (risk.IsTor)
                dangers.Add("出口 IP 被标记为 Tor 节点");
            else if (risk.Score >= 60)
                dangers.Add("IP 风险分过高（" + risk.Score + "/100）");
            else if (risk.IsVPN || risk.IsProxy)
                warnings.Add("IP 存在 VPN/Proxy 标记（风险分 " + risk.Score + "）");
            else if (risk.IsDatacenter || risk.Score >= 20)
                warnings.Add("当前为机房 IP 或风险分偏高（" + risk.Score + "/100）");

            if (dangers.Count > 0)
            {
                var all = new List<string>(dangers);
                all.AddRange(warnings);
                return Tuple.Create(OverallLevel.Danger, dangers[0], all);
            }
            if (warnings.Count > 0)
            {
                return Tuple.Create(OverallLevel.Warning, warnings[0], warnings);
            }

            var place = string.IsNullOrEmpty(claudeExit.Country) ? claudeExit.CountryCode : claudeExit.Country;
            string shortType = "常规 IP";
            switch (claudeExit.IpType)
            {
                case IPTypeCategory.Residential: shortType = "住宅 IP"; break;
                case IPTypeCategory.Mobile: shortType = "移动 IP"; break;
                case IPTypeCategory.Datacenter: shortType = "机房 IP"; break;
                case IPTypeCategory.Proxy: shortType = "代理 IP"; break;
            }
            return Tuple.Create(OverallLevel.Safe, string.Format("{0} · {1} · 风险分 {2} · 无泄露", shortType, place, risk.Score), new List<string>());
        }
    }
}
