using System;
using System.Collections.Generic;
using System.Text;

namespace ClaudeIPGuard
{
    public static class FixPromptGenerator
    {
        public static string Generate(DetectionSnapshot snap)
        {
            string levelTag;
            string levelAdvice;
            switch (snap.OverallLevel)
            {
                case OverallLevel.Danger:
                    levelTag = "🔴 红色高危警报（建议立即修复后再使用 Claude）";
                    levelAdvice = "当前存在高危封控/泄露红线，请优先帮我排查并彻底修复以下问题。";
                    break;
                case OverallLevel.Warning:
                    levelTag = "🟡 黄色风险预警（存在潜在风控风险）";
                    levelAdvice = "当前环境存在一定风险或不确定项，请帮我优化节点或网络配置以达到全绿安全状态。";
                    break;
                case OverallLevel.Safe:
                    levelTag = "🟢 当前环境正常（常规体检/备份诊断）";
                    levelAdvice = "当前各项指标均已通过，如需进一步优化延迟或稳定性可参考以下环境信息。";
                    break;
                default:
                    levelTag = "⏳ 正在检测中";
                    levelAdvice = "检测尚未完成，请先执行一次刷新接口获取最新状态后再排查。";
                    break;
            }

            var issues = new List<string>();
            var steps = new List<string>();

            if (string.IsNullOrEmpty(snap.ClaudeExit.Ip))
            {
                issues.Add("🔴 **无法连接 Claude 出口**：探测 `claude.ai` 超时或失败。");
                steps.Add("- **排查代理连通性**：检查 Clash Verge（或其他代理软件）是否正常运行、系统代理/TUN 是否开启；通过本地控制接口（Windows Named Pipe `\\\\.\\pipe\\verge-mihomo` 或 `127.0.0.1:9097`）检查节点延迟并切换可用海外节点。");
            }

            if (!string.IsNullOrEmpty(snap.ClaudeExit.Ip) && !snap.ClaudeSupported)
            {
                issues.Add(string.Format("🔴 **出口地区不支持 Claude**：当前 `claude.ai` 出口位于 `{0}`（{1}），属于 Anthropic 受限地区。", snap.ClaudeExit.CountryCode, snap.ClaudeExit.Country));
                steps.Add("- **切换 Clash 节点至支持地区（最常见原因）**：读取 Clash Verge 策略组列表，筛选并切换到 **日本（JP）、台湾（TW）、美国（US）、新加坡（SG）或欧洲** 等 Claude 支持地区节点，**严禁选择香港（HK）/ 澳门（MO）/ 中国大陆（CN）/ 俄罗斯（RU）**，优先选择标注「家宽 / 住宅 / ISP / 原生」的节点。");
            }

            switch (snap.Dns.Status)
            {
                case DNSLeakStatus.Leaked:
                    issues.Add(string.Format("🔴 **中国大陆 DNS 泄露**：DNS 出口为 `{0}`（{1}），暴露了本地运营商 DNS。", snap.Dns.Ip, snap.Dns.Geo));
                    steps.Add("- **修复 Clash Verge DNS 泄露**：\r\n  1. 检查 `%APPDATA%\\io.github.clash-verge-rev.clash-verge-rev\\verge.yaml`，确保开启 DNS 覆写：`enable_dns_settings: true`。\r\n  2. 检查同目录下 `dns_config.yaml`：确保 `enable: true`、`enhanced-mode: fake-ip`、`respect-rules: true`、`ipv6: false`，`nameserver` 设为 `https://1.1.1.1/dns-query` 和 `https://8.8.8.8/dns-query`，`direct-nameserver` 和 `proxy-server-nameserver` 使用国内 DoH（`https://dns.alidns.com/dns-query`、`https://doh.pub/dns-query`）。\r\n  3. 重启 Clash Verge 使配置生效。");
                    break;
                case DNSLeakStatus.Unknown:
                    issues.Add("🟡 **DNS 泄露检测失败**：未能获取 DNS 出口 IP，无法确认是否存在 DNS 泄露。");
                    steps.Add("- **排查 DNS 探测失败原因**：优先切换延迟更稳定、丢包更低的 Clash 节点，并检查 `dns_config.yaml` 是否正确配置了海外加密 DNS 与 `respect-rules: true`。");
                    break;
                case DNSLeakStatus.Warning:
                    issues.Add(string.Format("🟡 **DNS 出口与节点跨区**：代理出口在 `{0}`，而 DNS 出口在 `{1}`（{2}）。", snap.ClaudeExit.CountryCode, snap.Dns.CountryCode, snap.Dns.Provider));
                    steps.Add("- **让 DNS 解析与代理节点同区**：检查 Clash Verge `dns_config.yaml` 是否开启 `respect-rules: true`，确保 DoH 请求通过当前代理节点出口发出。");
                    break;
            }

            if (snap.Ipv6.Status == CheckState.Danger || snap.Ipv6.Status == CheckState.Warning)
            {
                var icon = snap.Ipv6.Status == CheckState.Danger ? "🔴" : "🟡";
                issues.Add(string.Format("{0} **IPv6 异常（{1}）**：检测到 IPv6 出口 `{2}`（{3}）。", icon, snap.Ipv6.Label, snap.Ipv6.Ip, snap.Ipv6.Detail));
                steps.Add("- **关闭 Windows 公网 IPv6 防泄露**：\r\n  1. 在管理员 PowerShell 中运行 `Disable-NetAdapterBinding -Name \"*\" -ComponentID ms_tcpip6`（或在「网络适配器属性」中取消勾选 Internet 协议版本 6）。\r\n  2. 确保 Clash Verge 的 `dns_config.yaml` 中 `ipv6: false`。");
            }

            if (snap.Stun.Status == CheckState.Danger || snap.Stun.Status == CheckState.Warning)
            {
                var icon = snap.Stun.Status == CheckState.Danger ? "🔴" : "🟡";
                issues.Add(string.Format("{0} **UDP / WebRTC（STUN）异常（{1}）**：STUN 映射 IP 为 `{2}`，与 Claude 代理出口 `{3}` 不一致。", icon, snap.Stun.Label, snap.Stun.MappedIP, snap.ClaudeExit.Ip));
                steps.Add("- **修复 UDP / WebRTC 泄露**：检查当前 Clash 节点是否支持 UDP 转发（`udp: true`），确认开启 TUN 模式并检查 `fake-ip-filter` 是否误放行 `stun.*.*` 直连。");
            }

            if (snap.RouteConsistency.Status == CheckState.Danger || snap.RouteConsistency.Status == CheckState.Warning)
            {
                var icon = snap.RouteConsistency.Status == CheckState.Danger ? "🔴" : "🟡";
                issues.Add(string.Format("{0} **Anthropic 全站路由不一致（{1}）**：{2}。", icon, snap.RouteConsistency.Label, snap.RouteConsistency.Detail));
                steps.Add("- **统一 Anthropic 相关域名分流规则**：检查 Clash 分流规则，确保 `DOMAIN-SUFFIX,claude.ai`、`DOMAIN-SUFFIX,anthropic.com`、`DOMAIN-SUFFIX,claude.com` 统一指向同一个干净的代理策略组/固定节点。");
            }

            if (snap.Risk.Score >= 20 || snap.Risk.IsVPN || snap.Risk.IsProxy || snap.Risk.IsTor || snap.Risk.IsDatacenter)
            {
                var icon = (snap.Risk.Score >= 60 || snap.Risk.IsTor) ? "🔴" : "🟡";
                var flags = snap.Risk.RiskFlags.Count == 0 ? "风险分偏高" : string.Join(" / ", snap.Risk.RiskFlags);
                issues.Add(string.Format("{0} **出口 IP 纯净度风险**：双引擎风险分 `{1}/100`，IP 属性为「{2}」，命中标记：`{3}`。", icon, snap.Risk.Score, snap.ClaudeExit.IpTypeLabel, flags));
                steps.Add("- **更换更纯净的住宅 / 家宽节点（最有效方案）**：查看 Clash Verge 当前策略组下的全部可用节点，优先挑选标注「家宽 / 住宅 / ISP / 原生 / 静态」且位于日本/台湾/美国/新加坡的节点逐一切换；每次切换后调用 `curl.exe -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/refresh` 检查 `risk.score < 20` 且 `claudeExit.ipType` 为 `residential`。");
            }

            if (snap.Stability.Status == CheckState.Danger || snap.Stability.Status == CheckState.Warning)
            {
                var icon = snap.Stability.Status == CheckState.Danger ? "🔴" : "🟡";
                issues.Add(string.Format("{0} **出口 IP 不稳定 / 自动漂移**：{1}。", icon, snap.Stability.Label));
                steps.Add("- **改为固定单节点**：检查 Clash Verge 当前是否选用了自动测速（url-test）或负载均衡（load-balance）分组，切换为固定单个稳定住宅节点。");
            }

            var clashInfo = snap.Clash.Running
                ? string.Format("运行中（模式：{0}，TUN：{1}，节点链：{2}）", snap.Clash.Mode.ToUpperInvariant(), snap.Clash.TunEnabled ? "开启" : "关闭", snap.Clash.NodeChain)
                : "未检测到 Clash 本地控制接口（可能使用了其他代理软件，或未开启控制端口）";

            var exitLoc = string.IsNullOrEmpty(snap.ClaudeExit.City)
                ? (string.IsNullOrEmpty(snap.ClaudeExit.Country) ? snap.ClaudeExit.CountryCode : snap.ClaudeExit.Country)
                : snap.ClaudeExit.Country + " · " + snap.ClaudeExit.City;

            var sb = new StringBuilder();
            sb.AppendLine("请帮我排查并修复本机（Windows）使用 Claude AI 时的网络环境风险。");
            sb.AppendLine();
            sb.AppendLine("## 1. 警报等级");
            sb.AppendLine(levelTag);
            sb.AppendLine(levelAdvice);
            sb.AppendLine();
            sb.AppendLine("## 2. 检测到的问题");
            sb.AppendLine(issues.Count == 0 ? "- 暂无异常告警项。" : string.Join("\r\n", issues));
            sb.AppendLine();
            sb.AppendLine("## 3. 当前实时检测快照（来自 ClaudeIPGuard Windows）");
            sb.AppendLine("- **综合摘要**：" + snap.OverallSummary);
            sb.AppendLine(string.Format("- **Claude 出口 IP**：`{0}`（地区：{1}，支持状态：{2}，延迟：{3}ms）",
                string.IsNullOrEmpty(snap.ClaudeExit.Ip) ? "无" : snap.ClaudeExit.Ip,
                exitLoc,
                snap.ClaudeSupported ? "支持" : "不支持",
                snap.ClaudeExit.LatencyMs));
            sb.AppendLine(string.Format("- **IP 纯净度**：{0}｜双引擎风险分：`{1}/100`｜标记：{2}｜ASN/运营商：{3} {4}",
                snap.ClaudeExit.IpTypeLabel,
                snap.Risk.Score,
                snap.Risk.RiskFlags.Count == 0 ? "无" : string.Join(", ", snap.Risk.RiskFlags),
                snap.ClaudeExit.Asn,
                snap.ClaudeExit.Isp));
            sb.AppendLine(string.Format("- **DNS 泄露检测**：{0}（出口：`{1}`，{2}）",
                snap.Dns.StatusLabel,
                string.IsNullOrEmpty(snap.Dns.Ip) ? "未获取" : snap.Dns.Ip,
                string.IsNullOrEmpty(snap.Dns.Geo) ? "无" : snap.Dns.Geo));
            sb.AppendLine("- **IPv6 检测**：" + snap.Ipv6.Label + (string.IsNullOrEmpty(snap.Ipv6.Ip) ? "" : "（" + snap.Ipv6.Ip + "）"));
            sb.AppendLine("- **UDP / STUN 检测**：" + snap.Stun.Label + (string.IsNullOrEmpty(snap.Stun.MappedIP) ? "" : "（" + snap.Stun.MappedIP + "）"));
            sb.AppendLine(string.Format("- **全站路由一致性**：{0}（{1}）", snap.RouteConsistency.Label, snap.RouteConsistency.Detail));
            sb.AppendLine("- **IP 稳定性**：" + snap.Stability.Label);
            sb.AppendLine("- **代理软件状态**：" + clashInfo);
            sb.AppendLine();
            sb.AppendLine("## 4. 建议排查与修复方向");
            sb.AppendLine(steps.Count == 0 ? "- 如需优化节点速度或地区，可查看 Clash Verge 节点列表并切换后复测。" : string.Join("\r\n", steps));
            sb.AppendLine();
            sb.AppendLine("## 5. 执行要求与验收标准");
            sb.AppendLine("1. 修改任何本机配置文件前请先备份原文件；如果涉及切换 Clash Verge 节点，请优先选择纯净度高、延迟稳定的家宽/住宅节点。");
            sb.AppendLine("2. 修复完成后，请直接运行以下命令触发实时复测并核对结果：");
            sb.AppendLine("   ```powershell");
            sb.AppendLine("   curl.exe -s --noproxy 127.0.0.1 http://127.0.0.1:17899/api/refresh");
            sb.AppendLine("   ```");
            sb.AppendLine("3. 验收目标：`overallLevel` 变为 `\"safe\"`、`claudeSupported` 为 `true`、`dns.status` 为 `\"safe\"`、`ipv6.status` 为 `\"safe\"`、`stun.status` 为 `\"safe\"`、`routeConsistency.status` 为 `\"safe\"` 且 `risk.score < 20`。");

            return sb.ToString();
        }
    }
}
