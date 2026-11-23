using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ClaudeIPGuard
{
    public class MonitorService
    {
        private const string RunRegPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string SettingsRegPath = @"Software\ClaudeIPGuard";
        private const string AppRegName = "ClaudeIPGuard";

        private readonly IPChecker _checker = new IPChecker();
        private readonly ClashClient _clashClient = new ClashClient();
        private readonly object _lock = new object();

        private DetectionSnapshot _snapshot = new DetectionSnapshot();
        private LocalHttpServer _httpServer;
        private Timer _clashTimer;
        private Timer _periodicTimer;
        private CancellationTokenSource _debounceCts;
        private int _isCheckingFlag = 0;

        private class DriftEvent
        {
            public DateTime Timestamp;
            public CheckState Severity;
            public int? DistanceKm;
            public string Route;
            public string Detail;
        }

        private string _lastClashSig = "";
        private IPDetail _trackedExit = null;
        private string _trackedNodeSig = "";
        private int _sessionIPChangeCount = 0;
        private int _unexpectedDriftCount = 0;
        private readonly List<DriftEvent> _recentDrifts = new List<DriftEvent>();
        private string _lastIPChangedAt = "";
        private string _lastAlertSummary = "";
        private DateTime _lastAlertTime = DateTime.MinValue;

        public event Action<DetectionSnapshot, bool> SnapshotChanged;
        public event Action<string, string> DangerAlertTriggered;

        public int RefreshIntervalSeconds { get; private set; }
        public bool AlertsEnabled { get; private set; }
        public bool AlwaysOnTop { get; private set; }

        public bool IsChecking
        {
            get { return Interlocked.CompareExchange(ref _isCheckingFlag, 0, 0) == 1; }
        }

        public DetectionSnapshot CurrentSnapshot
        {
            get { lock (_lock) return _snapshot; }
        }

        public MonitorService()
        {
            RefreshIntervalSeconds = ReadIntSetting("RefreshIntervalSeconds", 300);
            AlertsEnabled = ReadBoolSetting("AlertsEnabled", true);
            AlwaysOnTop = ReadBoolSetting("AlwaysOnTop", true);
        }

        public void Start()
        {
            _httpServer = new LocalHttpServer(
                17899,
                () => CurrentSnapshot,
                () => TriggerCheckAsync("API 触发刷新"));
            _httpServer.Start();

            Task.Run(() =>
            {
                _lastClashSig = _clashClient.FetchState().Signature;
            });

            _clashTimer = new Timer(state => PollClash(), null, 2500, 2000);
            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            ReschedulePeriodicTimer();

            var initTask = TriggerCheckAsync("启动检测");
        }

        public void Stop()
        {
            try { NetworkChange.NetworkAddressChanged -= OnNetworkChanged; } catch { }
            try { _clashTimer?.Dispose(); } catch { }
            try { _periodicTimer?.Dispose(); } catch { }
            try { _debounceCts?.Cancel(); } catch { }
            try { _httpServer?.Stop(); } catch { }
        }

        public void SetRefreshInterval(int seconds)
        {
            RefreshIntervalSeconds = seconds;
            WriteIntSetting("RefreshIntervalSeconds", seconds);
            ReschedulePeriodicTimer();
        }

        public void SetAlertsEnabled(bool enabled)
        {
            AlertsEnabled = enabled;
            WriteBoolSetting("AlertsEnabled", enabled);
        }

        public void SetAlwaysOnTop(bool enabled)
        {
            AlwaysOnTop = enabled;
            WriteBoolSetting("AlwaysOnTop", enabled);
        }

        public bool IsLaunchAtLoginEnabled()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(RunRegPath, false))
                {
                    var val = key?.GetValue(AppRegName) as string;
                    return !string.IsNullOrWhiteSpace(val);
                }
            }
            catch
            {
                return false;
            }
        }

        public void SetLaunchAtLogin(bool enabled)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(RunRegPath, true))
                {
                    if (key == null) return;
                    if (enabled)
                    {
                        var exe = Process.GetCurrentProcess().MainModule?.FileName
                                  ?? Assembly.GetExecutingAssembly().Location;
                        key.SetValue(AppRegName, "\"" + exe + "\"");
                    }
                    else
                    {
                        key.DeleteValue(AppRegName, false);
                    }
                }
            }
            catch { }
        }

        public async Task<DetectionSnapshot> TriggerCheckAsync(string reason)
        {
            Interlocked.Exchange(ref _isCheckingFlag, 1);
            SnapshotChanged?.Invoke(CurrentSnapshot, true);

            try
            {
                var raw = await _checker.RunFullCheckAsync(reason);
                var enriched = ApplyStabilityAndAlerts(raw);
                lock (_lock)
                {
                    _snapshot = enriched;
                    _lastClashSig = enriched.Clash.Signature;
                }
                Interlocked.Exchange(ref _isCheckingFlag, 0);
                SnapshotChanged?.Invoke(enriched, false);
                return enriched;
            }
            catch
            {
                Interlocked.Exchange(ref _isCheckingFlag, 0);
                SnapshotChanged?.Invoke(CurrentSnapshot, false);
                return CurrentSnapshot;
            }
        }

        private void ScheduleDebouncedCheck(string reason, int delayMs)
        {
            try { _debounceCts?.Cancel(); } catch { }
            var cts = new CancellationTokenSource();
            _debounceCts = cts;
            Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(delayMs, cts.Token);
                    if (!cts.IsCancellationRequested)
                    {
                        await TriggerCheckAsync(reason);
                    }
                }
                catch { }
            });
        }

        private void PollClash()
        {
            try
            {
                var state = _clashClient.FetchState();
                var sig = state.Signature;
                if (!string.IsNullOrEmpty(_lastClashSig) && sig != _lastClashSig)
                {
                    _lastClashSig = sig;
                    var reason = state.Running ? ("节点切换 → " + state.ActiveNode) : "Clash 状态变动";
                    ScheduleDebouncedCheck(reason, 1100);
                }
                else if (string.IsNullOrEmpty(_lastClashSig))
                {
                    _lastClashSig = sig;
                }
            }
            catch { }
        }

        private void OnNetworkChanged(object sender, EventArgs e)
        {
            ScheduleDebouncedCheck("系统网络变动", 1800);
        }

        private void ReschedulePeriodicTimer()
        {
            try { _periodicTimer?.Dispose(); } catch { }
            _periodicTimer = null;
            if (RefreshIntervalSeconds <= 0) return;
            int ms = RefreshIntervalSeconds * 1000;
            _periodicTimer = new Timer(_ =>
            {
                var __ = TriggerCheckAsync("定时刷新");
            }, null, ms, ms);
        }

        private static int HaversineKm(double lat1, double lon1, double lat2, double lon2)
        {
            const double r = 6371.0;
            double dLat = (lat2 - lat1) * Math.PI / 180.0;
            double dLon = (lon2 - lon1) * Math.PI / 180.0;
            double a = Math.Sin(dLat / 2.0) * Math.Sin(dLat / 2.0)
                + Math.Cos(lat1 * Math.PI / 180.0) * Math.Cos(lat2 * Math.PI / 180.0)
                * Math.Sin(dLon / 2.0) * Math.Sin(dLon / 2.0);
            double c = 2.0 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(Math.Max(0.0, 1.0 - a)));
            return (int)Math.Round(r * c);
        }

        private DetectionSnapshot ApplyStabilityAndAlerts(DetectionSnapshot result)
        {
            var now = result.UpdatedAt;
            var newExit = result.ClaudeExit;
            var newIP = newExit.Ip;
            var newNodeSig = result.Clash.Signature;

            _recentDrifts.RemoveAll(ev => (now - ev.Timestamp).TotalSeconds > 3600);

            if (!string.IsNullOrEmpty(newIP))
            {
                if (_trackedExit != null && !string.IsNullOrEmpty(_trackedExit.Ip) && newIP != _trackedExit.Ip)
                {
                    _sessionIPChangeCount++;
                    _lastIPChangedAt = now.ToString("HH:mm:ss");
                    bool nodeChanged = newNodeSig != _trackedNodeSig;
                    if (nodeChanged)
                    {
                        _recentDrifts.Clear();
                    }
                    else
                    {
                        _unexpectedDriftCount++;
                        var prev = _trackedExit;
                        bool crossCountry = !string.IsNullOrEmpty(prev.CountryCode) && !string.IsNullOrEmpty(newExit.CountryCode)
                            && !string.Equals(prev.CountryCode, newExit.CountryCode, StringComparison.OrdinalIgnoreCase);
                        bool asnChanged = !string.IsNullOrEmpty(prev.Asn) && !string.IsNullOrEmpty(newExit.Asn)
                            && !string.Equals(prev.Asn, newExit.Asn, StringComparison.OrdinalIgnoreCase);
                        bool regionChanged = !string.IsNullOrEmpty(prev.Region) && !string.IsNullOrEmpty(newExit.Region)
                            && !string.Equals(prev.Region, newExit.Region, StringComparison.OrdinalIgnoreCase);

                        int? distKm = null;
                        if (prev.Latitude.HasValue && prev.Longitude.HasValue
                            && newExit.Latitude.HasValue && newExit.Longitude.HasValue)
                        {
                            distKm = HaversineKm(prev.Latitude.Value, prev.Longitude.Value, newExit.Latitude.Value, newExit.Longitude.Value);
                        }

                        string fromLabel = regionChanged
                            ? (string.IsNullOrEmpty(prev.Region) ? prev.City : prev.Region)
                            : (!string.IsNullOrEmpty(prev.City) ? prev.City : (!string.IsNullOrEmpty(prev.Region) ? prev.Region : prev.CountryCode));
                        string toLabel = regionChanged
                            ? (string.IsNullOrEmpty(newExit.Region) ? newExit.City : newExit.Region)
                            : (!string.IsNullOrEmpty(newExit.City) ? newExit.City : (!string.IsNullOrEmpty(newExit.Region) ? newExit.Region : newExit.CountryCode));
                        string routeText = (!string.IsNullOrEmpty(fromLabel) && !string.IsNullOrEmpty(toLabel))
                            ? (fromLabel + " → " + toLabel)
                            : "";

                        CheckState severity;
                        string detail;
                        if (crossCountry)
                        {
                            severity = CheckState.Danger;
                            detail = "跨国漂移：" + prev.CountryCode + " → " + newExit.CountryCode;
                        }
                        else if (distKm.HasValue && distKm.Value > 500)
                        {
                            severity = CheckState.Danger;
                            detail = string.Format("超远跨城：{0}（约 {1}km）", routeText, distKm.Value);
                        }
                        else if (distKm.HasValue && distKm.Value > 80)
                        {
                            severity = CheckState.Warning;
                            detail = string.Format("跨城漂移：{0}（约 {1}km）", routeText, distKm.Value);
                        }
                        else if (!distKm.HasValue && regionChanged)
                        {
                            severity = CheckState.Warning;
                            detail = "跨区漂移：" + routeText;
                        }
                        else if (asnChanged)
                        {
                            severity = CheckState.Warning;
                            detail = string.Format("跨运营商漂移（{0} → {1}）", prev.Asn, newExit.Asn);
                        }
                        else
                        {
                            severity = CheckState.Safe;
                            string distPart = distKm.HasValue ? ("约 " + distKm.Value + "km · ") : "";
                            detail = "同城微漂移（" + distPart + "正常家宽波动）";
                        }

                        _recentDrifts.Add(new DriftEvent
                        {
                            Timestamp = now,
                            Severity = severity,
                            DistanceKm = distKm,
                            Route = routeText,
                            Detail = detail
                        });
                    }
                }
                _trackedExit = newExit;
                _trackedNodeSig = newNodeSig;
            }

            var stability = new IPStabilityInfo
            {
                SessionChangeCount = _sessionIPChangeCount,
                UnexpectedDriftCount = _unexpectedDriftCount,
                RecentDriftCount1h = _recentDrifts.Count,
                LastChangedAt = _lastIPChangedAt
            };

            var latestEvent = _recentDrifts.LastOrDefault();
            var worstDanger = _recentDrifts.LastOrDefault(ev => ev.Severity == CheckState.Danger);
            var worstWarning = _recentDrifts.LastOrDefault(ev => ev.Severity == CheckState.Warning);
            var best = worstDanger ?? worstWarning ?? latestEvent;
            if (best != null)
            {
                stability.LastDriftDistanceKm = best.DistanceKm;
                stability.LastDriftRoute = best.Route;
            }

            if (_recentDrifts.Count == 0)
            {
                stability.Status = CheckState.Safe;
                stability.Label = _sessionIPChangeCount > 0
                    ? string.Format("稳定 · 手动切换 {0} 次", _sessionIPChangeCount)
                    : "稳定 · 无异常跳变";
            }
            else if (worstDanger != null)
            {
                stability.Status = CheckState.Danger;
                stability.Label = worstDanger.Detail;
                result.RiskAlerts.Add(worstDanger.Detail);
                if (result.OverallLevel != OverallLevel.Danger)
                {
                    result.OverallLevel = OverallLevel.Danger;
                    result.OverallSummary = worstDanger.Detail;
                }
            }
            else if (_recentDrifts.Count >= 4)
            {
                stability.Status = CheckState.Danger;
                stability.Label = string.Format("高频漂移（{0}次/1h）", _recentDrifts.Count);
                result.RiskAlerts.Add(string.Format("1 小时内出口 IP 自动漂移 {0} 次（疑似动态轮换池）", _recentDrifts.Count));
                if (result.OverallLevel != OverallLevel.Danger)
                {
                    result.OverallLevel = OverallLevel.Danger;
                    result.OverallSummary = string.Format("1 小时内高频漂移 {0} 次", _recentDrifts.Count);
                }
            }
            else if (worstWarning != null)
            {
                stability.Status = CheckState.Warning;
                stability.Label = worstWarning.Detail;
                result.RiskAlerts.Add(worstWarning.Detail);
                if (result.OverallLevel == OverallLevel.Safe)
                {
                    result.OverallLevel = OverallLevel.Warning;
                    result.OverallSummary = worstWarning.Detail;
                }
            }
            else if (_recentDrifts.Count >= 2)
            {
                stability.Status = CheckState.Warning;
                stability.Label = string.Format("同城较频漂移（{0}次/1h）", _recentDrifts.Count);
                result.RiskAlerts.Add(string.Format("1 小时内同城 IP 变动 {0} 次", _recentDrifts.Count));
                if (result.OverallLevel == OverallLevel.Safe)
                {
                    result.OverallLevel = OverallLevel.Warning;
                    result.OverallSummary = string.Format("1 小时内同城漂移 {0} 次", _recentDrifts.Count);
                }
            }
            else
            {
                stability.Status = CheckState.Safe;
                string kmStr = (latestEvent != null && latestEvent.DistanceKm.HasValue)
                    ? ("约 " + latestEvent.DistanceKm.Value + "km · ")
                    : "";
                stability.Label = "同城微漂移（" + kmStr + "1次/1h · 正常）";
            }

            result.Stability = stability;

            if (AlertsEnabled && result.OverallLevel == OverallLevel.Danger)
            {
                var nowAlert = DateTime.Now;
                if (result.OverallSummary != _lastAlertSummary || (nowAlert - _lastAlertTime).TotalSeconds > 180)
                {
                    _lastAlertSummary = result.OverallSummary;
                    _lastAlertTime = nowAlert;
                    DangerAlertTriggered?.Invoke("ClaudeIPGuard 高危预警", result.OverallSummary);
                }
            }
            else if (result.OverallLevel == OverallLevel.Safe)
            {
                _lastAlertSummary = "";
            }

            return result;
        }

        private static int ReadIntSetting(string name, int fallback)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(SettingsRegPath, false))
                {
                    if (key != null && key.GetValue(name) != null)
                        return Convert.ToInt32(key.GetValue(name));
                }
            }
            catch { }
            return fallback;
        }

        private static bool ReadBoolSetting(string name, bool fallback)
        {
            return ReadIntSetting(name, fallback ? 1 : 0) != 0;
        }

        private static void WriteIntSetting(string name, int val)
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(SettingsRegPath))
                {
                    key?.SetValue(name, val, RegistryValueKind.DWord);
                }
            }
            catch { }
        }

        private static void WriteBoolSetting(string name, bool val)
        {
            WriteIntSetting(name, val ? 1 : 0);
        }
    }
}
