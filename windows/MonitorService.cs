using System;
using System.Diagnostics;
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

        private string _lastClashSig = "";
        private string _trackedExitIP = "";
        private string _trackedExitCountry = "";
        private string _trackedNodeSig = "";
        private int _sessionIPChangeCount = 0;
        private int _unexpectedDriftCount = 0;
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

            _clashTimer = new Timer(_ => PollClash(), null, 2500, 2000);
            NetworkChange.NetworkAddressChanged += OnNetworkChanged;
            ReschedulePeriodicTimer();

            var _ = TriggerCheckAsync("启动检测");
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

        private DetectionSnapshot ApplyStabilityAndAlerts(DetectionSnapshot result)
        {
            var newIP = result.ClaudeExit.Ip;
            var newCountry = result.ClaudeExit.CountryCode;
            var newNodeSig = result.Clash.Signature;

            bool unexpectedCrossCountry = false;
            bool unexpectedIPDrift = false;

            if (!string.IsNullOrEmpty(newIP))
            {
                if (!string.IsNullOrEmpty(_trackedExitIP) && newIP != _trackedExitIP)
                {
                    _sessionIPChangeCount++;
                    _lastIPChangedAt = result.UpdatedAt.ToString("HH:mm:ss");
                    bool nodeChanged = newNodeSig != _trackedNodeSig;
                    if (!nodeChanged)
                    {
                        _unexpectedDriftCount++;
                        unexpectedIPDrift = true;
                        if (!string.IsNullOrEmpty(_trackedExitCountry) && !string.IsNullOrEmpty(newCountry) && newCountry != _trackedExitCountry)
                        {
                            unexpectedCrossCountry = true;
                        }
                    }
                }
                _trackedExitIP = newIP;
                _trackedExitCountry = newCountry;
                _trackedNodeSig = newNodeSig;
            }

            var stability = new IPStabilityInfo
            {
                SessionChangeCount = _sessionIPChangeCount,
                UnexpectedDriftCount = _unexpectedDriftCount,
                LastChangedAt = _lastIPChangedAt
            };

            if (unexpectedCrossCountry)
            {
                stability.Status = CheckState.Danger;
                stability.Label = string.Format("未切节点跨国漂移（{0}次）", _unexpectedDriftCount);
                result.RiskAlerts.Add("未切节点但出口 IP 跨国漂移至 " + newCountry);
                if (result.OverallLevel != OverallLevel.Danger)
                {
                    result.OverallLevel = OverallLevel.Danger;
                    result.OverallSummary = "出口 IP 异常跨国漂移（" + newCountry + "）";
                }
            }
            else if (_unexpectedDriftCount > 0)
            {
                stability.Status = CheckState.Warning;
                stability.Label = string.Format("自动漂移 {0} 次{1}", _unexpectedDriftCount, string.IsNullOrEmpty(_lastIPChangedAt) ? "" : " · " + _lastIPChangedAt);
                if (unexpectedIPDrift) result.RiskAlerts.Add("当前节点出口 IP 自动更换（动态/负载均衡）");
                if (result.OverallLevel == OverallLevel.Safe)
                {
                    result.OverallLevel = OverallLevel.Warning;
                    result.OverallSummary = "地区正常，但节点 IP 存在自动漂移";
                }
            }
            else if (_sessionIPChangeCount > 0)
            {
                stability.Status = CheckState.Safe;
                stability.Label = string.Format("稳定 · 手动切换 {0} 次", _sessionIPChangeCount);
            }
            else
            {
                stability.Status = CheckState.Safe;
                stability.Label = "稳定 · 无异常跳变";
            }

            result.Stability = stability;

            if (AlertsEnabled && result.OverallLevel == OverallLevel.Danger)
            {
                var now = DateTime.Now;
                if (result.OverallSummary != _lastAlertSummary || (now - _lastAlertTime).TotalSeconds > 180)
                {
                    _lastAlertSummary = result.OverallSummary;
                    _lastAlertTime = now;
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
