using System;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace ClaudeIPGuard
{
    public partial class MainWindow : Window
    {
        private readonly MonitorService _monitor;
        private readonly DispatcherTimer _clockTimer;
        private readonly DispatcherTimer _toastTimer;
        private DetectionSnapshot _current = new DetectionSnapshot();
        private bool _isPinned = false;

        private static readonly Color GreenColor = Color.FromRgb(0x22, 0xC5, 0x5E);
        private static readonly Color OrangeColor = Color.FromRgb(0xF5, 0x9E, 0x0B);
        private static readonly Color RedColor = Color.FromRgb(0xEF, 0x44, 0x44);
        private static readonly Color BlueColor = Color.FromRgb(0x3B, 0x82, 0xF6);
        private static readonly Color GrayColor = Color.FromRgb(0x9B, 0xA1, 0xAE);

        public bool IsPinned
        {
            get { return _isPinned; }
        }

        public MainWindow(MonitorService monitor)
        {
            InitializeComponent();
            _monitor = monitor;
            Topmost = _monitor.AlwaysOnTop;

            _clockTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _clockTimer.Tick += (s, e) => UpdateLastRefreshText();
            _clockTimer.Start();

            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1800) };
            _toastTimer.Tick += (s, e) =>
            {
                ToastBorder.Visibility = Visibility.Collapsed;
                _toastTimer.Stop();
            };

            Deactivated += (s, e) =>
            {
                if (!_isPinned)
                {
                    Hide();
                }
            };

            Closing += (s, e) =>
            {
                e.Cancel = true;
                _isPinned = false;
                UpdatePinVisual();
                Hide();
            };

            RenderSnapshot(_monitor.CurrentSnapshot, _monitor.IsChecking);
        }

        public void PositionNearTray()
        {
            UpdateLayout();
            var work = SystemParameters.WorkArea;
            var h = ActualHeight > 100 ? ActualHeight : 600;
            Left = Math.Max(work.Left + 8, work.Right - Width - 8);
            Top = Math.Max(work.Top + 8, work.Bottom - h - 8);
        }

        public void TogglePin()
        {
            _isPinned = !_isPinned;
            Topmost = _isPinned ? _monitor.AlwaysOnTop : true;
            UpdatePinVisual();
            ShowToast(_isPinned ? "已钉在桌面角落（可拖动位置）" : "已取消固定");
        }

        private void UpdatePinVisual()
        {
            PinBtn.Background = _isPinned
                ? new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB))
                : new SolidColorBrush(Color.FromRgb(0x2A, 0x2E, 0x37));
            PinBtn.ToolTip = _isPinned ? "取消固定桌面悬浮窗" : "钉在桌面角落（常驻浮窗）";
        }

        public void RenderSnapshot(DetectionSnapshot snap, bool isChecking)
        {
            _current = snap;

            // 1. Top Banner
            var bannerColor = LevelColor(snap.OverallLevel);
            BannerBorder.Background = new SolidColorBrush(WithAlpha(bannerColor, 26));
            BannerBorder.BorderBrush = new SolidColorBrush(WithAlpha(bannerColor, 72));
            BannerIconBg.Background = new SolidColorBrush(WithAlpha(bannerColor, 46));
            BannerIconText.Foreground = new SolidColorBrush(bannerColor);
            BannerIconText.Text = snap.OverallLevel == OverallLevel.Safe ? "✓"
                : (snap.OverallLevel == OverallLevel.Warning ? "!"
                : (snap.OverallLevel == OverallLevel.Danger ? "✕" : "…"));
            BannerTitle.Text = snap.LevelTitle;
            BannerSummary.Text = snap.OverallSummary;
            RefreshBtn.Content = isChecking ? "…" : "↻";

            // 2. Red/Yellow AI Fix Prompt Bar
            bool showFix = snap.OverallLevel == OverallLevel.Warning || snap.OverallLevel == OverallLevel.Danger;
            AiFixBar.Visibility = showFix ? Visibility.Visible : Visibility.Collapsed;
            if (showFix)
            {
                var accent = snap.OverallLevel == OverallLevel.Danger ? RedColor : OrangeColor;
                int count = Math.Max(1, snap.RiskAlerts.Count);
                AiFixBar.Background = new SolidColorBrush(WithAlpha(accent, 28));
                AiFixBar.BorderBrush = new SolidColorBrush(WithAlpha(accent, 90));
                AiFixTitle.Foreground = new SolidColorBrush(accent);
                AiFixTitle.Text = snap.OverallLevel == OverallLevel.Danger
                    ? string.Format("高危警报 · 发现 {0} 项异常", count)
                    : string.Format("风险预警 · 发现 {0} 项待优化", count);
                CopyPromptBtn.Background = new SolidColorBrush(accent);
            }

            // 3. 2x2 Leak Guard Matrix
            bool allClear = snap.Dns.Status == DNSLeakStatus.Safe
                            && snap.Ipv6.Status == CheckState.Safe
                            && snap.Stun.Status == CheckState.Safe
                            && snap.RouteConsistency.Status == CheckState.Safe;
            var leakBadgeColor = allClear ? GreenColor : (snap.OverallLevel == OverallLevel.Danger ? RedColor : OrangeColor);
            SetBadge(LeakSummaryBadge, LeakSummaryText,
                allClear ? "4/4 全部通过" : (snap.OverallLevel == OverallLevel.Danger ? "发现泄露风险" : "需关注"),
                leakBadgeColor);

            var dnsCol = DnsColor(snap.Dns.Status);
            StyleTile(DnsTile, DnsDot, DnsValue, dnsCol);
            DnsValue.Text = snap.Dns.StatusLabel;
            DnsSub.Text = string.IsNullOrEmpty(snap.Dns.Ip)
                ? "未获取到出口"
                : (string.IsNullOrEmpty(snap.Dns.Provider) ? snap.Dns.Ip : (snap.Dns.CountryCode + " · " + snap.Dns.Provider).Trim(' ', '·'));
            DnsTile.ToolTip = string.IsNullOrEmpty(snap.Dns.Ip) ? "DNS 检测失败" : ("DNS IP: " + snap.Dns.Ip + " (" + snap.Dns.Geo + ") · 点击复制");

            var v6Col = StateColor(snap.Ipv6.Status);
            StyleTile(Ipv6Tile, Ipv6Dot, Ipv6Value, v6Col);
            Ipv6Value.Text = snap.Ipv6.Label;
            Ipv6Sub.Text = string.IsNullOrEmpty(snap.Ipv6.Detail) ? "IPv6 已隔离" : snap.Ipv6.Detail;

            var stunCol = StateColor(snap.Stun.Status);
            StyleTile(StunTile, StunDot, StunValue, stunCol);
            StunValue.Text = snap.Stun.Label;
            StunSub.Text = string.IsNullOrEmpty(snap.Stun.Detail) ? "检测中" : snap.Stun.Detail;

            var routeCol = StateColor(snap.RouteConsistency.Status);
            StyleTile(RouteTile, RouteDot, RouteValue, routeCol);
            RouteValue.Text = snap.RouteConsistency.Label;
            RouteSub.Text = string.IsNullOrEmpty(snap.RouteConsistency.Detail) ? "Web / API / CF" : snap.RouteConsistency.Detail;

            // 4. Claude Exit IP & Purity Card
            SetBadge(RiskScoreBadge, RiskScoreText, "风险分 " + snap.Risk.Score + "/100", StateColor(snap.Risk.ScoreLevel));
            var regColor = string.IsNullOrEmpty(snap.ClaudeExit.Ip) ? GrayColor : (snap.ClaudeSupported ? GreenColor : RedColor);
            SetBadge(RegionSupportBadge, RegionSupportText,
                string.IsNullOrEmpty(snap.ClaudeExit.Ip) ? "离线" : (snap.ClaudeSupported ? "支持地区" : "不支持地区"),
                regColor);

            ExitIpText.Text = string.IsNullOrEmpty(snap.ClaudeExit.Ip)
                ? "-"
                : (string.IsNullOrEmpty(snap.ClaudeExit.CountryCode) ? snap.ClaudeExit.Ip : "[" + snap.ClaudeExit.CountryCode + "] " + snap.ClaudeExit.Ip);

            if (snap.ClaudeExit.LatencyMs > 0)
            {
                LatencyBadge.Visibility = Visibility.Visible;
                LatencyText.Text = snap.ClaudeExit.LatencyMs + "ms";
            }
            else
            {
                LatencyBadge.Visibility = Visibility.Collapsed;
            }

            var loc = string.IsNullOrEmpty(snap.ClaudeExit.City)
                ? (string.IsNullOrEmpty(snap.ClaudeExit.Country) ? (string.IsNullOrEmpty(snap.ClaudeExit.CountryCode) ? "-" : snap.ClaudeExit.CountryCode) : snap.ClaudeExit.Country)
                : snap.ClaudeExit.Country + " · " + snap.ClaudeExit.City;
            LocationText.Text = loc;

            if (!string.IsNullOrEmpty(snap.TimezoneCheck.Label))
            {
                TzBadge.Visibility = Visibility.Visible;
                var diff = Math.Abs(snap.TimezoneCheck.HourDiff ?? 0);
                var tzCol = diff <= 2 ? GreenColor : (diff <= 6 ? BlueColor : OrangeColor);
                SetBadge(TzBadge, TzText, snap.TimezoneCheck.Label, tzCol);
            }
            else
            {
                TzBadge.Visibility = Visibility.Collapsed;
            }

            SetBadge(IpTypeBadge, IpTypeText, snap.ClaudeExit.IpTypeLabel, IpTypeColor(snap.ClaudeExit.IpType));
            if (snap.Risk.RiskFlags.Count == 0)
            {
                SetBadge(FlagsBadge, FlagsText, "无匿名标记", GreenColor);
            }
            else
            {
                var flagsStr = string.Join(" / ", snap.Risk.RiskFlags);
                var flagCol = (snap.Risk.IsTor || snap.Risk.IsVPN || snap.Risk.IsProxy) ? RedColor : OrangeColor;
                SetBadge(FlagsBadge, FlagsText, flagsStr, flagCol);
            }

            var ispStr = string.IsNullOrEmpty(snap.ClaudeExit.Asn)
                ? (string.IsNullOrEmpty(snap.ClaudeExit.Isp) ? "-" : snap.ClaudeExit.Isp)
                : snap.ClaudeExit.Asn + (string.IsNullOrEmpty(snap.ClaudeExit.Isp) ? "" : " · " + snap.ClaudeExit.Isp);
            IspText.Text = ispStr;
            IspText.ToolTip = string.IsNullOrEmpty(snap.Risk.Rdns) ? ispStr : (ispStr + "\r\nrDNS: " + snap.Risk.Rdns);

            var stabCol = StateColor(snap.Stability.Status);
            StabilityDot.Fill = new SolidColorBrush(stabCol);
            StabilityText.Text = snap.Stability.Label;
            StabilityText.Foreground = new SolidColorBrush(snap.Stability.Status == CheckState.Safe ? GrayColor : stabCol);

            // 5. Proxy Node & Direct Card
            if (snap.Clash.Running)
            {
                var modeLabel = snap.Clash.Mode.ToUpperInvariant() + (snap.Clash.TunEnabled ? " · TUN" : "");
                SetBadge(ClashModeBadge, ClashModeText, modeLabel, BlueColor);
                ClashNodeText.Text = string.IsNullOrEmpty(snap.Clash.ActiveNode) ? "-" : snap.Clash.ActiveNode;
                ClashNodeText.Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0xE9, 0xEF));
                ClashNodeText.ToolTip = snap.Clash.NodeChain;
            }
            else
            {
                SetBadge(ClashModeBadge, ClashModeText, "系统代理 / 通用模式", GrayColor);
                ClashNodeText.Text = "未连接 Clash API（通用检测生效）";
                ClashNodeText.Foreground = new SolidColorBrush(GrayColor);
            }

            DirectText.Text = string.IsNullOrEmpty(snap.DirectExit.Ip)
                ? "-"
                : snap.DirectExit.Ip + (string.IsNullOrEmpty(snap.DirectExit.Location) ? "" : " · " + snap.DirectExit.Location);

            UpdateLastRefreshText();
        }

        private void UpdateLastRefreshText()
        {
            if (_monitor.IsChecking)
            {
                LastRefreshText.Text = "正在刷新...";
                LastRefreshText.Foreground = new SolidColorBrush(BlueColor);
                return;
            }
            LastRefreshText.Foreground = new SolidColorBrush(Color.FromRgb(0xE6, 0xE9, 0xEF));
            var elapsed = Math.Max(0, (int)(DateTime.Now - _current.UpdatedAt).TotalSeconds);
            string rel;
            if (elapsed < 5) rel = "刚刚";
            else if (elapsed < 60) rel = elapsed + "秒前";
            else if (elapsed < 3600) rel = (elapsed / 60) + "分钟前";
            else rel = (elapsed / 3600) + "小时前";
            LastRefreshText.Text = string.Format("{0:HH:mm:ss}（{1}）", _current.UpdatedAt, rel);
        }

        public void ShowToast(string message)
        {
            ToastText.Text = message;
            ToastBorder.Visibility = Visibility.Visible;
            _toastTimer.Stop();
            _toastTimer.Start();
        }

        private void CopyWithToast(string text, string label)
        {
            if (string.IsNullOrEmpty(text)) return;
            try
            {
                Clipboard.SetText(text);
                ShowToast("已复制 " + label);
            }
            catch { }
        }

        // MARK: - Event Handlers
        private void RootBorder_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ButtonState == MouseButtonState.Pressed)
            {
                try { DragMove(); } catch { }
            }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e)
        {
            var _ = _monitor.TriggerCheckAsync("手动刷新");
        }

        private void PinBtn_Click(object sender, RoutedEventArgs e)
        {
            TogglePin();
        }

        private void CopyPromptBtn_Click(object sender, RoutedEventArgs e)
        {
            var prompt = FixPromptGenerator.Generate(_current);
            CopyWithToast(prompt, "AI 修复 Prompt，直接粘贴给 AI 即可");
        }

        private void DnsTile_Click(object sender, MouseButtonEventArgs e)
        {
            if (!string.IsNullOrEmpty(_current.Dns.Ip))
                CopyWithToast(_current.Dns.Ip, "DNS IP");
        }

        private void ExitIpText_Click(object sender, MouseButtonEventArgs e)
        {
            if (!string.IsNullOrEmpty(_current.ClaudeExit.Ip))
                CopyWithToast(_current.ClaudeExit.Ip, "Claude 出口 IP");
        }

        private void ApiLink_Click(object sender, MouseButtonEventArgs e)
        {
            CopyWithToast("http://127.0.0.1:17899/api/status", "本地 API 地址");
        }

        private void SettingsBtn_Click(object sender, RoutedEventArgs e)
        {
            var menu = new ContextMenu();

            var intervalHeader = new MenuItem { Header = "自动刷新频率" };
            var intervals = new[]
            {
                new Tuple<string, int>("仅节点/网络变化时", 0),
                new Tuple<string, int>("每 1 分钟", 60),
                new Tuple<string, int>("每 5 分钟（推荐）", 300),
                new Tuple<string, int>("每 10 分钟", 600)
            };
            foreach (var item in intervals)
            {
                var mi = new MenuItem
                {
                    Header = item.Item1,
                    IsCheckable = true,
                    IsChecked = _monitor.RefreshIntervalSeconds == item.Item2
                };
                int sec = item.Item2;
                mi.Click += (s2, e2) =>
                {
                    _monitor.SetRefreshInterval(sec);
                    ShowToast("已更新自动刷新频率");
                };
                intervalHeader.Items.Add(mi);
            }
            menu.Items.Add(intervalHeader);
            menu.Items.Add(new Separator());

            var autoStart = new MenuItem
            {
                Header = "开机自动启动",
                IsCheckable = true,
                IsChecked = _monitor.IsLaunchAtLoginEnabled()
            };
            autoStart.Click += (s2, e2) =>
            {
                _monitor.SetLaunchAtLogin(autoStart.IsChecked);
                ShowToast(autoStart.IsChecked ? "已开启开机自启" : "已关闭开机自启");
            };
            menu.Items.Add(autoStart);

            var alerts = new MenuItem
            {
                Header = "高危风险时发送系统通知",
                IsCheckable = true,
                IsChecked = _monitor.AlertsEnabled
            };
            alerts.Click += (s2, e2) => _monitor.SetAlertsEnabled(alerts.IsChecked);
            menu.Items.Add(alerts);

            var topMost = new MenuItem
            {
                Header = "桌面悬浮窗始终置顶",
                IsCheckable = true,
                IsChecked = _monitor.AlwaysOnTop
            };
            topMost.Click += (s2, e2) =>
            {
                _monitor.SetAlwaysOnTop(topMost.IsChecked);
                if (_isPinned) Topmost = topMost.IsChecked;
            };
            menu.Items.Add(topMost);

            menu.Items.Add(new Separator());

            var copyPrompt = new MenuItem { Header = "复制 AI 诊断修复 Prompt" };
            copyPrompt.Click += (s2, e2) => CopyWithToast(FixPromptGenerator.Generate(_current), "AI 修复 Prompt");
            menu.Items.Add(copyPrompt);

            var copyJson = new MenuItem { Header = "复制完整 JSON 报告" };
            copyJson.Click += (s2, e2) => CopyWithToast(JsonHelper.SerializeSnapshot(_current), "JSON 报告");
            menu.Items.Add(copyJson);

            var openWeb = new MenuItem { Header = "在浏览器打开 ip.net.coffee" };
            openWeb.Click += (s2, e2) =>
            {
                try { Process.Start(new ProcessStartInfo("https://ip.net.coffee/claude/") { UseShellExecute = true }); } catch { }
            };
            menu.Items.Add(openWeb);

            menu.Items.Add(new Separator());

            var quit = new MenuItem { Header = "退出 ClaudeIPGuard" };
            quit.Click += (s2, e2) => ((App)Application.Current).ExitApplication();
            menu.Items.Add(quit);

            menu.PlacementTarget = SettingsBtn;
            menu.IsOpen = true;
        }

        // MARK: - Style Helpers
        private static void SetBadge(Border border, TextBlock text, string label, Color color)
        {
            text.Text = label;
            text.Foreground = new SolidColorBrush(color);
            border.Background = new SolidColorBrush(WithAlpha(color, 36));
        }

        private static void StyleTile(Border tile, System.Windows.Shapes.Ellipse dot, TextBlock valueText, Color color)
        {
            dot.Fill = new SolidColorBrush(color);
            tile.Background = new SolidColorBrush(WithAlpha(color, 20));
            tile.BorderBrush = new SolidColorBrush(WithAlpha(color, 64));
            valueText.Foreground = new SolidColorBrush(color == GreenColor ? Color.FromRgb(0xF3, 0xF5, 0xF8) : color);
        }

        private static Color WithAlpha(Color c, byte alpha)
        {
            return Color.FromArgb(alpha, c.R, c.G, c.B);
        }

        private static Color LevelColor(OverallLevel level)
        {
            switch (level)
            {
                case OverallLevel.Safe: return GreenColor;
                case OverallLevel.Warning: return OrangeColor;
                case OverallLevel.Danger: return RedColor;
                default: return BlueColor;
            }
        }

        private static Color StateColor(CheckState state)
        {
            switch (state)
            {
                case CheckState.Safe: return GreenColor;
                case CheckState.Warning: return OrangeColor;
                case CheckState.Danger: return RedColor;
                default: return GrayColor;
            }
        }

        private static Color DnsColor(DNSLeakStatus status)
        {
            switch (status)
            {
                case DNSLeakStatus.Safe: return GreenColor;
                case DNSLeakStatus.Leaked: return RedColor;
                default: return OrangeColor;
            }
        }

        private static Color IpTypeColor(IPTypeCategory type)
        {
            switch (type)
            {
                case IPTypeCategory.Residential: return GreenColor;
                case IPTypeCategory.Mobile: return Color.FromRgb(0x10, 0xB9, 0x81);
                case IPTypeCategory.Datacenter: return OrangeColor;
                case IPTypeCategory.Proxy: return RedColor;
                default: return GrayColor;
            }
        }
    }
}
