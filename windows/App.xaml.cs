using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using Forms = System.Windows.Forms;

namespace ClaudeIPGuard
{
    public partial class App : Application
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        private Mutex _singleInstanceMutex;
        private MonitorService _monitor;
        private MainWindow _mainWindow;
        private Forms.NotifyIcon _trayIcon;
        private IntPtr _currentIconHandle = IntPtr.Zero;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            bool createdNew;
            _singleInstanceMutex = new Mutex(true, "Global\\ClaudeIPGuard_SingleInstance_Mutex", out createdNew);
            if (!createdNew)
            {
                Shutdown();
                return;
            }

            // Enable TLS 1.2 + TLS 1.3 on .NET Framework 4.8
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)12288;
            }
            catch
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            }

            _monitor = new MonitorService();
            _mainWindow = new MainWindow(_monitor);

            SetupTrayIcon();

            _monitor.SnapshotChanged += (snap, checking) =>
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    _mainWindow.RenderSnapshot(snap, checking);
                    UpdateTrayVisual(snap, checking);
                }));
            };

            _monitor.DangerAlertTriggered += (title, body) =>
            {
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        _trayIcon?.ShowBalloonTip(5000, title, body, Forms.ToolTipIcon.Error);
                    }
                    catch { }
                }));
            };

            _monitor.Start();
            UpdateTrayVisual(_monitor.CurrentSnapshot, true);

            // Show the panel briefly on first manual launch so user immediately sees it
            _mainWindow.PositionNearTray();
            _mainWindow.Show();
            _mainWindow.Activate();
        }

        private void SetupTrayIcon()
        {
            var menu = new Forms.ContextMenuStrip();
            menu.Items.Add("打开 / 隐藏检测面板", null, (s, e) => ToggleMainWindow());
            menu.Items.Add("立即重新检测", null, (s, e) => { var _ = _monitor.TriggerCheckAsync("手动刷新"); });
            menu.Items.Add("钉在桌面 / 取消固定", null, (s, e) =>
            {
                if (!_mainWindow.IsVisible)
                {
                    _mainWindow.PositionNearTray();
                    _mainWindow.Show();
                }
                _mainWindow.TogglePin();
            });
            menu.Items.Add("复制 AI 修复 Prompt", null, (s, e) =>
            {
                try
                {
                    Clipboard.SetText(FixPromptGenerator.Generate(_monitor.CurrentSnapshot));
                    _trayIcon?.ShowBalloonTip(2500, "ClaudeIPGuard", "已复制 AI 修复 Prompt，直接粘贴给 AI 即可", Forms.ToolTipIcon.Info);
                }
                catch { }
            });
            menu.Items.Add("复制本地 API 地址", null, (s, e) =>
            {
                try { Clipboard.SetText("http://127.0.0.1:17899/api/status"); } catch { }
            });
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add("退出 ClaudeIPGuard", null, (s, e) => ExitApplication());

            _trayIcon = new Forms.NotifyIcon
            {
                Visible = true,
                Text = "ClaudeIPGuard · 正在检测...",
                ContextMenuStrip = menu
            };

            _trayIcon.MouseUp += (s, e) =>
            {
                if (e.Button == Forms.MouseButtons.Left)
                {
                    ToggleMainWindow();
                }
            };
        }

        private void ToggleMainWindow()
        {
            if (_mainWindow.IsVisible)
            {
                if (!_mainWindow.IsPinned)
                {
                    _mainWindow.Hide();
                }
                else
                {
                    _mainWindow.Activate();
                }
            }
            else
            {
                if (!_mainWindow.IsPinned)
                {
                    _mainWindow.PositionNearTray();
                }
                _mainWindow.Show();
                _mainWindow.Activate();
            }
        }

        private void UpdateTrayVisual(DetectionSnapshot snap, bool isChecking)
        {
            if (_trayIcon == null) return;

            Color dotColor;
            if (isChecking && string.IsNullOrEmpty(snap.ClaudeExit.Ip))
                dotColor = Color.FromArgb(0x3B, 0x82, 0xF6);
            else if (snap.OverallLevel == OverallLevel.Safe)
                dotColor = Color.FromArgb(0x22, 0xC5, 0x5E);
            else if (snap.OverallLevel == OverallLevel.Warning)
                dotColor = Color.FromArgb(0xF5, 0x9E, 0x0B);
            else if (snap.OverallLevel == OverallLevel.Danger)
                dotColor = Color.FromArgb(0xEF, 0x44, 0x44);
            else
                dotColor = Color.FromArgb(0x3B, 0x82, 0xF6);

            SetTrayIconBitmap(dotColor);

            var code = string.IsNullOrEmpty(snap.ClaudeExit.CountryCode) ? "--" : snap.ClaudeExit.CountryCode;
            var tip = string.Format("ClaudeIPGuard | {0} · {1}", code, snap.OverallSummary);
            if (tip.Length > 63) tip = tip.Substring(0, 60) + "...";
            _trayIcon.Text = tip;
        }

        private void SetTrayIconBitmap(Color statusColor)
        {
            using (var bmp = new Bitmap(32, 32))
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);

                // Outer dark ring
                using (var bgBrush = new SolidBrush(Color.FromArgb(235, 22, 26, 33)))
                {
                    g.FillEllipse(bgBrush, 2, 2, 28, 28);
                }
                using (var borderPen = new Pen(Color.FromArgb(140, statusColor), 2.5f))
                {
                    g.DrawEllipse(borderPen, 3, 3, 26, 26);
                }
                // Inner status dot
                using (var dotBrush = new SolidBrush(statusColor))
                {
                    g.FillEllipse(dotBrush, 8, 8, 16, 16);
                }

                IntPtr newHandle = bmp.GetHicon();
                var icon = Icon.FromHandle(newHandle);
                _trayIcon.Icon = (Icon)icon.Clone();
                DestroyIcon(newHandle);
                if (_currentIconHandle != IntPtr.Zero)
                {
                    DestroyIcon(_currentIconHandle);
                    _currentIconHandle = IntPtr.Zero;
                }
            }
        }

        public void ExitApplication()
        {
            _monitor?.Stop();
            if (_trayIcon != null)
            {
                _trayIcon.Visible = false;
                _trayIcon.Dispose();
                _trayIcon = null;
            }
            try { _singleInstanceMutex?.ReleaseMutex(); } catch { }
            Shutdown();
        }
    }
}
