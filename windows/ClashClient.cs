using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.Sockets;
using System.Text;

namespace ClaudeIPGuard
{
    public class ClashClient
    {
        private readonly string[] _configPaths;
        private readonly int[] _fallbackPorts = new[] { 9097, 9090, 29090 };
        private readonly string[] _pipeNames = new[] { "verge-mihomo", "clash-verge-mihomo" };

        public ClashClient()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            _configPaths = new[]
            {
                Path.Combine(appData, "io.github.clash-verge-rev.clash-verge-rev", "clash-verge.yaml"),
                Path.Combine(appData, "io.github.zzzgydi.clash-verge", "clash-verge.yaml"),
                Path.Combine(appData, "mihomo-party", "work", "config.yaml"),
                Path.Combine(userProfile, ".config", "clash", "config.yaml")
            };
        }

        private string ReadSecret()
        {
            foreach (var path in _configPaths)
            {
                try
                {
                    if (!File.Exists(path)) continue;
                    using (var sr = new StreamReader(path, Encoding.UTF8))
                    {
                        for (int i = 0; i < 80; i++)
                        {
                            var line = sr.ReadLine();
                            if (line == null) break;
                            var trimmed = line.Trim();
                            if (trimmed.StartsWith("secret:"))
                            {
                                return trimmed.Substring("secret:".Length).Trim().Trim('\'', '"');
                            }
                        }
                    }
                }
                catch { }
            }
            return "";
        }

        private string HttpOverPipe(string pipeName, string path, string secret)
        {
            try
            {
                using (var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut))
                {
                    pipe.Connect(600);
                    return SendRawHttp(pipe, path, secret);
                }
            }
            catch
            {
                return null;
            }
        }

        private string HttpOverTcp(int port, string path, string secret)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var task = client.ConnectAsync("127.0.0.1", port);
                    if (!task.Wait(600) || !client.Connected) return null;
                    client.ReceiveTimeout = 1200;
                    client.SendTimeout = 1200;
                    using (var stream = client.GetStream())
                    {
                        return SendRawHttp(stream, path, secret);
                    }
                }
            }
            catch
            {
                return null;
            }
        }

        private string SendRawHttp(Stream stream, string path, string secret)
        {
            var sb = new StringBuilder();
            sb.AppendFormat("GET {0} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n", path);
            if (!string.IsNullOrEmpty(secret))
            {
                sb.AppendFormat("Authorization: Bearer {0}\r\n", secret);
            }
            sb.Append("\r\n");

            var reqBytes = Encoding.UTF8.GetBytes(sb.ToString());
            stream.Write(reqBytes, 0, reqBytes.Length);
            stream.Flush();

            using (var ms = new MemoryStream())
            {
                var buf = new byte[8192];
                int n;
                while ((n = stream.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, n);
                }
                var full = Encoding.UTF8.GetString(ms.ToArray());
                var idx = full.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                return idx >= 0 ? full.Substring(idx + 4) : null;
            }
        }

        private Dictionary<string, object> FetchJson(string path, string secret, string pipeName, int? tcpPort)
        {
            string body = null;
            if (!string.IsNullOrEmpty(pipeName))
                body = HttpOverPipe(pipeName, path, secret);
            else if (tcpPort.HasValue)
                body = HttpOverTcp(tcpPort.Value, path, secret);

            return JsonHelper.ParseObject(body);
        }

        public ClashState FetchState()
        {
            var secret = ReadSecret();
            string activePipe = null;
            int? activePort = null;
            Dictionary<string, object> cfg = null;

            foreach (var pipe in _pipeNames)
            {
                cfg = FetchJson("/configs", secret, pipe, null) ?? FetchJson("/configs", "", pipe, null);
                if (cfg != null && cfg.ContainsKey("mode"))
                {
                    activePipe = pipe;
                    break;
                }
            }

            if (cfg == null)
            {
                foreach (var port in _fallbackPorts)
                {
                    cfg = FetchJson("/configs", secret, null, port) ?? FetchJson("/configs", "", null, port);
                    if (cfg != null && cfg.ContainsKey("mode"))
                    {
                        activePort = port;
                        break;
                    }
                }
            }

            if (cfg == null || !cfg.ContainsKey("mode"))
                return new ClashState { Running = false };

            var state = new ClashState
            {
                Running = true,
                Mode = JsonHelper.GetString(cfg, "mode", "rule")
            };

            var tun = JsonHelper.GetDict(cfg, "tun");
            if (tun != null)
            {
                state.TunEnabled = JsonHelper.GetBool(tun, "enable", false);
            }

            var root = FetchJson("/proxies", secret, activePipe, activePort)
                       ?? FetchJson("/proxies", "", activePipe, activePort);
            var proxies = JsonHelper.GetDict(root, "proxies");
            if (proxies == null) return state;

            string startGroup = null;
            var lowerMode = state.Mode.ToLowerInvariant();
            if (lowerMode == "global")
            {
                startGroup = "GLOBAL";
            }
            else if (lowerMode == "direct")
            {
                state.ActiveGroup = "DIRECT";
                state.ActiveNode = "DIRECT";
                state.NodeChain = "DIRECT";
                return state;
            }
            else
            {
                var preferred = new[]
                {
                    "Claude", "AI", "OpenAI", "ChatGPT", "Proxies", "Proxy",
                    "节点选择", "PROXY", "✈️Final", "Final", "🐟 漏网之鱼"
                };
                startGroup = preferred.FirstOrDefault(p => proxies.ContainsKey(p));
                if (startGroup == null)
                {
                    foreach (var kv in proxies)
                    {
                        if (kv.Key == "GLOBAL") continue;
                        var entry = kv.Value as Dictionary<string, object>;
                        if (JsonHelper.GetString(entry, "type") == "Selector")
                        {
                            startGroup = kv.Key;
                            break;
                        }
                    }
                }
            }

            if (string.IsNullOrEmpty(startGroup)) return state;
            state.ActiveGroup = startGroup;

            var chain = new List<string> { startGroup };
            var visited = new HashSet<string> { startGroup };
            var current = startGroup;

            for (int i = 0; i < 8; i++)
            {
                if (!proxies.ContainsKey(current)) break;
                var entry = proxies[current] as Dictionary<string, object>;
                var next = JsonHelper.GetString(entry, "now");
                if (string.IsNullOrEmpty(next) || visited.Contains(next)) break;
                visited.Add(next);
                chain.Add(next);
                current = next;
            }

            state.ActiveNode = chain[chain.Count - 1];
            state.NodeChain = string.Join(" → ", chain);
            return state;
        }
    }
}
