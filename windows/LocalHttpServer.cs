using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ClaudeIPGuard
{
    public class LocalHttpServer
    {
        private readonly int _port;
        private readonly Func<DetectionSnapshot> _getSnapshot;
        private readonly Func<Task<DetectionSnapshot>> _triggerRefresh;
        private TcpListener _listener;
        private CancellationTokenSource _cts;

        public LocalHttpServer(
            int port,
            Func<DetectionSnapshot> getSnapshot,
            Func<Task<DetectionSnapshot>> triggerRefresh)
        {
            _port = port;
            _getSnapshot = getSnapshot;
            _triggerRefresh = triggerRefresh;
        }

        public void Start()
        {
            try
            {
                _cts = new CancellationTokenSource();
                _listener = new TcpListener(IPAddress.Loopback, _port);
                _listener.Start();
                Task.Run(() => AcceptLoopAsync(_cts.Token));
            }
            catch { }
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = null;
                try
                {
                    client = await _listener.AcceptTcpClientAsync();
                }
                catch
                {
                    if (ct.IsCancellationRequested) break;
                    continue;
                }
                var accepted = client;
                var _ = Task.Run(() => HandleClientAsync(accepted));
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    client.ReceiveTimeout = 3000;
                    client.SendTimeout = 5000;
                    using (var stream = client.GetStream())
                    {
                        var buf = new byte[8192];
                        int n = await stream.ReadAsync(buf, 0, buf.Length);
                        if (n <= 0) return;

                        var reqText = Encoding.UTF8.GetString(buf, 0, n);
                        var firstLineEnd = reqText.IndexOf("\r\n", StringComparison.Ordinal);
                        var firstLine = firstLineEnd > 0 ? reqText.Substring(0, firstLineEnd) : reqText;
                        var parts = firstLine.Split(' ');
                        var method = parts.Length > 0 ? parts[0] : "GET";
                        var rawPath = parts.Length > 1 ? parts[1] : "/";
                        var qIdx = rawPath.IndexOf('?');
                        var path = qIdx >= 0 ? rawPath.Substring(0, qIdx) : rawPath;

                        if (method == "OPTIONS")
                        {
                            await SendAsync(stream, "204 No Content", "text/plain; charset=utf-8", new byte[0]);
                            return;
                        }

                        switch (path)
                        {
                            case "/":
                            case "/status":
                            case "/api/status":
                                {
                                    var json = JsonHelper.SerializeSnapshot(_getSnapshot());
                                    await SendAsync(stream, "200 OK", "application/json; charset=utf-8", Encoding.UTF8.GetBytes(json));
                                    break;
                                }
                            case "/refresh":
                            case "/api/refresh":
                                {
                                    var updated = await _triggerRefresh();
                                    var json = JsonHelper.SerializeSnapshot(updated);
                                    await SendAsync(stream, "200 OK", "application/json; charset=utf-8", Encoding.UTF8.GetBytes(json));
                                    break;
                                }
                            case "/fix-prompt":
                            case "/api/fix-prompt":
                                {
                                    var snap = _getSnapshot();
                                    var prompt = FixPromptGenerator.Generate(snap);
                                    if (rawPath.IndexOf("format=json", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        var obj = new Dictionary<string, object>
                                        {
                                            ["overallLevel"] = snap.OverallLevel.ToString().ToLowerInvariant(),
                                            ["overallSummary"] = snap.OverallSummary,
                                            ["prompt"] = prompt
                                        };
                                        var json = JsonHelper.SerializePretty(obj);
                                        await SendAsync(stream, "200 OK", "application/json; charset=utf-8", Encoding.UTF8.GetBytes(json));
                                    }
                                    else
                                    {
                                        await SendAsync(stream, "200 OK", "text/plain; charset=utf-8", Encoding.UTF8.GetBytes(prompt));
                                    }
                                    break;
                                }
                            case "/health":
                                {
                                    await SendAsync(stream, "200 OK", "application/json; charset=utf-8",
                                        Encoding.UTF8.GetBytes("{\"ok\":true,\"service\":\"ClaudeIPGuard\",\"platform\":\"windows\"}\r\n"));
                                    break;
                                }
                            default:
                                {
                                    await SendAsync(stream, "404 Not Found", "application/json; charset=utf-8",
                                        Encoding.UTF8.GetBytes("{\"error\":\"Not Found\",\"endpoints\":[\"/api/status\",\"/api/refresh\",\"/api/fix-prompt\",\"/health\"]}\r\n"));
                                    break;
                                }
                        }
                    }
                }
                catch { }
            }
        }

        private static async Task SendAsync(NetworkStream stream, string status, string contentType, byte[] body)
        {
            var header =
                "HTTP/1.1 " + status + "\r\n" +
                "Content-Type: " + contentType + "\r\n" +
                "Content-Length: " + body.Length + "\r\n" +
                "Access-Control-Allow-Origin: *\r\n" +
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n";

            var headerBytes = Encoding.UTF8.GetBytes(header);
            await stream.WriteAsync(headerBytes, 0, headerBytes.Length);
            if (body.Length > 0)
            {
                await stream.WriteAsync(body, 0, body.Length);
            }
            await stream.FlushAsync();
        }
    }
}
