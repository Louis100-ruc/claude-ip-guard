import Foundation
import Network

final class LocalHTTPServer {
    let port: UInt16
    private var listener: NWListener?
    private let queue = DispatchQueue(label: "com.claudeipguard.http", qos: .utility)
    private let getSnapshot: () -> DetectionSnapshot
    private let triggerRefresh: (@escaping (DetectionSnapshot) -> Void) -> Void

    init(
        port: UInt16 = 17899,
        getSnapshot: @escaping () -> DetectionSnapshot,
        triggerRefresh: @escaping (@escaping (DetectionSnapshot) -> Void) -> Void
    ) {
        self.port = port
        self.getSnapshot = getSnapshot
        self.triggerRefresh = triggerRefresh
    }

    func start() {
        do {
            let params = NWParameters.tcp
            params.requiredLocalEndpoint = NWEndpoint.hostPort(
                host: NWEndpoint.Host("127.0.0.1"),
                port: NWEndpoint.Port(rawValue: port)!
            )
            let listener = try NWListener(using: params)
            listener.newConnectionHandler = { [weak self] conn in
                self?.handleConnection(conn)
            }
            listener.start(queue: queue)
            self.listener = listener
        } catch {
            NSLog("[ClaudeIPGuard] Failed to start HTTP server on 127.0.0.1:\(port): \(error)")
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }

    private func handleConnection(_ conn: NWConnection) {
        conn.start(queue: queue)
        conn.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, _, _ in
            guard let self = self,
                  let data = data,
                  let reqText = String(data: data, encoding: .utf8) else {
                conn.cancel()
                return
            }

            let firstLine = reqText.split(separator: "\r\n", maxSplits: 1).first ?? ""
            let parts = firstLine.split(separator: " ")
            let method = parts.count > 0 ? String(parts[0]) : "GET"
            let rawPath = parts.count > 1 ? String(parts[1]) : "/"
            let path = rawPath.split(separator: "?").first.map(String.init) ?? "/"

            if method == "OPTIONS" {
                self.sendResponse(conn: conn, status: "204 No Content", body: Data())
                return
            }

            switch path {
            case "/", "/status", "/api/status":
                let snap = self.getSnapshot()
                self.sendJSON(conn: conn, snapshot: snap)

            case "/refresh", "/api/refresh":
                self.triggerRefresh { updated in
                    self.sendJSON(conn: conn, snapshot: updated)
                }

            case "/fix-prompt", "/api/fix-prompt":
                let snap = self.getSnapshot()
                let prompt = FixPromptGenerator.generate(from: snap)
                if rawPath.contains("format=json") {
                    let obj: [String: Any] = [
                        "overallLevel": snap.overallLevel.rawValue,
                        "overallSummary": snap.overallSummary,
                        "prompt": prompt
                    ]
                    let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]))
                        ?? Data("{}".utf8)
                    self.sendResponse(conn: conn, status: "200 OK", contentType: "application/json; charset=utf-8", body: data)
                } else {
                    self.sendResponse(conn: conn, status: "200 OK", contentType: "text/plain; charset=utf-8", body: Data(prompt.utf8))
                }

            case "/health":
                let payload = Data("{\"ok\":true,\"service\":\"ClaudeIPGuard\"}\n".utf8)
                self.sendResponse(conn: conn, status: "200 OK", body: payload)

            default:
                let payload = Data("{\"error\":\"Not Found\",\"endpoints\":[\"/api/status\",\"/api/refresh\",\"/api/fix-prompt\",\"/health\"]}\n".utf8)
                self.sendResponse(conn: conn, status: "404 Not Found", body: payload)
            }
        }
    }

    private func sendJSON(conn: NWConnection, snapshot: DetectionSnapshot) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = (try? encoder.encode(snapshot)) ?? Data("{\"error\":\"encode_failed\"}".utf8)
        sendResponse(conn: conn, status: "200 OK", body: data)
    }

    private func sendResponse(conn: NWConnection, status: String, contentType: String = "application/json; charset=utf-8", body: Data) {
        let header = """
        HTTP/1.1 \(status)\r
        Content-Type: \(contentType)\r
        Content-Length: \(body.count)\r
        Access-Control-Allow-Origin: *\r
        Access-Control-Allow-Methods: GET, POST, OPTIONS\r
        Cache-Control: no-store\r
        Connection: close\r
        \r\n
        """
        var response = Data(header.utf8)
        response.append(body)
        conn.send(content: response, completion: .contentProcessed { _ in
            conn.cancel()
        })
    }
}
