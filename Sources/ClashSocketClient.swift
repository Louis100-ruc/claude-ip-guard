import Foundation
import Darwin

final class ClashSocketClient: @unchecked Sendable {
    private let socketPath = "/tmp/verge/verge-mihomo.sock"
    private let configPaths: [String]
    private let fallbackTCPPorts: [UInt16] = [9097, 9090, 29090]

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.configPaths = [
            "\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml",
            "\(home)/Library/Application Support/io.github.zzzgydi.clash-verge/clash-verge.yaml",
            "\(home)/Library/Application Support/mihomo-party/work/config.yaml",
            "\(home)/.config/clash/config.yaml"
        ]
    }

    private func readSecret() -> String {
        for path in configPaths {
            guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            for line in content.split(separator: "\n", maxSplits: 60, omittingEmptySubsequences: false) {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("secret:") {
                    let value = trimmed.dropFirst("secret:".count)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                        .trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
                    return value
                }
            }
        }
        return ""
    }

    private func httpGetUnixSocket(path: String, secret: String) -> Data? {
        guard FileManager.default.fileExists(atPath: socketPath) else { return nil }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 1, tv_usec: 500_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8CString)
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { cPtr in
                for i in 0..<pathBytes.count {
                    cPtr[i] = pathBytes[i]
                }
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else { return nil }

        return sendHTTPGet(fd: fd, path: path, secret: secret)
    }

    private func httpGetLocalTCP(port: UInt16, path: String, secret: String) -> Data? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr)

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connectResult == 0 else { return nil }

        return sendHTTPGet(fd: fd, path: path, secret: secret)
    }

    private func sendHTTPGet(fd: Int32, path: String, secret: String) -> Data? {
        var request = "GET \(path) HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n"
        if !secret.isEmpty {
            request += "Authorization: Bearer \(secret)\r\n"
        }
        request += "\r\n"

        let reqData = Data(request.utf8)
        let sent = reqData.withUnsafeBytes { rawBuf -> Int in
            guard let base = rawBuf.baseAddress else { return -1 }
            return send(fd, base, reqData.count, 0)
        }
        guard sent == reqData.count else { return nil }

        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n > 0 {
                response.append(buffer, count: n)
            } else {
                break
            }
        }

        guard let separatorRange = response.range(of: Data("\r\n\r\n".utf8)) else {
            return nil
        }
        return response.subdata(in: separatorRange.upperBound..<response.endIndex)
    }

    private func fetchJSON(path: String, secret: String, tcpPort: UInt16?) -> [String: Any]? {
        let data: Data?
        if let port = tcpPort {
            data = httpGetLocalTCP(port: port, path: path, secret: secret)
        } else {
            data = httpGetUnixSocket(path: path, secret: secret)
        }
        guard let d = data else { return nil }
        return try? JSONSerialization.jsonObject(with: d) as? [String: Any]
    }

    func fetchState() -> ClashState {
        let secret = readSecret()

        // 1. Prefer Clash Verge Rev Unix Socket
        var activePort: UInt16? = nil
        var configJSON = fetchJSON(path: "/configs", secret: secret, tcpPort: nil)

        // 2. Fallback to common local Clash / Mihomo HTTP controller ports
        if configJSON == nil {
            for port in fallbackTCPPorts {
                if let cfg = fetchJSON(path: "/configs", secret: secret, tcpPort: port) {
                    configJSON = cfg
                    activePort = port
                    break
                }
                if !secret.isEmpty, let cfg = fetchJSON(path: "/configs", secret: "", tcpPort: port) {
                    configJSON = cfg
                    activePort = port
                    break
                }
            }
        }

        guard let cfg = configJSON, cfg["mode"] != nil else {
            return ClashState(running: false)
        }

        var state = ClashState()
        state.running = true
        state.mode = (cfg["mode"] as? String) ?? "rule"
        if let tun = cfg["tun"] as? [String: Any] {
            state.tunEnabled = (tun["enable"] as? Bool) ?? false
        }

        guard let rootJSON = fetchJSON(path: "/proxies", secret: secret, tcpPort: activePort)
                ?? fetchJSON(path: "/proxies", secret: "", tcpPort: activePort),
              let proxies = rootJSON["proxies"] as? [String: [String: Any]] else {
            return state
        }

        let startGroup: String?
        if state.mode.lowercased() == "global" {
            startGroup = "GLOBAL"
        } else if state.mode.lowercased() == "direct" {
            state.activeGroup = "DIRECT"
            state.activeNode = "DIRECT"
            state.nodeChain = "DIRECT"
            return state
        } else {
            let preferred = ["Claude", "AI", "OpenAI", "ChatGPT", "Proxies", "Proxy", "节点选择", "PROXY", "MESL", "✈️Final", "Final", "🐟 漏网之鱼"]
            startGroup = preferred.first(where: { proxies[$0] != nil })
                ?? proxies.first(where: { k, v in
                    k != "GLOBAL" && ((v["type"] as? String) == "Selector")
                })?.key
        }

        guard let first = startGroup else { return state }
        state.activeGroup = first

        var chain: [String] = [first]
        var current = first
        var visited: Set<String> = [first]

        for _ in 0..<8 {
            guard let entry = proxies[current],
                  let next = entry["now"] as? String,
                  !next.isEmpty,
                  !visited.contains(next) else {
                break
            }
            visited.insert(next)
            chain.append(next)
            current = next
        }

        state.activeNode = chain.last ?? first
        state.nodeChain = chain.joined(separator: " → ")
        return state
    }
}
