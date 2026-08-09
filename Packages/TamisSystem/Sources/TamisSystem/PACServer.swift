import Foundation
import Network

/// Serves the proxy auto-configuration file, and outlives the application.
///
/// macOS keeps asking for the auto-configuration URL for as long as the setting is in
/// place — including after Tamis quits, crashes, or is deleted. Something has to answer,
/// and what it answers when the proxy is gone decides whether closing the application
/// leaves a working Mac or a Mac that cannot browse.
///
/// So the file is not simply read from disk and returned. Before serving it, the helper
/// checks that the proxy is actually accepting connections; if it is not, it serves
/// `DIRECT` for everything. A stale script pointing at a closed port is the one outcome
/// worth engineering against.
///
/// Loopback only. A PAC reachable from the network tells anyone who asks which hosts
/// this machine treats as sensitive.
public final class PACServer: @unchecked Sendable {

    public enum Failure: Error, Sendable, Equatable {
        case cannotListen(String)
    }

    private let pacURL: URL
    private let proxyPort: UInt16
    private let queue = DispatchQueue(label: "io.github.black0s.tamis.pac")
    private var listener: NWListener?

    public private(set) var boundPort: UInt16?

    public init(pacURL: URL, proxyPort: UInt16) {
        self.pacURL = pacURL
        self.proxyPort = proxyPort
    }

    public func start(port: UInt16) throws {
        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .loopback
        parameters.allowLocalEndpointReuse = true

        guard let endpointPort = NWEndpoint.Port(rawValue: port),
              let listener = try? NWListener(using: parameters, on: endpointPort)
        else { throw Failure.cannotListen("port \(port)") }

        listener.newConnectionHandler = { [weak self] connection in
            self?.serve(connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.boundPort = listener.port?.rawValue }
        }
        listener.start(queue: queue)
        self.listener = listener

        // The port is needed by the caller — the system proxy setting points at it —
        // so a short wait here is worth more than an asynchronous surprise later.
        let deadline = Date().addingTimeInterval(2)
        while boundPort == nil, Date() < deadline { usleep(5_000) }
        guard boundPort != nil else { throw Failure.cannotListen("délai dépassé") }
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        boundPort = nil
    }

    // MARK: Serving

    private func serve(_ connection: NWConnection) {
        connection.start(queue: queue)
        // The request is read and discarded: there is exactly one resource here, and
        // parsing a request in order to ignore it would only add a way to be wrong.
        connection.receive(minimumIncompleteLength: 1, maximumLength: 4_096) { [weak self] _, _, _, _ in
            guard let self else { connection.cancel(); return }
            let body = self.currentScript()
            let response = """
            HTTP/1.1 200 OK\r
            Content-Type: application/x-ns-proxy-autoconfig\r
            Content-Length: \(body.utf8.count)\r
            Cache-Control: no-store\r
            Connection: close\r
            \r
            \(body)
            """
            connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in
                connection.cancel()
            })
        }
    }

    /// What to serve right now.
    ///
    /// The proxy is probed rather than assumed. `Cache-Control: no-store` above is the
    /// other half of that: a cached script would keep pointing at a dead port for as
    /// long as the system felt like remembering it.
    func currentScript() -> String {
        guard isProxyAnswering(),
              let script = try? String(contentsOf: pacURL, encoding: .utf8),
              !script.isEmpty
        else { return ProxyAutoConfig.failOpen }
        return script
    }

    /// Whether anything is accepting connections on the proxy port.
    ///
    /// A plain connect, with a short timeout: the question is only whether the socket
    /// is open, and speaking HTTP to find out would take longer and answer the same.
    func isProxyAnswering(timeout: TimeInterval = 0.25) -> Bool {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }

        var timeoutValue = timeval(
            tv_sec: Int(timeout), tv_usec: Int32((timeout - floor(timeout)) * 1_000_000)
        )
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeoutValue,
                   socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = proxyPort.bigEndian

        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}
