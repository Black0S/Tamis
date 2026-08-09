import Foundation
import Darwin
import Testing
@testable import TamisDNS

/// A throwaway UDP client, so the server is exercised through a real socket rather
/// than by calling its handler directly.
private struct UDPClient {
    let fd: Int32

    init(timeout: TimeInterval = 2) {
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    }

    func exchange(_ datagram: [UInt8], port: UInt16) -> [UInt8]? {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }

        let sent = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                datagram.withUnsafeBufferPointer { buffer in
                    sendto(fd, buffer.baseAddress, buffer.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: 4096)
        let received = recv(fd, &buffer, buffer.count, 0)
        guard received > 0 else { return nil }
        return Array(buffer[0..<received])
    }

    func close() { Darwin.close(fd) }
}

private func query(_ name: String, type: UInt16 = 1, id: UInt16 = 0x7777) -> [UInt8] {
    DNSHeader(id: id, flags: 0x0100, questionCount: 1).bytes
        + DNSName.encode(name)
        + [UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01]
}

@Suite("DNS server", .serialized)
struct DNSServerTests {

    /// Starts a server on a kernel-chosen port. No privileges, nothing installed —
    /// the same code path that will later receive its socket from launchd.
    private func makeServer(
        blocking domains: [String] = [],
        cache: DNSCache = DNSCache()
    ) async throws -> (server: DNSServer, port: UInt16) {
        let socket = try DNSSocket.bind(host: "127.0.0.1", port: 0)
        let port = try #require(socket.boundPort())
        let policy = ResolverPolicy(blocklist: DomainBlocklist(blocking: domains))
        let server = DNSServer(socket: socket, policy: policy, cache: cache)
        await server.start()
        return (server, port)
    }

    @Test("a blocked name is refused with NXDOMAIN, keeping the query's ID")
    func blockedQuery() async throws {
        let (server, port) = try await makeServer(blocking: ["doubleclick.net"])
        defer { Task { await server.stop() } }

        let client = UDPClient()
        defer { client.close() }

        let reply = try #require(client.exchange(query("ads.doubleclick.net", id: 0x1234), port: port))
        let header = try DNSHeader(bytes: reply)
        #expect(header.id == 0x1234)
        #expect(header.isResponse)
        #expect(header.flags & 0x000F == UInt16(DNSResponseCode.nameError.rawValue))
        #expect(header.answerCount == 0)
        #expect(await server.statistics.blocked == 1)
    }

    @Test("the Firefox canary is refused so Firefox drops its own DoH")
    func canary() async throws {
        let (server, port) = try await makeServer()
        defer { Task { await server.stop() } }

        let client = UDPClient()
        defer { client.close() }

        let reply = try #require(client.exchange(query("use-application-dns.net"), port: port))
        #expect(try DNSHeader(bytes: reply).flags & 0x000F == UInt16(DNSResponseCode.nameError.rawValue))
    }

    /// The full pipeline without touching the network: the cache is primed, so a hit
    /// proves policy, lookup and the socket path all line up.
    @Test("a cached answer is served without going upstream")
    func cacheHit() async throws {
        let cache = DNSCache()
        let primed = try DNSQuery(datagram: query("example.com", id: 0x0001))
        var response = DNSHeader(
            id: 0x0001, flags: 0x8180, questionCount: 1, answerCount: 1
        ).bytes
        response += DNSName.encode("example.com") + [0x00, 0x01, 0x00, 0x01]
        response += DNSName.encode("example.com")
            + [0x00, 0x01, 0x00, 0x01]          // type A, class IN
            + [0x00, 0x00, 0x01, 0x2C]          // TTL 300
            + [0x00, 0x04, 93, 184, 216, 34]    // RDLENGTH 4 + address
        #expect(await cache.store(query: primed, response: response))

        let (server, port) = try await makeServer(cache: cache)
        defer { Task { await server.stop() } }

        let client = UDPClient()
        defer { client.close() }

        let reply = try #require(client.exchange(query("example.com", id: 0x99AA), port: port))
        let header = try DNSHeader(bytes: reply)
        #expect(header.id == 0x99AA)       // rewritten from the cached 0x0001
        #expect(header.answerCount == 1)
        #expect(await server.statistics.cacheHits == 1)
        #expect(await server.statistics.upstreamFailures == 0)
    }

    /// Replying to an unparsable datagram is how DNS reflection attacks are fed, and
    /// there is no ID to answer with anyway.
    @Test("a malformed datagram gets no reply at all")
    func malformed() async throws {
        let (server, port) = try await makeServer()
        defer { Task { await server.stop() } }

        let client = UDPClient(timeout: 1)
        defer { client.close() }

        #expect(client.exchange([0x00, 0x01, 0x02], port: port) == nil)
        #expect(await server.statistics.malformed == 1)
    }

    @Test("decisions are reported so the app can build its history")
    func decisionHandler() async throws {
        let socket = try DNSSocket.bind(host: "127.0.0.1", port: 0)
        let port = try #require(socket.boundPort())
        let policy = ResolverPolicy(blocklist: DomainBlocklist(blocking: ["tracker.example"]))
        let server = DNSServer(socket: socket, policy: policy)

        let recorded = Recorder()
        await server.setDecisionHandler { name, outcome in
            Task { await recorded.add(name, outcome) }
        }
        await server.start()
        defer { Task { await server.stop() } }

        let client = UDPClient()
        defer { client.close() }
        _ = client.exchange(query("ads.tracker.example"), port: port)

        try await Task.sleep(for: .milliseconds(200))
        let entries = await recorded.entries
        #expect(entries.first?.0 == "ads.tracker.example")
        if case .block(.blocklist) = entries.first?.1 {} else {
            Issue.record("expected a blocklist decision, got \(String(describing: entries.first?.1))")
        }
    }
}

private actor Recorder {
    var entries: [(String, ResolverPolicy.Outcome)] = []
    func add(_ name: String, _ outcome: ResolverPolicy.Outcome) {
        entries.append((name, outcome))
    }
}

@Suite("Socket activation")
struct SocketActivationTests {

    /// Outside launchd there is no socket to adopt, and the failure must be a clear
    /// error rather than a crash — the daemon reports it and exits.
    @Test("activation reports a clear error when not running under launchd")
    func notUnderLaunchd() {
        #expect(throws: SocketError.self) {
            _ = try SocketActivation.socket(named: "DNS")
        }
    }

    @Test("a self-bound socket reports the port the kernel chose")
    func ephemeralPort() throws {
        let socket = try DNSSocket.bind(host: "127.0.0.1", port: 0)
        defer { socket.close() }
        let port = try #require(socket.boundPort())
        #expect(port > 0)
        #expect(socket.source == .bound(host: "127.0.0.1", port: 0))
    }
}
