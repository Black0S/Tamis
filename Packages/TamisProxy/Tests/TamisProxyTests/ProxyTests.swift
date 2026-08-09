import Foundation
import Testing
import NIOCore
import NIOPosix
import NIOConcurrencyHelpers
@testable import TamisProxy

@Suite("CONNECT target parsing")
struct ConnectTargetTests {

    @Test("well-formed targets", arguments: [
        ("example.com:443", "example.com", 443),
        ("127.0.0.1:8080", "127.0.0.1", 8080),
        // An IPv6 literal is bracketed, and the last colon is the port separator.
        ("[2606:4700:4700::1111]:443", "2606:4700:4700::1111", 443),
    ])
    func valid(uri: String, host: String, port: Int) {
        let parsed = ConnectHandler.parseTarget(uri)
        #expect(parsed?.host == host)
        #expect(parsed?.port == port)
    }

    @Test("malformed targets are refused rather than guessed at", arguments: [
        "example.com", ":443", "example.com:", "example.com:0",
        "example.com:70000", "example.com:https", "",
    ])
    func invalid(uri: String) {
        #expect(ConnectHandler.parseTarget(uri) == nil)
    }
}

@Suite("Interception policy")
struct InterceptionPolicyTests {

    @Test("by default a connection is intercepted")
    func defaultIsIntercept() {
        let policy = InterceptionPolicy()
        #expect(policy.decision(forHost: "example.com") == .intercept)
    }

    /// Bank and password-manager domains are never decrypted. Getting this wrong is
    /// not a filtering miss — it is a breach of the promise made at onboarding.
    @Test("an excluded domain is tunnelled, subdomains included")
    func exclusionsWin() {
        let policy = InterceptionPolicy(exclusions: ["bnpparibas.net"])
        #expect(policy.decision(forHost: "bnpparibas.net") == .tunnel(reason: .httpsExclusion(matched: "bnpparibas.net")))
        #expect(policy.decision(forHost: "mabanque.bnpparibas.net") == .tunnel(reason: .httpsExclusion(matched: "bnpparibas.net")))
        // A domain that merely ends with the same letters is a different site.
        #expect(policy.decision(forHost: "notbnpparibas.net") == .intercept)
    }

    @Test("an excluded application is tunnelled whatever the host")
    func excludedApps() {
        let policy = InterceptionPolicy(excludedApps: ["org.whispersystems.signal"])
        #expect(policy.decision(forHost: "example.com", bundleID: "org.whispersystems.signal")
                == .tunnel(reason: .excludedApp(bundleID: "org.whispersystems.signal")))
        #expect(policy.decision(forHost: "example.com", bundleID: "com.apple.Safari") == .intercept)
    }

    @Test("a target that refused our certificate is remembered")
    func learnedPassthrough() {
        var policy = InterceptionPolicy()
        #expect(policy.decision(forHost: "pinned.example") == .intercept)
        policy.learnPassthrough(host: "pinned.example")
        #expect(policy.decision(forHost: "pinned.example") == .tunnel(reason: .certificatePinning))
    }

    /// Pausing must make Tamis transparent, not merely inert: every connection has to
    /// keep working exactly as if it were not installed.
    @Test("pausing tunnels everything")
    func disabledTunnelsEverything() {
        let policy = InterceptionPolicy(isEnabled: false)
        #expect(policy.decision(forHost: "example.com") == .tunnel(reason: .filteringDisabled))
    }
}

// MARK: - End to end

/// A minimal origin that answers any request with a fixed response, so the tunnel is
/// exercised against something real rather than a mock.
private final class OriginServer: Sendable {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let channelBox = NIOLockedValueBox<Channel?>(nil)

    func start() async throws -> Int {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(FixedResponseHandler())
            }
        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        channelBox.withLockedValue { $0 = channel }
        return channel.localAddress?.port ?? 0
    }

    func stop() async {
        let channel = channelBox.withLockedValue { $0 }
        try? await channel?.close()
        try? await group.shutdownGracefully()
    }
}

private final class FixedResponseHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let body = "tamis-origin-ok"
        let response = """
        HTTP/1.1 200 OK\r
        Content-Type: text/plain\r
        Content-Length: \(body.count)\r
        Connection: close\r
        \r
        \(body)
        """
        var buffer = context.channel.allocator.buffer(capacity: response.utf8.count)
        buffer.writeString(response)
        context.writeAndFlush(wrapOutboundOut(buffer)).whenComplete { _ in
            context.close(promise: nil)
        }
    }
}

@Suite("Proxy end to end", .serialized)
struct ProxyEndToEndTests {

    /// Sets up an origin and a proxy, runs `body`, and tears both down on every path.
    ///
    /// Cleanup cannot live in `defer`, because `defer` cannot await and a detached
    /// Task may not run before the objects are deallocated — NIO traps when an
    /// EventLoopGroup is destroyed without being shut down, which crashes the whole
    /// test process rather than failing one test.
    private func withServers<T>(
        policy: InterceptionPolicy = .init(),
        events: EventSink = EventSink(),
        _ body: (_ proxyPort: Int, _ originPort: Int) async throws -> T
    ) async throws -> T {
        let origin = OriginServer()
        let originPort = try await origin.start()
        let proxy = ProxyServer(configuration: .init(port: 0, policy: policy), events: events)
        try await proxy.start()

        func teardown() async {
            try? await proxy.stop()
            await origin.stop()
        }

        do {
            guard let proxyPort = proxy.boundPort else {
                await teardown()
                throw ProxyError.notStarted
            }
            let result = try await body(proxyPort, originPort)
            await teardown()
            return result
        } catch {
            await teardown()
            throw error
        }
    }

    /// Drives the proxy with curl rather than a hand-rolled client: the CONNECT
    /// handshake is exactly what a browser performs, including the details that are
    /// easy to get subtly wrong when writing both sides of it.
    private func curl(_ arguments: [String]) throws -> (body: String, trace: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = arguments
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let diagnostics = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (
            String(decoding: data, as: UTF8.self),
            String(decoding: diagnostics, as: UTF8.self)
        )
    }

    @Test("a CONNECT tunnel carries traffic end to end")
    func tunnelWorks() async throws {
        try await withServers { proxyPort, originPort in
            let body = try curl([
                "-sv", "--max-time", "10", "--proxytunnel",
                "-x", "http://127.0.0.1:\(proxyPort)",
                "http://127.0.0.1:\(originPort)/",
            ])
            #expect(body.body.contains("tamis-origin-ok"), "trace: \(body.trace)")
        }
    }

    @Test("the reason a connection was tunnelled is reported")
    func eventsAreEmitted() async throws {
        let recorder = EventRecorder()
        let events = EventSink { event in
            Task { await recorder.record(event) }
        }
        try await withServers(policy: .init(exclusions: ["127.0.0.1"]), events: events) { proxyPort, originPort in
            _ = try curl([
                "-sv", "--max-time", "10", "--proxytunnel",
                "-x", "http://127.0.0.1:\(proxyPort)",
                "http://127.0.0.1:\(originPort)/",
            ])
            try await Task.sleep(for: .milliseconds(300))
        }

        let recorded = await recorder.events
        let tunnelled = recorded.contains { event in
            if case .tunnelled(_, .httpsExclusion) = event { return true }
            return false
        }
        #expect(tunnelled, "expected an httpsExclusion tunnel event, got \(recorded)")
    }

    /// A 200 sent before the far end is up leaves the client negotiating TLS against
    /// nothing, which surfaces as an unexplained handshake failure rather than a
    /// connection error.
    @Test("an unreachable target answers 502 rather than a broken tunnel")
    func unreachableTarget() async throws {
        try await withServers { proxyPort, _ in
            let result = try curl([
                "-sv", "-o", "/dev/null", "--max-time", "10",
                "--proxytunnel", "-x", "http://127.0.0.1:\(proxyPort)",
                "http://127.0.0.1:1/",              // nothing listens on port 1
            ])
            // curl reports %{http_code} as 000 here — no HTTP transaction completed,
            // since the tunnel never opened. What matters is the status the proxy put
            // on the wire, which only the trace shows.
            #expect(result.trace.contains("502"), "trace: \(result.trace)")
        }
    }
}

private actor EventRecorder {
    var events: [EventSink.Event] = []
    func record(_ event: EventSink.Event) { events.append(event) }
}
