import Foundation
import NIOCore
import NIOPosix
import NIOConcurrencyHelpers
import NIOHTTP1
import NIOSSL

public enum ProxyError: Error, Sendable, Equatable {
    case malformedConnectTarget(String)
    case notStarted
}

/// The HTTP proxy clients are pointed at by the PAC file.
///
/// Listens on loopback only. There is no authentication and that is a decision, not an
/// omission: any local process can already open its own sockets, so the proxy grants no
/// capability it did not already have. What it does add is visibility — every
/// connection is attributed and recorded.
public final class ProxyServer: Sendable {

    public struct Configuration: Sendable {
        public var host: String
        public var port: Int
        public var policy: InterceptionPolicy
        /// Absent means Tamis can only tunnel — which is a valid state, not a broken
        /// one: it is what a paused or not-yet-onboarded installation looks like.
        public var interception: TLSInterception.Materials?

        public init(
            host: String = "127.0.0.1",
            port: Int = 0,
            policy: InterceptionPolicy = .init(),
            interception: TLSInterception.Materials? = nil
        ) {
            self.host = host
            self.port = port
            self.policy = policy
            self.interception = interception
        }
    }

    private let group: EventLoopGroup
    private let configuration: Configuration
    private let events: EventSink
    private let ownsGroup: Bool
    private let channelBox = NIOLockedValueBox<Channel?>(nil)
    /// Targets that refused our certificate. Consulted on the next connection, which
    /// is how a pinned client's automatic retry gets tunnelled instead of failing
    /// again.
    private let learnedBox = NIOLockedValueBox<Set<String>>([])

    public init(
        configuration: Configuration,
        group: EventLoopGroup? = nil,
        events: EventSink = EventSink()
    ) {
        self.configuration = configuration
        self.group = group ?? MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.ownsGroup = group == nil
        self.events = events
    }

    /// Hosts learned to be un-interceptable during this run.
    public var learnedPassthrough: Set<String> {
        learnedBox.withLockedValue { $0 }
    }

    /// The port actually listened on, which matters when 0 asked the kernel to choose.
    public var boundPort: Int? {
        channelBox.withLockedValue { $0?.localAddress?.port }
    }

    public func start() async throws {
        let configuration = self.configuration
        let events = self.events
        let group = self.group
        let learned = self.learnedBox
        let learn: @Sendable (String) -> Void = { (host: String) -> Void in
            learned.withLockedValue { set in _ = set.insert(host) }
        }

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                // Deliberately not `configureHTTPServerPipeline`: a CONNECT tunnel has
                // to strip every HTTP handler once the 200 is out, and a pipeline this
                // small makes that a known, explicit list rather than a guess.
                channel.pipeline.addHandlers([
                    HTTPResponseEncoder(),
                    ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
                    ConnectHandler(
                        policy: configuration.policy, group: group, events: events,
                        interception: configuration.interception, learn: learn
                    ),
                ])
            }

        let channel = try await bootstrap.bind(host: configuration.host, port: configuration.port).get()
        channelBox.withLockedValue { $0 = channel }
    }

    public func stop() async throws {
        let channel = channelBox.withLockedValue { channel -> Channel? in
            defer { channel = nil }
            return channel
        }
        try? await channel?.close()
        if ownsGroup {
            try? await group.shutdownGracefully()
        }
    }
}

/// Reports what the proxy decided, so the app can build history without the proxy
/// knowing anything about storage.
public final class EventSink: Sendable {
    public typealias Handler = @Sendable (Event) -> Void

    public enum Event: Sendable {
        case tunnelled(host: String, reason: InterceptionPolicy.TunnelReason)
        case intercepted(host: String)
        /// The client refused our certificate: it pins. Remembered so the retry is
        /// tunnelled.
        case pinningDetected(host: String)
        /// The origin asked for a certificate only the user's keychain holds.
        case clientCertificateRequired(host: String)
        /// The origin's own certificate did not validate. A security finding, never
        /// answered by falling back to a tunnel.
        case upstreamCertificateRejected(host: String, reason: String, isNameMismatch: Bool)
        case failed(host: String, message: String)
    }

    private let handler: NIOLockedValueBox<Handler?>

    public init(handler: Handler? = nil) {
        self.handler = NIOLockedValueBox(handler)
    }

    public func setHandler(_ handler: @escaping Handler) {
        self.handler.withLockedValue { $0 = handler }
    }

    func emit(_ event: Event) {
        handler.withLockedValue { $0 }?(event)
    }
}

// MARK: - CONNECT

/// Handles the client's first request and decides what the connection becomes.
final class ConnectHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let policy: InterceptionPolicy
    private let group: EventLoopGroup
    private let events: EventSink
    private let interception: TLSInterception.Materials?
    private let learn: @Sendable (String) -> Void
    private var target: (host: String, port: Int)?
    private var mode: Mode = .tunnel

    enum Mode { case tunnel, intercept }

    init(
        policy: InterceptionPolicy,
        group: EventLoopGroup,
        events: EventSink,
        interception: TLSInterception.Materials?,
        learn: @escaping @Sendable (String) -> Void
    ) {
        self.policy = policy
        self.group = group
        self.events = events
        self.interception = interception
        self.learn = learn
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            guard head.method == .CONNECT else {
                // Plain HTTP proxying is a separate path; refuse clearly rather than
                // half-handling it.
                respond(context: context, status: .notImplemented)
                return
            }
            guard let parsed = Self.parseTarget(head.uri) else {
                events.emit(.failed(host: head.uri, message: "malformed CONNECT target"))
                respond(context: context, status: .badRequest)
                return
            }
            target = parsed

        case .body:
            break   // a CONNECT carries no body

        case .end:
            guard let target else {
                respond(context: context, status: .badRequest)
                return
            }
            switch policy.decision(forHost: target.host) {
            case .tunnel(let reason):
                events.emit(.tunnelled(host: target.host, reason: reason))
                mode = .tunnel
            case .intercept:
                // No materials means onboarding has not run. Tunnelling then is the
                // right answer, not a degraded one: Tamis is simply transparent.
                mode = interception == nil ? .tunnel : .intercept
                if mode == .tunnel {
                    events.emit(.tunnelled(host: target.host, reason: .filteringDisabled))
                }
            }
            switch mode {
            case .tunnel:    openTunnel(context: context, to: target)
            case .intercept: beginInterception(context: context, to: target)
            }
        }
    }

    /// `CONNECT host:port` — the host may be an IPv6 literal in brackets.
    static func parseTarget(_ uri: String) -> (host: String, port: Int)? {
        guard let colon = uri.lastIndex(of: ":") else { return nil }
        let host = String(uri[uri.startIndex..<colon])
        guard let port = Int(uri[uri.index(after: colon)...]), (1...65_535).contains(port) else {
            return nil
        }
        let bare = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast())
            : host
        guard !bare.isEmpty else { return nil }
        return (bare, port)
    }

    private func openTunnel(context: ChannelHandlerContext, to target: (host: String, port: Int)) {
        let client = context.channel
        let loop = context.eventLoop
        let events = self.events
        let relay = RelayHandler(peer: nil)

        ClientBootstrap(group: group)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { upstream in
                upstream.pipeline.addHandler(RelayHandler(peer: client))
            }
            .connect(host: target.host, port: target.port)
            // The connect future completes on the upstream channel's loop, which is not
            // necessarily the client's. A ChannelHandlerContext may only ever be touched
            // from its own loop, so hop before going anywhere near it.
            .hop(to: loop)
            .whenComplete { result in
                switch result {
                case .success(let upstream):
                    relay.setPeer(upstream)
                    // Answer only once the far end is up: a 200 followed by a failed
                    // connection leaves the client negotiating TLS against nothing,
                    // which surfaces as an unexplained handshake error.
                    //
                    // Content-Length: 0 is not decoration. Without explicit framing the
                    // encoder falls back to chunked and writes a chunk terminator into
                    // the tunnel, so the first thing the client reads after the 200 is
                    // `0\r\n\r\n` rather than the origin's response.
                    var headers = HTTPHeaders()
                    headers.add(name: "Content-Length", value: "0")
                    let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
                    context.write(self.wrapOutboundOut(.head(head)), promise: nil)
                    context.writeAndFlush(self.wrapOutboundOut(.end(nil)))
                        .flatMap { Self.becomeRawTunnel(on: client, connectHandler: self, relay: relay) }
                        .whenFailure { _ in
                            client.close(promise: nil)
                            upstream.close(promise: nil)
                        }
                case .failure(let error):
                    events.emit(.failed(host: target.host, message: "\(error)"))
                    self.respond(context: context, status: .badGateway)
                }
            }
    }

    /// Answers the CONNECT, then turns the client side into a TLS server.
    ///
    /// The 200 goes out before the TLS handlers are installed, because the client will
    /// not start its handshake until it has seen one.
    private func beginInterception(context: ChannelHandlerContext, to target: (host: String, port: Int)) {
        guard let materials = interception else {
            openTunnel(context: context, to: target)
            return
        }
        let client = context.channel
        let events = self.events
        let group = self.group
        let learn = self.learn

        var headers = HTTPHeaders()
        headers.add(name: "Content-Length", value: "0")
        let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)))
            .flatMap { () -> EventLoopFuture<Void> in
                let pipeline = client.pipeline
                return pipeline.removeHandler(self)
                    .flatMap { pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self) }
                    .flatMap { pipeline.removeHandler($0) }
                    .flatMap { pipeline.handler(type: HTTPResponseEncoder.self) }
                    .flatMap { pipeline.removeHandler($0) }
                    .flatMap { () -> EventLoopFuture<Void> in
                        do {
                            let configuration = try TLSInterception.serverConfiguration(
                                for: target.host, materials: materials
                            )
                            let sslContext = try NIOSSLContext(configuration: configuration)
                            return pipeline.addHandlers([
                                NIOSSLServerHandler(context: sslContext),
                                InterceptHandler(
                                    target: target, materials: materials, group: group,
                                    events: events, onPinningDetected: learn
                                ),
                            ])
                        } catch {
                            return client.eventLoop.makeFailedFuture(error)
                        }
                    }
            }
            .whenFailure { error in
                events.emit(.failed(host: target.host, message: "\(error)"))
                client.close(promise: nil)
            }
    }

    /// Strips the HTTP machinery so the two channels exchange opaque bytes.
    ///
    /// Every handler is named explicitly rather than swept: leaving one behind would
    /// have it try to parse TLS records as HTTP, which fails in ways that look like a
    /// network fault rather than a bug here.
    private static func becomeRawTunnel(
        on channel: Channel,
        connectHandler: ConnectHandler,
        relay: RelayHandler
    ) -> EventLoopFuture<Void> {
        let pipeline = channel.pipeline
        return pipeline.removeHandler(connectHandler)
            .flatMap { pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self) }
            .flatMap { pipeline.removeHandler($0) }
            .flatMap { pipeline.handler(type: HTTPResponseEncoder.self) }
            .flatMap { pipeline.removeHandler($0) }
            .flatMap { pipeline.addHandler(relay) }
    }

    private func respond(context: ChannelHandlerContext, status: HTTPResponseStatus) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Length", value: "0")
        headers.add(name: "Connection", value: "close")
        let head = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            context.close(promise: nil)
        }
    }
}
