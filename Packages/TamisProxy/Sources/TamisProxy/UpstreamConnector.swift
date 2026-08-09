import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import NIOConcurrencyHelpers

/// Opens the connection to the origin, and reports what came back.
///
/// This runs *before* the client is answered, which is the ordering that makes the rest
/// work. Knowing the origin's protocol lets Tamis offer the client exactly that and
/// nothing else, so both sides always match; and knowing that interception is
/// impossible — an origin demanding a client certificate — while the client is still
/// waiting means falling back to a plain tunnel without it ever noticing.
enum UpstreamConnector {

    /// What happened when Tamis tried to speak TLS to the origin.
    enum Outcome: Sendable {
        /// Ready to intercept, speaking this protocol.
        case ready(Channel, NegotiatedProtocol)
        /// The origin wants a certificate only the user's keychain holds. Interception
        /// cannot satisfy that, and the connection should be tunnelled instead.
        case requiresClientCertificate
        /// The origin's own certificate did not validate. A security finding, never
        /// answered by falling back to a tunnel.
        case certificateRejected(reason: String, isNameMismatch: Bool)
        case failed(Error)
    }

    static func connect(
        to target: (host: String, port: Int),
        materials: TLSInterception.Materials,
        on loop: EventLoop
    ) -> EventLoopFuture<Outcome> {
        let host = target.host
        let verification = NIOLockedValueBox<SystemTrustVerifier.Result?>(nil)
        let handshake = loop.makePromise(of: Outcome.self)
        let settled = NIOLockedValueBox(false)

        @Sendable func settle(_ outcome: Outcome) {
            let alreadyDone = settled.withLockedValue { done -> Bool in
                defer { done = true }
                return done
            }
            guard !alreadyDone else { return }
            handshake.succeed(outcome)
        }

        // Bound to the client's event loop rather than the whole group. The two
        // channels of a proxied connection then share a loop, which removes every
        // cross-loop hop on the data path — and, with HTTP/2, the multiplexer
        // preconditions that come with touching a channel from the wrong one.
        ClientBootstrap(group: loop)
            .channelOption(.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                do {
                    var configuration = TLSInterception.clientConfiguration()
                    // Only what the bridge can actually carry today. Offering h2 here
                    // would have it negotiated and then hang: the origin answers, but
                    // the response never reaches the upstream stream handler. The
                    // machinery is written and tested up to that point — see
                    // HTTP2Bridge — and this line is the switch that turns it on.
                    configuration.applicationProtocols = ["http/1.1"]
                    let context = try NIOSSLContext(configuration: configuration)
                    let callback = TLSInterception.makeVerificationCallback(
                        hostname: host, materials: materials
                    ) { result in verification.withLockedValue { $0 = result } }
                    let tls = try NIOSSLClientHandler(
                        context: context,
                        serverHostname: InterceptHandler.sniName(for: host),
                        customVerificationCallback: callback
                    )
                    return channel.pipeline.addHandlers([
                        tls,
                        HandshakeReporter(
                            onCompleted: { protocolName in
                                settle(.ready(channel, NegotiatedProtocol.from(protocolName)))
                            },
                            onFailed: { error in
                                if case .rejected(let reason, let mismatch)? =
                                    verification.withLockedValue({ $0 }) {
                                    settle(.certificateRejected(
                                        reason: reason, isNameMismatch: mismatch
                                    ))
                                } else if InterceptHandler.looksLikeClientCertificateRequest(error) {
                                    settle(.requiresClientCertificate)
                                } else {
                                    settle(.failed(error))
                                }
                            }
                        ),
                    ])
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: target.host, port: target.port)
            .hop(to: loop)
            .whenFailure { error in settle(.failed(error)) }

        return handshake.futureResult
    }
}

/// Reports the outcome of a TLS handshake exactly once.
///
/// `connect()` completes when TCP is up; the handshake runs afterwards, so its result
/// arrives as a channel event rather than as a connect result. Watching the wrong one
/// turns a rejected certificate into a generic connection failure.
final class HandshakeReporter: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let onCompleted: @Sendable (String?) -> Void
    private let onFailed: @Sendable (Error) -> Void
    private var reported = false

    init(
        onCompleted: @escaping @Sendable (String?) -> Void,
        onFailed: @escaping @Sendable (Error) -> Void
    ) {
        self.onCompleted = onCompleted
        self.onFailed = onFailed
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted(let negotiated) = event, !reported {
            reported = true
            onCompleted(negotiated)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if !reported {
            reported = true
            onFailed(error)
        }
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        if !reported {
            reported = true
            onFailed(ChannelError.eof)
        }
        context.fireChannelInactive()
    }
}
