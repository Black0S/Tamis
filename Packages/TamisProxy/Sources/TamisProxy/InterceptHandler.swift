import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import NIOConcurrencyHelpers
import X509
import SwiftASN1
import TamisTLS
import TamisFilterEngine
import NIOHTTP1

/// Builds the two TLS sessions an intercepted connection is made of.
///
/// Tamis sits between them: it terminates the client's TLS with a certificate it
/// minted, and opens its own TLS to the origin. Neither side is aware of the other's
/// session, which is exactly why the origin's certificate must be checked here with
/// full rigour — the client has stopped checking it.
public enum TLSInterception {

    /// Everything needed to intercept, kept together so the proxy is configured once.
    public struct Materials: Sendable {
        public let cache: LeafCache
        public let leafPrivateKeyDER: [UInt8]
        public let authorityDER: [UInt8]
        /// Extra roots trusted for *upstream* verification.
        ///
        /// A test seam. Production leaves it empty and evaluates against what the
        /// machine actually trusts — a proxy that ships its own extra roots is a proxy
        /// nobody should install.
        public let additionalTrustAnchors: [[UInt8]]

        public init(
            authority: CertificateAuthority,
            cache: LeafCache,
            leafPrivateKeyDER: [UInt8],
            additionalTrustAnchors: [[UInt8]] = []
        ) throws {
            self.cache = cache
            self.leafPrivateKeyDER = leafPrivateKeyDER
            self.authorityDER = try authority.certificateDER()
            self.additionalTrustAnchors = additionalTrustAnchors
        }
    }

    /// The TLS configuration presented to the client for one target.
    ///
    /// The authority is sent alongside the leaf. A client that already trusts the root
    /// does not need it, but sending it costs one certificate and removes an entire
    /// class of "works here, fails there" reports.
    static func serverConfiguration(
        for target: String,
        materials: Materials
    ) throws -> TLSConfiguration {
        let certificate = try materials.cache.certificate(for: target)

        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        let leafDER = serializer.serializedBytes

        let chain: [NIOSSLCertificateSource] = [
            .certificate(try NIOSSLCertificate(bytes: leafDER, format: .der)),
            .certificate(try NIOSSLCertificate(bytes: materials.authorityDER, format: .der)),
        ]
        let key = try NIOSSLPrivateKey(bytes: materials.leafPrivateKeyDER, format: .der)

        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain,
            privateKey: .privateKey(key)
        )
        // Only HTTP/1.1 is advertised for now. Announcing h2 without implementing it
        // would have the client speak a protocol we cannot parse, which fails as a
        // hang rather than as an error.
        configuration.applicationProtocols = ["http/1.1"]
        return configuration
    }

    /// The TLS configuration used towards the origin.
    ///
    /// Verification is delegated to `SecTrust`, because BoringSSL does not read the
    /// macOS keychain and a bundled root list would reject every locally trusted
    /// authority — `mkcert`, Caddy, corporate roots.
    static func clientConfiguration() -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.applicationProtocols = ["http/1.1"]
        // The built-in check is replaced, not relaxed: the callback below is stricter
        // than BoringSSL's default here, since it consults the system's trust policy.
        configuration.certificateVerification = .noHostnameVerification
        return configuration
    }

    /// Verification callback handed to `NIOSSLClientHandler`.
    static func makeVerificationCallback(
        hostname: String,
        materials: Materials,
        onResult: @escaping @Sendable (SystemTrustVerifier.Result) -> Void
    ) -> NIOSSLCustomVerificationCallback {
        let anchors = materials.additionalTrustAnchors
        return { certificates, promise in
            let chain = certificates.compactMap { try? $0.toDERBytes() }
            let result = anchors.isEmpty
                ? SystemTrustVerifier.evaluate(chain: chain, hostname: hostname)
                : SystemTrustVerifier.evaluate(chain: chain, hostname: hostname, anchors: anchors)
            onResult(result)
            switch result {
            case .trusted:
                promise.succeed(.certificateVerified)
            case .rejected:
                // Failing the handshake is the whole point: the client trusts us now,
                // so accepting a bad origin certificate would hide a real attack.
                promise.succeed(.failed)
            }
        }
    }
}

/// Reports why an upstream TLS session failed.
///
/// `connect()` completes as soon as TCP is up — the handshake happens afterwards, so a
/// rejected origin certificate arrives here as a channel error rather than as a failed
/// connect. Watching the wrong one is how a security finding turns into a generic
/// "connection failed".
final class UpstreamDiagnosticHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let host: String
    private let events: EventSink
    private let outcome: NIOLockedValueBox<SystemTrustVerifier.Result?>
    private let onClientCertificateRequired: @Sendable (String) -> Void
    private var reported = false

    init(
        host: String,
        events: EventSink,
        outcome: NIOLockedValueBox<SystemTrustVerifier.Result?>,
        onClientCertificateRequired: @escaping @Sendable (String) -> Void
    ) {
        self.host = host
        self.events = events
        self.outcome = outcome
        self.onClientCertificateRequired = onClientCertificateRequired
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard !reported else { return }
        reported = true

        if case .rejected(let reason, let isNameMismatch)? = outcome.withLockedValue({ $0 }) {
            // A bad origin certificate is a security finding, not an outage, and must
            // never be answered by falling back to a tunnel — that would hide exactly
            // what was just detected.
            events.emit(.upstreamCertificateRejected(
                host: host, reason: reason, isNameMismatch: isNameMismatch
            ))
        } else if InterceptHandler.looksLikeClientCertificateRequest(error) {
            // The origin wants a certificate only the user's keychain holds.
            // Interception cannot satisfy that, so remember and tunnel next time.
            onClientCertificateRequired(host)
            events.emit(.clientCertificateRequired(host: host))
        } else {
            events.emit(.failed(host: host, message: "\(error)"))
        }
        context.close(promise: nil)
    }
}

/// Bridges the decrypted client session to the decrypted origin session.
///
/// Waits for the client handshake before dialling upstream. A client that refuses our
/// certificate never gets that far, and the failure surfaces as an error rather than
/// as a connection to an origin nobody is going to talk to.
final class InterceptHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let target: (host: String, port: Int)
    private let materials: TLSInterception.Materials
    private let group: EventLoopGroup
    private let events: EventSink
    private let engine: FilterEngine?
    private let onPinningDetected: @Sendable (String) -> Void

    private var upstream: Channel?
    private var pending: [ByteBuffer] = []
    private var handshakeDone = false
    private var failed = false
    /// True once the HTTP handlers are installed downstream and reads may flow on.
    private var ready = false

    init(
        target: (host: String, port: Int),
        materials: TLSInterception.Materials,
        group: EventLoopGroup,
        events: EventSink,
        engine: FilterEngine?,
        onPinningDetected: @escaping @Sendable (String) -> Void
    ) {
        self.target = target
        self.materials = materials
        self.group = group
        self.events = events
        self.engine = engine
        self.onPinningDetected = onPinningDetected
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted = event {
            handshakeDone = true
            connectUpstream(context: context)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard ready else {
            // Decrypted bytes can arrive before the origin session is up; holding them
            // is the difference between a working first request and a truncated one.
            pending.append(unwrapInboundIn(data))
            return
        }
        context.fireChannelRead(data)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard !failed else { return }
        failed = true

        if !handshakeDone {
            // The client refused the certificate we presented. That is certificate
            // pinning, not a fault: the target is remembered so the retry every pinned
            // client performs is tunnelled instead.
            onPinningDetected(target.host)
            events.emit(.pinningDetected(host: target.host))
        } else {
            events.emit(.failed(host: target.host, message: "\(error)"))
        }
        upstream?.close(promise: nil)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        upstream?.close(promise: nil)
        context.fireChannelInactive()
    }

    private func connectUpstream(context: ChannelHandlerContext) {
        let client = context.channel
        let loop = context.eventLoop
        let events = self.events
        let host = target.host
        let materials = self.materials
        let onPinning = self.onPinningDetected
        // No engine loaded is the first-launch state: traffic is parsed and forwarded,
        // nothing matches — precisely what "no list chosen yet" should do.
        let engineOrEmpty = self.engine ?? FilterEngine(rules: "")

        let verificationOutcome = NIOLockedValueBox<SystemTrustVerifier.Result?>(nil)

        ClientBootstrap(group: group)
            .channelInitializer { upstream in
                do {
                    let configuration = TLSInterception.clientConfiguration()
                    let sslContext = try NIOSSLContext(configuration: configuration)
                    let callback = TLSInterception.makeVerificationCallback(
                        hostname: host,
                        materials: materials
                    ) { result in
                        verificationOutcome.withLockedValue { $0 = result }
                    }
                    let tls = try NIOSSLClientHandler(
                        context: sslContext,
                        serverHostname: Self.sniName(for: host),
                        customVerificationCallback: callback
                    )
                    return upstream.pipeline.addHandlers([
                        tls,
                        UpstreamDiagnosticHandler(
                            host: host, events: events, outcome: verificationOutcome,
                            onClientCertificateRequired: onPinning
                        ),
                        HTTPRequestEncoder(),
                        ByteToMessageHandler(HTTPResponseDecoder(leftOverBytesStrategy: .forwardBytes)),
                        UpstreamResponseHandler(client: client),
                    ])
                } catch {
                    return upstream.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: target.host, port: target.port)
            .hop(to: loop)
            .whenComplete { result in
                switch result {
                case .success(let upstream):
                    self.upstream = upstream
                    events.emit(.intercepted(host: host))

                    // Decrypted bytes stop being opaque here: both sides are parsed, so
                    // the engine sees requests and the injection layer will later see
                    // responses without another round of parsing.
                    //
                    // The handlers are appended at the tail, which is already after this
                    // one. This handler stays in place rather than removing itself: the
                    // buffered bytes have to be re-delivered *downstream* of the TLS
                    // handler, and only a context positioned here can do that.
                    // `pipeline.fireChannelRead` starts at the head, which would feed
                    // already-decrypted bytes back into TLS.
                    client.pipeline.addHandlers([
                        HTTPResponseEncoder(),
                        ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
                        HTTPFilteringHandler(
                            engine: engineOrEmpty, host: host, upstream: upstream, events: events
                        ),
                    ]).whenComplete { _ in
                        self.ready = true
                        for buffer in self.pending {
                            context.fireChannelRead(self.wrapInboundOut(buffer))
                        }
                        self.pending.removeAll()
                    }
                case .failure(let error):
                    // Reaching here means TCP itself failed; a TLS rejection surfaces
                    // on the channel instead, in UpstreamDiagnosticHandler.
                    events.emit(.failed(host: host, message: "\(error)"))
                    client.close(promise: nil)
                }
            }
    }

    /// An address is not a valid SNI value, and sending one makes some origins abort.
    static func sniName(for host: String) -> String? {
        let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if bare.contains(":") { return nil }
        let labels = bare.split(separator: ".")
        if labels.count == 4, labels.allSatisfy({ $0.allSatisfy(\.isNumber) }) { return nil }
        return bare
    }

    static func looksLikeClientCertificateRequest(_ error: Error) -> Bool {
        let text = "\(error)".lowercased()
        return text.contains("certificate required")
            || text.contains("sslv3 alert handshake failure")
            || text.contains("peer did not return a certificate")
    }
}
