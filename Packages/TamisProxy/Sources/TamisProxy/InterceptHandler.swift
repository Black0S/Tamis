import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import NIOHTTP1
import NIOConcurrencyHelpers
import X509
import SwiftASN1
import TamisTLS
import TamisFilterEngine
import TamisUserScripts

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
    ///
    /// Only the protocol the origin chose is advertised, so the two sides can never
    /// disagree — see ``NegotiatedProtocol``.
    static func serverConfiguration(
        for target: String,
        materials: Materials,
        advertising negotiated: NegotiatedProtocol
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
        configuration.applicationProtocols = negotiated.alpn
        return configuration
    }

    /// The TLS configuration used towards the origin.
    ///
    /// Verification is delegated to `SecTrust`, because BoringSSL does not read the
    /// macOS keychain and a bundled root list would reject every locally trusted
    /// authority — `mkcert`, Caddy, corporate roots.
    static func clientConfiguration() -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        // The built-in check is replaced, not relaxed: the callback consults the
        // system's trust policy, which BoringSSL cannot.
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

/// Waits for the client handshake, then wires the two sides together.
///
/// The upstream connection already exists by the time this runs, so the only thing
/// left to decide is which pair of pipelines to install. A client that refuses our
/// certificate never reaches the handshake, and that failure is what identifies a
/// pinned target.
final class InterceptHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let target: (host: String, port: Int)
    private let upstream: Channel
    private let negotiated: NegotiatedProtocol
    private let engine: FilterEngine
    private let cosmetic: CosmeticEngine?
    private let userScripts: [UserScript]
    private let userStyles: [UserStyle]
    private let styleVariables: [String: [String: String]]
    private let resolvedRequires: [URL: String]
    private let events: EventSink
    private let onPinningDetected: @Sendable (String) -> Void

    private var pending: [ByteBuffer] = []
    private var ready = false
    private var handshakeDone = false
    private var failed = false

    init(
        target: (host: String, port: Int),
        upstream: Channel,
        negotiated: NegotiatedProtocol,
        engine: FilterEngine,
        cosmetic: CosmeticEngine?,
        userScripts: [UserScript],
        userStyles: [UserStyle],
        styleVariables: [String: [String: String]],
        resolvedRequires: [URL: String],
        events: EventSink,
        onPinningDetected: @escaping @Sendable (String) -> Void
    ) {
        self.target = target
        self.upstream = upstream
        self.negotiated = negotiated
        self.engine = engine
        self.cosmetic = cosmetic
        self.userScripts = userScripts
        self.userStyles = userStyles
        self.styleVariables = styleVariables
        self.resolvedRequires = resolvedRequires
        self.events = events
        self.onPinningDetected = onPinningDetected
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted = event, !handshakeDone {
            handshakeDone = true
            install(context: context)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard ready else {
            // Decrypted bytes can arrive before the pipelines are in place; holding
            // them is the difference between a working first request and a truncated
            // one.
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
        upstream.close(promise: nil)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        upstream.close(promise: nil)
        context.fireChannelInactive()
    }

    private func install(context: ChannelHandlerContext) {
        let client = context.channel
        let host = target.host
        let events = self.events
        let engine = self.engine
        let cosmetic = self.cosmetic
        let userScripts = self.userScripts
        let userStyles = self.userStyles
        let styleVariables = self.styleVariables
        let resolvedRequires = self.resolvedRequires

        let installed: EventLoopFuture<Void>
        switch negotiated {
        case .http2:
            installed = HTTP2Bridge.install(
                client: client, upstream: upstream, host: host,
                engine: engine, cosmetic: cosmetic,
                userScripts: userScripts, userStyles: userStyles,
                styleVariables: styleVariables, resolvedRequires: resolvedRequires,
                events: events
            )
        case .http1:
            let requestContext = RequestContext()
            installed = upstream.pipeline.addHandlers([
                HTTPRequestEncoder(),
                ByteToMessageHandler(HTTPResponseDecoder(leftOverBytesStrategy: .forwardBytes)),
                ResponseInjectingHandler(
                    client: client, host: host, cosmetic: cosmetic,
                    userScripts: userScripts, userStyles: userStyles,
                styleVariables: styleVariables, resolvedRequires: resolvedRequires,
                    context: requestContext, events: events, propagatesClose: true
                ),
            ])
            .flatMap {
                client.pipeline.addHandlers([
                    HTTPResponseEncoder(),
                    ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
                    HTTPFilteringHandler(
                        engine: engine, host: host, upstream: self.upstream,
                        events: events, requestContext: requestContext,
                        propagatesClose: true
                    ),
                ])
            }
        }

        installed.whenComplete { result in
            switch result {
            case .success:
                // Only now can anything parse what the origin already sent. Over
                // HTTP/2 that is its SETTINGS frame, which arrived before this
                // pipeline existed.
                self.upstream.pipeline.handler(type: HandshakeReporter.self)
                    .whenSuccess { reporter in
                        self.upstream.eventLoop.execute { reporter.releaseReads() }
                    }
                events.emit(.intercepted(host: host, negotiated: self.negotiated.rawValue))
                self.ready = true
                // Replayed through this handler's own context: it is the only position
                // downstream of TLS and upstream of the new handlers. Firing from the
                // pipeline head would feed decrypted bytes back into TLS.
                for buffer in self.pending {
                    context.fireChannelRead(self.wrapInboundOut(buffer))
                }
                self.pending.removeAll()
            case .failure(let error):
                events.emit(.failed(host: host, message: "\(error)"))
                self.upstream.close(promise: nil)
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
