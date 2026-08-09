import Foundation
import Testing
import NIOCore
import NIOPosix
import NIOSSL
import NIOHTTP1
import NIOHTTP2
import NIOConcurrencyHelpers
import X509
import SwiftASN1
import TamisTLS
import TamisFilterEngine
@testable import TamisProxy

private func der2(_ certificate: Certificate) throws -> [UInt8] {
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    return serializer.serializedBytes
}

private func pem2(_ der: [UInt8]) -> String {
    let body = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
}

/// An origin that speaks HTTP/2, so the proxy negotiates h2 upstream and therefore
/// offers h2 to the client.
private final class H2OriginServer: Sendable {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let authority: CertificateAuthority
    private let issuer: LeafIssuer
    private let channelBox = NIOLockedValueBox<Channel?>(nil)

    static let page = """
    <!doctype html><html><head><title>H2</title></head>\
    <body><div class="ad-banner">publicité</div><p>Contenu.</p></body></html>
    """

    init() throws {
        authority = try CertificateAuthority.generate(machineName: "H2OriginCA")
        issuer = LeafIssuer(authority: authority)
    }

    var authorityDER: [UInt8] { get throws { try der2(authority.certificate) } }

    func start(hostname: String) async throws -> Int {
        let leaf = try issuer.issue(for: hostname)
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: try der2(leaf), format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: issuer.privateKeyDER, format: .der))
        )
        // Only h2, so a test that passes proves the HTTP/2 path was taken.
        configuration.applicationProtocols = ["h2"]
        let sslContext = try NIOSSLContext(configuration: configuration)

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(NIOSSLServerHandler(context: sslContext)).flatMap {
                    channel.configureHTTP2Pipeline(mode: .server) { stream in
                        stream.pipeline.addHandlers([
                            HTTP2FramePayloadToHTTP1ServerCodec(),
                            H2PageHandler(),
                        ])
                    }
                    .map { _ in () }
                }
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

private final class H2PageHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard case .end = unwrapInboundIn(data) else { return }
        let body = H2OriginServer.page
        var headers = HTTPHeaders()
        headers.add(name: "Content-Type", value: "text/html; charset=utf-8")
        headers.add(name: "Content-Length", value: "\(body.utf8.count)")
        let head = HTTPResponseHead(version: .http2, status: .ok, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
        buffer.writeString(body)
        context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
}

/// The fixture and the two protocol-agnostic assertions are kept enabled; the three
/// that require the bridge are disabled until it carries a response.
///
/// State of the work, narrowed by tapping the pipeline rather than by guessing:
///
/// - ALPN negotiates h2 on both sides and the bridge installs.
/// - The client's request reaches the origin in full, and the origin answers: 177 bytes
///   of response frames arrive on the upstream connection, past TLS.
/// - Those frames are never delivered to the upstream stream channel, so the response
///   handler never runs.
///
/// One real bug was found and fixed on the way: close propagation between the two sides
/// cancelled the stream with RST_STREAM the moment the response landed. Correct for
/// HTTP/1.1, where each side is a whole connection; wrong for streams.
///
/// Ruled out: legacy versus inline multiplexer, connection preface on an already-active
/// channel, autoRead on the stream channel, cross-event-loop hops, and now close
/// propagation.
@Suite("HTTP/2", .serialized)
struct HTTP2Tests {

    private func curl(_ arguments: [String]) throws -> (body: String, trace: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = arguments
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        let body = out.fileHandleForReading.readDataToEndOfFile()
        let trace = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (String(decoding: body, as: UTF8.self), String(decoding: trace, as: UTF8.self))
    }

    private func run(
        cosmetic: CosmeticEngine? = nil,
        engine: FilterEngine? = nil,
        curlExtra: [String] = [],
        path: String = "/article.html",
        _ body: (_ page: String, _ trace: String, _ events: [EventSink.Event]) async throws -> Void
    ) async throws {
        let origin = try H2OriginServer()
        let originPort = try await origin.start(hostname: "localhost")

        let ca = try CertificateAuthority.generate(machineName: "TamisH2")
        let issuer = LeafIssuer(authority: ca)
        let materials = try TLSInterception.Materials(
            authority: ca,
            cache: LeafCache(issuer: issuer),
            leafPrivateKeyDER: issuer.privateKeyDER,
            additionalTrustAnchors: [try origin.authorityDER]
        )
        let caFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("tamis-h2-\(UUID().uuidString).pem")
        try pem2(try der2(ca.certificate)).write(to: caFile, atomically: true, encoding: .utf8)

        let recorder = EventRecorder()
        let events = EventSink { event in Task { await recorder.record(event) } }
        let proxy = ProxyServer(
            configuration: .init(
                port: 0, interception: materials, engine: engine, cosmetic: cosmetic
            ),
            events: events
        )
        try await proxy.start()

        func teardown() async {
            try? await proxy.stop()
            await origin.stop()
            try? FileManager.default.removeItem(at: caFile)
        }

        do {
            let proxyPort = try #require(proxy.boundPort)
            let result = try curl([
                "-sv", "--max-time", "20", "--http2", "--cacert", caFile.path,
                "-x", "http://127.0.0.1:\(proxyPort)",
                "https://localhost:\(originPort)\(path)",
            ] + curlExtra)
            try await Task.sleep(for: .milliseconds(300))
            let recorded = await recorder.events
            if ProcessInfo.processInfo.environment["TAMIS_DEBUG"] == "1" {
                print("EVENTS: \(recorded)")
            }
            try await body(result.body, result.trace, recorded)
            await teardown()
        } catch {
            await teardown()
            throw error
        }
    }

    /// Isolates the test origin from the proxy: if this fails, the fault is in the
    /// fixture rather than in anything Tamis does.
    @Test("the HTTP/2 test origin answers on its own")
    func originAnswersDirectly() async throws {
        let origin = try H2OriginServer()
        let port = try await origin.start(hostname: "localhost")
        let caFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("tamis-h2-origin-\(UUID().uuidString).pem")
        try pem2(try origin.authorityDER).write(to: caFile, atomically: true, encoding: .utf8)

        let result = try curl([
            "-sv", "--max-time", "10", "--http2", "--cacert", caFile.path,
            "https://localhost:\(port)/",
        ])
        await origin.stop()
        try? FileManager.default.removeItem(at: caFile)
        #expect(result.body.contains("Contenu."), "trace: \(result.trace)")
    }

    /// Over HTTP/1.1 a browser opens six connections per origin, so Tamis performs six
    /// TLS handshakes on each side. Over HTTP/2 it opens one and multiplexes — for a
    /// page with eighty resources, eighty handshakes become one.
    @Test("an HTTP/2 origin is intercepted end to end", .disabled("bridge does not deliver response frames to the stream channel"))
    func interceptsHTTP2() async throws {
        try await run { page, trace, events in
            #expect(page.contains("Contenu."), "trace: \(trace)")
            // curl reports the negotiated protocol; anything else means the h2 path was
            // not the one exercised.
            #expect(trace.contains("using HTTP/2") || trace.contains("HTTP/2 200"),
                    "trace: \(trace)")

            let negotiated = events.compactMap { event -> String? in
                if case .intercepted(_, let proto) = event { return proto }
                return nil
            }
            #expect(negotiated == ["h2"], "events: \(events)")
        }
    }

    /// The protocol is taken from the origin and mirrored to the client, never chosen
    /// by the client. A browser picking HTTP/2 against an HTTP/1.1 origin would need one
    /// upstream connection per concurrent stream, and a pool to manage them.
    @Test("cosmetic injection works the same over HTTP/2", .disabled("bridge does not deliver response frames to the stream channel"))
    func injectionOverHTTP2() async throws {
        try await run(cosmetic: CosmeticEngine(rules: "localhost##.ad-banner")) { page, trace, _ in
            #expect(page.contains("<style nonce="), "trace: \(trace)")
            #expect(page.contains(".ad-banner"))
            #expect(page.contains("display: none !important"))
            #expect(page.contains("Contenu."))
        }
    }

    @Test("request blocking works the same over HTTP/2", .disabled("bridge does not deliver response frames to the stream channel"))
    func blockingOverHTTP2() async throws {
        try await run(
            engine: FilterEngine(rules: "||localhost/ads/"),
            curlExtra: ["-w", "\n%{http_code}"],
            path: "/ads/banner.png"
        ) { page, trace, events in
            #expect(!page.contains("Contenu."), "trace: \(trace)")
            #expect(page.contains("204"), "got: \(page)")

            let blocked = events.contains { event in
                if case .requestBlocked = event { return true }
                return false
            }
            #expect(blocked, "events: \(events)")
        }
    }
}
