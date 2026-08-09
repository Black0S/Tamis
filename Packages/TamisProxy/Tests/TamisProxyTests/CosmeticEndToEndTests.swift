import Foundation
import Testing
import NIOCore
import NIOPosix
import NIOSSL
import NIOConcurrencyHelpers
import X509
import SwiftASN1
import TamisTLS
import TamisFilterEngine
@testable import TamisProxy

private func derBytes(_ certificate: Certificate) throws -> [UInt8] {
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    return serializer.serializedBytes
}

private func pemText(_ der: [UInt8]) -> String {
    let body = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
}

/// An HTTPS origin serving a real page, so injection is exercised against markup
/// rather than a placeholder.
private final class HTMLOriginServer: Sendable {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let authority: CertificateAuthority
    private let issuer: LeafIssuer
    private let channelBox = NIOLockedValueBox<Channel?>(nil)

    static let page = """
    <!doctype html>
    <html lang="fr">
    <head><meta charset="utf-8"><title>Article</title></head>
    <body>
    <h1>Titre</h1>
    <div class="ad-banner">publicité</div>
    <p>Contenu de l'article.</p>
    </body>
    </html>
    """

    init() throws {
        authority = try CertificateAuthority.generate(machineName: "OriginCA")
        issuer = LeafIssuer(authority: authority)
    }

    var authorityDER: [UInt8] { get throws { try derBytes(authority.certificate) } }

    func start(hostname: String, extraHeaders: [(String, String)] = []) async throws -> Int {
        let leaf = try issuer.issue(for: hostname)
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: try derBytes(leaf), format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: issuer.privateKeyDER, format: .der))
        )
        configuration.applicationProtocols = ["http/1.1"]
        let sslContext = try NIOSSLContext(configuration: configuration)
        let headers = extraHeaders

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandlers([
                    NIOSSLServerHandler(context: sslContext),
                    HTMLPageHandler(extraHeaders: headers),
                ])
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

private final class HTMLPageHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let extraHeaders: [(String, String)]

    init(extraHeaders: [(String, String)]) {
        self.extraHeaders = extraHeaders
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let body = HTMLOriginServer.page
        var response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        for (name, value) in extraHeaders { response += "\(name): \(value)\r\n" }
        response += "Content-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"

        var buffer = context.channel.allocator.buffer(capacity: response.utf8.count)
        buffer.writeString(response)
        context.writeAndFlush(wrapOutboundOut(buffer)).whenComplete { _ in
            context.close(promise: nil)
        }
    }
}

@Suite("Cosmetic injection end to end", .serialized)
struct CosmeticEndToEndTests {

    private func curl(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = arguments
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        _ = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    private func run(
        cosmetic: CosmeticEngine?,
        originHeaders: [(String, String)] = [],
        curlExtra: [String] = [],
        _ body: (_ page: String, _ events: [EventSink.Event]) async throws -> Void
    ) async throws {
        let origin = try HTMLOriginServer()
        let originPort = try await origin.start(hostname: "localhost", extraHeaders: originHeaders)

        let ca = try CertificateAuthority.generate(machineName: "TamisTest")
        let issuer = LeafIssuer(authority: ca)
        let materials = try TLSInterception.Materials(
            authority: ca,
            cache: LeafCache(issuer: issuer),
            leafPrivateKeyDER: issuer.privateKeyDER,
            additionalTrustAnchors: [try origin.authorityDER]
        )
        let caFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("tamis-cosmetic-\(UUID().uuidString).pem")
        try pemText(try derBytes(ca.certificate)).write(to: caFile, atomically: true, encoding: .utf8)

        let recorder = EventRecorder()
        let events = EventSink { event in Task { await recorder.record(event) } }
        let proxy = ProxyServer(
            configuration: .init(port: 0, interception: materials, cosmetic: cosmetic),
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
            let page = try curl([
                "-s", "--max-time", "15", "--cacert", caFile.path,
                "-x", "http://127.0.0.1:\(proxyPort)",
                "https://localhost:\(originPort)/article.html",
            ] + curlExtra)
            try await Task.sleep(for: .milliseconds(250))
            try await body(page, await recorder.events)
            await teardown()
        } catch {
            await teardown()
            throw error
        }
    }

    /// The whole point of cosmetic filtering: blocking the request leaves a hole where
    /// the advert was, and this is what closes it.
    @Test("a stylesheet hiding the advert is injected into the page")
    func injectsStylesheet() async throws {
        try await run(cosmetic: CosmeticEngine(rules: "localhost##.ad-banner")) { page, events in
            #expect(page.contains("<style nonce="))
            #expect(page.contains(".ad-banner"))
            #expect(page.contains("display: none !important"))
            // The page itself must survive intact.
            #expect(page.contains("Contenu de l'article."))
            #expect(page.contains("<title>Article</title>"))

            let injected = events.contains { if case .injected = $0 { return true }; return false }
            #expect(injected, "events: \(events)")
        }
    }

    /// Immediately after `<head>`, so the rule applies before the document loads
    /// anything of its own and the advert slot never flashes visible.
    @Test("the stylesheet lands inside the head, before the body")
    func injectedInHead() async throws {
        try await run(cosmetic: CosmeticEngine(rules: "localhost##.ad-banner")) { page, _ in
            let styleIndex = try #require(page.range(of: "<style nonce=")?.lowerBound)
            let bodyIndex = try #require(page.range(of: "<body")?.lowerBound)
            #expect(styleIndex < bodyIndex)
        }
    }

    /// The single most common way a filtering proxy fails silently: without this the
    /// browser drops the injected tag and the hole stays open, with nothing in any log
    /// to explain it.
    @Test("a restrictive CSP is amended to accept the injected tag")
    func cspIsAmended() async throws {
        try await run(
            cosmetic: CosmeticEngine(rules: "localhost##.ad-banner"),
            originHeaders: [("Content-Security-Policy", "default-src 'self'; style-src 'self'")],
            curlExtra: ["-D", "-"]
        ) { page, _ in
            let nonce = try #require(
                page.range(of: "<style nonce=\"").map { range -> String in
                    let start = range.upperBound
                    let end = page[start...].firstIndex(of: "\"") ?? start
                    return String(page[start..<end])
                }
            )
            #expect(!nonce.isEmpty)
            // The very nonce on the tag must appear in the policy, or the browser drops it.
            #expect(page.contains("'nonce-\(nonce)'"))
            // And the rest of the policy is untouched.
            #expect(page.lowercased().contains("default-src 'self'"))
        }
    }

    @Test("a site with no matching rule is served byte for byte")
    func noRuleNoChange() async throws {
        try await run(cosmetic: CosmeticEngine(rules: "other.example##.ad-banner")) { page, _ in
            #expect(!page.contains("<style nonce="))
            #expect(page.contains("<div class=\"ad-banner\">"))
        }
    }

    /// No cosmetic engine is first launch: requests are still filtered, but nothing is
    /// hidden, so blocked adverts leave their holes open.
    @Test("without a cosmetic engine the page is untouched")
    func noEngineNoInjection() async throws {
        try await run(cosmetic: nil) { page, _ in
            #expect(!page.contains("<style nonce="))
            #expect(page.contains("Contenu de l'article."))
        }
    }
}
