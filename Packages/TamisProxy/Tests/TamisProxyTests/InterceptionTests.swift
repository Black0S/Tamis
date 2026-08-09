import Foundation
import Testing
import NIOCore
import NIOPosix
import NIOSSL
import NIOConcurrencyHelpers
import X509
import SwiftASN1
import TamisTLS
@testable import TamisProxy

private func der(_ certificate: Certificate) throws -> [UInt8] {
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    return serializer.serializedBytes
}

private func pem(_ der: [UInt8]) -> String {
    let body = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    return "-----BEGIN CERTIFICATE-----\n\(body)\n-----END CERTIFICATE-----\n"
}

/// An HTTPS origin with its own authority, standing in for a real site.
private final class TLSOriginServer: Sendable {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let authority: CertificateAuthority
    private let issuer: LeafIssuer
    private let channelBox = NIOLockedValueBox<Channel?>(nil)

    init() throws {
        authority = try CertificateAuthority.generate(machineName: "OriginCA")
        issuer = LeafIssuer(authority: authority)
    }

    var authorityDER: [UInt8] { get throws { try der(authority.certificate) } }

    func start(hostname: String) async throws -> Int {
        let leaf = try issuer.issue(for: hostname)
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: try der(leaf), format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: issuer.privateKeyDER, format: .der))
        )
        configuration.applicationProtocols = ["http/1.1"]
        let sslContext = try NIOSSLContext(configuration: configuration)

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandlers([
                    NIOSSLServerHandler(context: sslContext),
                    FixedHTTPResponseHandler(),
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

private final class FixedHTTPResponseHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let body = "tamis-tls-origin-ok"
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + "Content-Length: \(body.count)\r\nConnection: close\r\n\r\n\(body)"
        var buffer = context.channel.allocator.buffer(capacity: response.utf8.count)
        buffer.writeString(response)
        context.writeAndFlush(wrapOutboundOut(buffer)).whenComplete { _ in
            context.close(promise: nil)
        }
    }
}

@Suite("TLS interception", .serialized)
struct TLSInterceptionTests {

    private func makeMaterials(
        trusting originAuthority: [UInt8]
    ) throws -> (materials: TLSInterception.Materials, caPEM: String) {
        let ca = try CertificateAuthority.generate(machineName: "TamisTest")
        let issuer = LeafIssuer(authority: ca)
        let materials = try TLSInterception.Materials(
            authority: ca,
            cache: LeafCache(issuer: issuer),
            leafPrivateKeyDER: issuer.privateKeyDER,
            // The origin's authority is not in the system store, so the test supplies
            // it explicitly. Production leaves this empty.
            additionalTrustAnchors: [originAuthority]
        )
        return (materials, pem(try der(ca.certificate)))
    }

    private func curl(_ arguments: [String]) throws -> (body: String, trace: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = arguments
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let trace = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (String(decoding: data, as: UTF8.self), String(decoding: trace, as: UTF8.self))
    }

    /// The proof that interception works: curl trusts *Tamis's* authority, not the
    /// origin's, and still gets the origin's content. That can only happen if Tamis
    /// terminated one TLS session and opened another.
    @Test("an intercepted connection is decrypted and re-encrypted")
    func interceptionWorks() async throws {
        let origin = try TLSOriginServer()
        let originPort = try await origin.start(hostname: "localhost")
        let (materials, caPEM) = try makeMaterials(trusting: try origin.authorityDER)

        let caFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("tamis-test-ca-\(UUID().uuidString).pem")
        try caPEM.write(to: caFile, atomically: true, encoding: .utf8)

        let recorder = EventRecorder()
        let events = EventSink { event in Task { await recorder.record(event) } }
        let proxy = ProxyServer(
            configuration: .init(port: 0, interception: materials),
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
                "-sv", "--max-time", "15",
                "--cacert", caFile.path,               // trust Tamis, not the origin
                "-x", "http://127.0.0.1:\(proxyPort)",
                "https://localhost:\(originPort)/",
            ])
            #expect(result.body.contains("tamis-tls-origin-ok"), "trace: \(result.trace)")
            // curl must have been shown *our* certificate.
            #expect(result.trace.contains("Tamis Local CA"), "trace: \(result.trace)")

            try await Task.sleep(for: .milliseconds(200))
            let recorded = await recorder.events
            let intercepted = recorded.contains { event in
                if case .intercepted = event { return true }
                return false
            }
            #expect(intercepted, "events: \(recorded)")
            await teardown()
        } catch {
            await teardown()
            throw error
        }
    }

    /// A client that does not trust Tamis's authority must fail, not silently accept.
    /// This is the same code path a pinned application takes.
    @Test("a client that refuses our certificate is recorded as pinning")
    func pinningIsLearned() async throws {
        let origin = try TLSOriginServer()
        let originPort = try await origin.start(hostname: "localhost")
        let (materials, _) = try makeMaterials(trusting: try origin.authorityDER)

        let recorder = EventRecorder()
        let events = EventSink { event in Task { await recorder.record(event) } }
        let proxy = ProxyServer(
            configuration: .init(port: 0, interception: materials),
            events: events
        )
        try await proxy.start()

        func teardown() async {
            try? await proxy.stop()
            await origin.stop()
        }

        do {
            let proxyPort = try #require(proxy.boundPort)
            // No --cacert: curl trusts only the system store, which does not know us.
            let result = try curl([
                "-sv", "--max-time", "15",
                "-x", "http://127.0.0.1:\(proxyPort)",
                "https://localhost:\(originPort)/",
            ])
            #expect(!result.body.contains("tamis-tls-origin-ok"))

            try await Task.sleep(for: .milliseconds(400))
            let learned = proxy.learnedPassthrough
            #expect(learned.contains("localhost"), "learned: \(learned)")
            await teardown()
        } catch {
            await teardown()
            throw error
        }
    }

    /// An origin whose certificate does not validate must break the connection, never
    /// fall back to a tunnel — falling back would hide exactly what was just detected.
    @Test("an untrusted origin certificate fails the connection")
    func untrustedOriginIsRejected() async throws {
        let origin = try TLSOriginServer()
        let originPort = try await origin.start(hostname: "localhost")

        // Materials with no extra anchors: the origin's authority is unknown, so
        // upstream verification must refuse it.
        let ca = try CertificateAuthority.generate(machineName: "TamisTest")
        let issuer = LeafIssuer(authority: ca)
        let materials = try TLSInterception.Materials(
            authority: ca,
            cache: LeafCache(issuer: issuer),
            leafPrivateKeyDER: issuer.privateKeyDER
        )
        let caFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("tamis-test-ca-\(UUID().uuidString).pem")
        try pem(try der(ca.certificate)).write(to: caFile, atomically: true, encoding: .utf8)

        let recorder = EventRecorder()
        let events = EventSink { event in Task { await recorder.record(event) } }
        let proxy = ProxyServer(
            configuration: .init(port: 0, interception: materials),
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
                "-sv", "--max-time", "15", "--cacert", caFile.path,
                "-x", "http://127.0.0.1:\(proxyPort)",
                "https://localhost:\(originPort)/",
            ])
            #expect(!result.body.contains("tamis-tls-origin-ok"))

            try await Task.sleep(for: .milliseconds(400))
            let recorded = await recorder.events
            let rejected = recorded.contains { event in
                if case .upstreamCertificateRejected = event { return true }
                return false
            }
            #expect(rejected, "events: \(recorded)")
            await teardown()
        } catch {
            await teardown()
            throw error
        }
    }
}
