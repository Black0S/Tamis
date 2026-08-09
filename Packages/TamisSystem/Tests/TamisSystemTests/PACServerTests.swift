import Darwin
import Foundation
import Testing
@testable import TamisSystem

@Suite("PAC helper", .serialized)
struct PACServerTests {

    /// A listener standing in for the proxy, so "is it answering" has a real answer.
    private final class FakeProxy {
        let descriptor: Int32
        let port: UInt16

        init() {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            var yes: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       socklen_t(MemoryLayout<Int32>.size))
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            address.sin_port = 0
            _ = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            listen(fd, 8)
            var bound = sockaddr_in()
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &bound) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &length)
                }
            }
            descriptor = fd
            port = UInt16(bigEndian: bound.sin_port)
        }

        func stop() { close(descriptor) }
    }

    private func makePAC(_ contents: String) throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-pac-\(UUID().uuidString)/proxy.pac")
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    @Test("The file is served when the proxy is answering")
    func servesTheFile() throws {
        let proxy = FakeProxy()
        defer { proxy.stop() }

        let url = try makePAC("function FindProxyForURL(u,h){return \"PROXY 127.0.0.1:1\";}")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let server = PACServer(pacURL: url, proxyPort: proxy.port)
        #expect(server.isProxyAnswering())
        #expect(server.currentScript().contains("PROXY 127.0.0.1:1"))
    }

    /// The point of the whole helper. Quitting Tamis must leave a Mac that browses.
    @Test("A dead proxy is served as DIRECT, not as a stale script")
    func failsOpenWhenProxyIsGone() throws {
        let proxy = FakeProxy()
        let port = proxy.port
        proxy.stop()

        let url = try makePAC("function FindProxyForURL(u,h){return \"PROXY 127.0.0.1:1\";}")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let server = PACServer(pacURL: url, proxyPort: port)
        #expect(!server.isProxyAnswering())
        // The file still exists and still says PROXY. What is served does not.
        #expect(server.currentScript() == ProxyAutoConfig.failOpen)
    }

    @Test("A missing or empty file is served as DIRECT")
    func failsOpenWithoutAFile() throws {
        let proxy = FakeProxy()
        defer { proxy.stop() }

        let missing = URL(fileURLWithPath: "/nonexistent/\(UUID().uuidString).pac")
        #expect(PACServer(pacURL: missing, proxyPort: proxy.port).currentScript()
                == ProxyAutoConfig.failOpen)

        let empty = try makePAC("")
        defer { try? FileManager.default.removeItem(at: empty.deletingLastPathComponent()) }
        #expect(PACServer(pacURL: empty, proxyPort: proxy.port).currentScript()
                == ProxyAutoConfig.failOpen)
    }

    /// End to end over HTTP, because macOS fetches this with a URL request and a helper
    /// that answers correctly in Swift but malforms its response helps nobody.
    @Test("macOS can fetch it over HTTP")
    func servesOverHTTP() async throws {
        let proxy = FakeProxy()
        defer { proxy.stop() }

        let url = try makePAC("function FindProxyForURL(u,h){return \"PROXY 127.0.0.1:9;\";}")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let server = PACServer(pacURL: url, proxyPort: proxy.port)
        try server.start(port: 0)
        defer { server.stop() }

        let port = try #require(server.boundPort)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration)

        let (data, response) = try await session.data(
            from: try #require(URL(string: "http://127.0.0.1:\(port)/tamis.pac"))
        )
        let http = try #require(response as? HTTPURLResponse)
        #expect(http.statusCode == 200)
        // The type macOS expects for an auto-configuration file.
        #expect(http.value(forHTTPHeaderField: "Content-Type")
                == "application/x-ns-proxy-autoconfig")
        #expect(String(decoding: data, as: UTF8.self).contains("FindProxyForURL"))
    }

    /// A cached script would keep pointing at a dead port for as long as the system
    /// felt like remembering it, which is exactly what the fail-open check is for.
    @Test("The response forbids caching")
    func noCaching() async throws {
        let proxy = FakeProxy()
        defer { proxy.stop() }

        let url = try makePAC("function FindProxyForURL(u,h){return \"DIRECT\";}")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }

        let server = PACServer(pacURL: url, proxyPort: proxy.port)
        try server.start(port: 0)
        defer { server.stop() }

        let port = try #require(server.boundPort)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.connectionProxyDictionary = [:]
        let (_, response) = try await URLSession(configuration: configuration).data(
            from: try #require(URL(string: "http://127.0.0.1:\(port)/tamis.pac"))
        )
        #expect((response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "Cache-Control") == "no-store")
    }
}
