import Foundation
import Testing
@testable import TamisLists

/// Reaching the network is opt-in, so an offline run stays deterministic:
///
///     TAMIS_LIVE_TESTS=1 swift test --package-path Packages/TamisLists
private let liveTestsEnabled = ProcessInfo.processInfo.environment["TAMIS_LIVE_TESTS"] != nil

@Suite("Downloader")
struct DownloaderTests {

    /// The session settings are the interesting part: Tamis has just pointed the system
    /// proxy at itself, and a downloader that inherits that would fetch its own updates
    /// through the component it is updating.
    @Test("The session bypasses the system proxy and keeps no state")
    func sessionIsIsolated() {
        let configuration = ListDownloader.makeSession().configuration
        // Empty rather than nil: nil means "use the system settings".
        #expect(configuration.connectionProxyDictionary?.isEmpty == true)
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.urlCache == nil)
        #expect(configuration.tlsMinimumSupportedProtocolVersion == .TLSv12)
    }

    @Test("A real list downloads and clears the guardrails", .enabled(if: liveTestsEnabled))
    func liveDownload() async throws {
        let downloader = ListDownloader()
        let url = try #require(
            FilterListCatalog.bundled["ubo:easylist"]?.downloadURL
                ?? FilterListCatalog.bundled.entries.first?.downloadURL
        )
        let response = try await downloader.fetch(url)

        #expect(response.statusCode == 200)
        #expect(response.bytes > 10_000)
        #expect(UpdateGuard.checkTransport(
            statusCode: response.statusCode,
            contentLength: response.contentLength,
            receivedBytes: response.bytes
        ) == nil)
    }

    /// Worth exercising against a real server: it is the difference between a daily
    /// update costing a few hundred bytes and costing five megabytes.
    @Test("An unchanged list answers 304", .enabled(if: liveTestsEnabled))
    func liveConditional() async throws {
        let downloader = ListDownloader()
        let url = try #require(FilterListCatalog.bundled.entries(in: .dns).first?.downloadURL)

        let first = try await downloader.fetch(url)
        guard let etag = first.etag else { return }  // not every host offers one
        let second = try await downloader.fetch(url, etag: etag)
        #expect(second.isUnchanged)
        #expect(second.bytes == 0)
    }
}
