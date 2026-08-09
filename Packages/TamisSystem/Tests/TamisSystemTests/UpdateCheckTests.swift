import Foundation
import Testing
@testable import TamisSystem

private let liveTestsEnabled = ProcessInfo.processInfo.environment["TAMIS_LIVE_TESTS"] != nil

@Suite("Update check")
struct UpdateCheckTests {

    /// String comparison would call 0.10.0 older than 0.9.0 — the mistake that stops an
    /// update being offered at the moment it matters most.
    @Test("Versions compare numerically, not alphabetically", arguments: [
        ("0.10.0", "0.9.0", true),
        ("0.9.0", "0.10.0", false),
        ("1.0.0", "0.99.99", true),
        ("1.2.3", "1.2.3", false),
        ("1.2.4", "1.2.3", true),
        ("1.3", "1.2.9", true),
        ("2", "1.9.9", true),
    ])
    func numericComparison(candidate: String, current: String, expected: Bool) {
        #expect(UpdateCheck.isNewer(candidate, than: current) == expected,
                "\(candidate) vs \(current)")
    }

    /// Tags carry a `v` and often a suffix; versions carry neither.
    @Test("Tag decoration is ignored", arguments: [
        ("v1.2.0", "1.1.0", true),
        ("1.2.0-beta.1", "1.2.0", false),
        ("v2.0.0-rc1", "1.9.0", true),
    ])
    func tagDecoration(candidate: String, current: String, expected: Bool) {
        #expect(UpdateCheck.isNewer(candidate, than: current) == expected)
    }

    @Test("A release is read from GitHub's own shape")
    func parsing() throws {
        let json = """
        {"tag_name":"v0.2.0","name":"Tamis 0.2.0","body":"Notes.",
         "published_at":"2026-08-10T12:00:00Z","html_url":"https://example.com/r",
         "draft":false,"prerelease":false}
        """
        let release = try #require(UpdateCheck.parse(Data(json.utf8)))
        #expect(release.version == "v0.2.0")
        #expect(release.name == "Tamis 0.2.0")
        #expect(release.publishedAt != nil)
    }

    /// Neither is what somebody asked to be told about.
    @Test("Drafts and prereleases are not offered", arguments: [
        #"{"tag_name":"v9","html_url":"https://e.test","draft":true}"#,
        #"{"tag_name":"v9","html_url":"https://e.test","prerelease":true}"#,
    ])
    func draftsIgnored(json: String) {
        #expect(UpdateCheck.parse(Data(json.utf8)) == nil)
    }

    /// A project with no release yet is up to date, not broken.
    @Test("No release yet is not a failure")
    func noReleaseYet() async {
        let check = UpdateCheck(repository: "Black0S/definitely-not-a-repo-\(UUID().uuidString)",
                                currentVersion: "0.1.0")
        let outcome = await check.run()
        // Either GitHub says 404 — up to date — or the network is unavailable. Neither
        // is an error worth interrupting anyone for: a Mac that cannot reach GitHub is
        // still filtering.
        switch outcome {
        case .upToDate, .unavailable: break
        case .available(let release): Issue.record("version proposée : \(release.version)")
        }
    }

    @Test("The session does not go through Tamis's own proxy")
    func sessionIsolated() {
        #expect(UpdateCheck.makeSession().configuration.connectionProxyDictionary?.isEmpty == true)
    }

    @Test("Against the real repository", .enabled(if: liveTestsEnabled))
    func live() async {
        let outcome = await UpdateCheck(currentVersion: "0.0.1").run()
        switch outcome {
        case .available(let release):
            #expect(!release.version.isEmpty)
            #expect(release.url.host()?.contains("github.com") == true)
        case .upToDate, .unavailable:
            break   // no release published yet, which is true today
        }
    }
}
