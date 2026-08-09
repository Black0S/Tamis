import Foundation
import Testing
@testable import TamisLists

@Suite("Internal allowlist")
struct InternalAllowlistTests {

    private let allowlist = InternalAllowlist.shared

    /// The scenario the rule exists for: a list containing the host its own updates
    /// come from would otherwise seal Tamis shut, silently and permanently.
    @Test("Every catalogue download host is protected")
    func coversTheCatalogue() {
        for entry in FilterListCatalog.bundled.entries {
            guard let host = entry.downloadURL.host() else {
                Issue.record("\(entry.id) has no host")
                continue
            }
            #expect(allowlist.contains(host: host), "\(host) could be blocked by a list")
        }
    }

    @Test("Encrypted DNS and app updates are protected", arguments: [
        "cloudflare-dns.com", "dns.quad9.net", "dns.google",
        "api.github.com", "objects.githubusercontent.com",
    ])
    func infrastructure(host: String) {
        #expect(allowlist.contains(host: host))
    }

    @Test("Subdomains are covered")
    func subdomains() {
        #expect(allowlist.contains(host: "cdn.raw.githubusercontent.com"))
        #expect(allowlist.contains(host: "RAW.GITHUBUSERCONTENT.COM"))
    }

    /// An allowlist that quietly grew to cover ordinary browsing would be a back door
    /// with a good excuse. It stays confined to what Tamis needs to keep working.
    @Test("Ordinary hosts are not on it", arguments: [
        "doubleclick.net", "google-analytics.com", "facebook.com",
        "google.com", "example.com",
    ])
    func staysNarrow(host: String) {
        #expect(!allowlist.contains(host: host))
    }

    @Test("It is small enough to read")
    func size() {
        #expect(allowlist.entries.count < 40, "\(allowlist.entries.count) entries")
    }

    /// The screen showing this list is the whole point. An entry without a reason
    /// would be an entry nobody can audit.
    @Test("Every entry carries a justification and a purpose")
    func justified() {
        for entry in allowlist.entries {
            #expect(entry.justification.count > 30, "\(entry.host): \(entry.justification)")
        }
        #expect(!allowlist.entries(for: .encryptedDNS).isEmpty)
        #expect(!allowlist.entries(for: .filterListSource).isEmpty)
        #expect(!allowlist.entries(for: .appUpdate).isEmpty)
    }

    @Test("The catalogue is what feeds it, not a copy that can drift")
    func derived() {
        let catalog = FilterListCatalog(entries: [
            .init(id: "x", name: "Test", description: "",
                  downloadURL: URL(string: "https://lists.example.org/a.txt")!,
                  homepage: "", registry: "Test", category: .ads, format: .adblock,
                  languages: [], recommendedByRegistry: false, inSuggestedSelection: false,
                  deprecated: false, trust: nil)
        ])
        let derived = InternalAllowlist.make(catalog: catalog)
        #expect(derived.contains(host: "lists.example.org"))
        #expect(!derived.contains(host: "raw.githubusercontent.com"))
    }
}
