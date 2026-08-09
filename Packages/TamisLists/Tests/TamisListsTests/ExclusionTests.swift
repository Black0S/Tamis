import Foundation
import Testing
@testable import TamisLists

@Suite("Exclusions")
struct ExclusionTests {

    private func parse(_ text: String, lock: ExclusionSource.Lock = .hard)
        -> (ExclusionSource, ExclusionSource.ParseReport) {
        ExclusionSource.parse(
            text, id: "t", name: "Test", provider: "Test", licence: "MIT", lock: lock
        )
    }

    // MARK: Parsing

    @Test("All three comment styles are ignored")
    func comments() {
        let (source, report) = parse("""
        // AdGuard writes this
        # Zen writes this
        ! and one line of issues.txt writes this
        example.com
        """)
        #expect(source.entries.count == 1)
        #expect(report.unparsed.isEmpty)
    }

    @Test("Quotes mean that host and no other")
    func exact() {
        let (source, _) = parse("\"lastpass.com\"")
        #expect(source.entries.first?.scope == .exact)
        #expect(source.entries.first?.pattern == "lastpass.com")
    }

    @Test("$app= restricts to bundle identifiers")
    func appRestriction() {
        let (source, _) = parse("chatgpt.com$app=com.openai.atlas|com.example.other")
        #expect(source.entries.first?.apps == ["com.openai.atlas", "com.example.other"])
        #expect(source.entries.first?.pattern == "chatgpt.com")
    }

    /// `api.github.com$app=Discord.exe` is upstream's fix for Discord on Windows.
    /// Keeping it would exclude GitHub's API from filtering on a platform where the
    /// restriction can never be satisfied.
    @Test("Windows-only entries are dropped and counted")
    func windowsOnly() {
        let (source, report) = parse("api.github.com$app=Discord.exe")
        #expect(source.entries.isEmpty)
        #expect(report.notApplicableToMacOS == 1)
        #expect(report.unparsed.isEmpty)
    }

    @Test("Duplicate lines collapse")
    func duplicates() {
        let (source, report) = parse("example.com\nEXAMPLE.COM\nexample.com.")
        #expect(source.entries.count == 1)
        #expect(report.accepted == 1)
    }

    /// The one entry that would silently do nothing without ``IDNA``.
    @Test("A Unicode bank is stored the way it appears on the wire")
    func unicodeEntry() {
        let (source, _) = parse("onlinebanking-hüttenberger-bank.de")
        #expect(source.entries.first?.pattern == "xn--onlinebanking-httenberger-bank-jfd.de")
    }

    // MARK: Matching

    @Test("A bare domain covers its subdomains, an exact one does not")
    func scopes() {
        let (source, _) = parse("example.com\n\"exact.com\"")
        let set = ExclusionSet(sources: [source])

        #expect(set.isExcluded(host: "example.com"))
        #expect(set.isExcluded(host: "login.example.com"))
        #expect(set.isExcluded(host: "a.b.example.com"))
        #expect(set.isExcluded(host: "exact.com"))
        #expect(!set.isExcluded(host: "login.exact.com"))
    }

    /// `notexample.com` ends with `example.com` as a string but is a different domain.
    @Test("Suffix matching respects label boundaries")
    func labelBoundary() {
        let (source, _) = parse("example.com")
        let set = ExclusionSet(sources: [source])
        #expect(!set.isExcluded(host: "notexample.com"))
        #expect(!set.isExcluded(host: "example.com.evil.net"))
    }

    @Test("Wildcards span labels")
    func wildcard() {
        let (source, _) = parse("ping.*.adguard.io")
        let set = ExclusionSet(sources: [source])
        #expect(set.isExcluded(host: "ping.eu.adguard.io"))
        #expect(set.isExcluded(host: "ping.a.b.adguard.io"))
        #expect(!set.isExcluded(host: "ping.adguard.com"))
    }

    @Test("A Unicode host is matched by its encoded entry")
    func unicodeMatch() {
        let (source, _) = parse("onlinebanking-hüttenberger-bank.de")
        let set = ExclusionSet(sources: [source])
        #expect(set.isExcluded(host: "xn--onlinebanking-httenberger-bank-jfd.de"))
        #expect(set.isExcluded(host: "www.xn--onlinebanking-httenberger-bank-jfd.de"))
    }

    @Test("$app= narrows when the application is known")
    func appMatching() {
        let (source, _) = parse("chatgpt.com$app=com.openai.atlas")
        let set = ExclusionSet(sources: [source])
        #expect(set.isExcluded(host: "chatgpt.com", bundleID: "com.openai.atlas"))
        #expect(!set.isExcluded(host: "chatgpt.com", bundleID: "com.apple.Safari"))
    }

    /// Not attributing a connection must not silently turn an exclusion off.
    @Test("$app= still applies when the application is unknown")
    func appUnattributed() {
        let (source, _) = parse("chatgpt.com$app=com.openai.atlas")
        let set = ExclusionSet(sources: [source])
        #expect(set.isExcluded(host: "chatgpt.com", bundleID: nil))
    }

    // MARK: Sources stay independent

    @Test("A match names the source it came from")
    func attribution() {
        let (adguard, _) = ExclusionSource.parse(
            "apple.com", id: "adguard.mac", name: "macOS", provider: "AdGuard",
            licence: "MIT", lock: .entriesOverridable
        )
        let (zen, _) = ExclusionSource.parse(
            "apple.com\ngouv.fr", id: "zen.darwin", name: "Apple services",
            provider: "Zen", licence: "MIT", lock: .entriesOverridable
        )
        let set = ExclusionSet(sources: [adguard, zen])

        #expect(set.allMatches(host: "apple.com").map(\.sourceID) == ["adguard.mac", "zen.darwin"])
        #expect(set.allMatches(host: "gouv.fr").map(\.sourceID) == ["zen.darwin"])
        // An overlap is counted once even though both sources keep their own copy.
        #expect(set.distinctPatternCount == 2)
    }

    @Test("allMatches answers for the person asking, not for one application")
    func searchIgnoresApps() {
        let (source, _) = parse("chatgpt.com$app=com.openai.atlas")
        let set = ExclusionSet(sources: [source])
        #expect(set.allMatches(host: "chatgpt.com").count == 1)
    }

    // MARK: Locks

    @Test("An overridable source can have one entry switched off")
    func overrideSoft() {
        let (source, _) = parse("idmsa.apple.com\nrelays.syncthing.net", lock: .entriesOverridable)
        var set = ExclusionSet(sources: [source])
        set.setOverrides(["idmsa.apple.com"], forSource: "t")

        #expect(!set.isExcluded(host: "idmsa.apple.com"))
        #expect(set.isExcluded(host: "relays.syncthing.net"))
    }

    /// The guarantee the design rests on: no path, including a stored override,
    /// switches off a bank.
    @Test("A hard-locked source ignores overrides entirely")
    func overrideHard() {
        let (source, _) = parse("mabanque.bnpparibas", lock: .hard)
        var set = ExclusionSet(sources: [source])
        set.setOverrides(["mabanque.bnpparibas"], forSource: "t")
        #expect(set.isExcluded(host: "mabanque.bnpparibas"))
    }
}
