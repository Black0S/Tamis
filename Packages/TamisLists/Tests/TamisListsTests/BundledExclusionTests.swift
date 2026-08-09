import Foundation
import Testing
@testable import TamisLists

/// Run against the seven files actually shipped, not against fixtures.
///
/// Unit tests prove the parser handles the syntax it was shown. These prove the lists
/// in the repository parse, and that hosts people care about come out excluded — which
/// is a different claim, and the one that matters at run time.
@Suite("Bundled exclusions")
struct BundledExclusionTests {

    @Test("All seven sources load")
    func sourcesLoad() throws {
        let sources = BundledExclusions.sources
        #expect(sources.count == 7)
        for source in sources {
            #expect(!source.entries.isEmpty, "\(source.id) parsed to nothing")
        }
    }

    @Test("Nothing in the shipped lists fails to parse")
    func noUnparsedLines() throws {
        for (id, report) in BundledExclusions.reports {
            #expect(report.unparsed.isEmpty, "\(id): \(report.unparsed.prefix(5))")
        }
    }

    /// The lists are worth roughly this much; a large move means an upstream change
    /// worth reading rather than a test worth relaxing.
    @Test("The set is the size it should be")
    func size() {
        let set = BundledExclusions.makeSet()
        #expect(set.distinctPatternCount > 4_000)
        #expect(set.distinctPatternCount < 6_000)
    }

    @Test("Banks and password managers are excluded", arguments: [
        "mabanque.bnpparibas",
        "www.credit-agricole.fr",
        "chase.com",
        "lastpass.com",
        "proton.me",
        "appleid.apple.com",
    ])
    func sensitiveHosts(host: String) {
        let set = BundledExclusions.makeSet()
        #expect(set.match(host: host) != nil, "\(host) would be decrypted")
    }

    /// The reason ``IDNA`` exists, checked against the shipped file rather than a
    /// hand-written line.
    @Test("The Unicode bank in banks.txt matches its wire form")
    func unicodeBank() {
        let set = BundledExclusions.makeSet()
        #expect(set.match(host: "xn--onlinebanking-httenberger-bank-jfd.de") != nil)
    }

    /// Stated in SPEC §8.2 as a consequence, not a preference: Apple telemetry can only
    /// ever be handled at the DNS layer. If this stops being true the specification is
    /// wrong and should be corrected, so the fact is pinned here.
    @Test("Apple domains are excluded, which is why layer 1 is the only lever", arguments: [
        "apple.com", "icloud.com", "mzstatic.com", "idmsa.apple.com", "updates.cdn-apple.com",
    ])
    func appleIsOutOfReach(host: String) {
        let set = BundledExclusions.makeSet()
        #expect(set.match(host: host) != nil)
    }

    @Test("An ordinary advertising host is not excluded", arguments: [
        "doubleclick.net", "ads.example.com", "googlesyndication.com",
    ])
    func advertisingIsNotExcluded(host: String) {
        let set = BundledExclusions.makeSet()
        #expect(set.match(host: host) == nil, "excluded by \(String(describing: set.match(host: host)))")
    }

    @Test("Windows-only entries are reported rather than silently absent")
    func windowsEntries() {
        let total = BundledExclusions.reports.values.reduce(0) { $0 + $1.notApplicableToMacOS }
        #expect(total >= 1)
    }

    @Test("Banks and sensitive data cannot be switched off")
    func hardLocks() {
        let locked = BundledExclusions.sources.filter { $0.lock == .hard }.map(\.id)
        #expect(locked.contains("adguard.banks"))
        #expect(locked.contains("adguard.sensitive"))
    }
}
