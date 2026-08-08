import Testing
@testable import TamisDNS

@Suite("Domain blocklist")
struct DomainBlocklistTests {

    @Test("hosts entries are only blocks when they point at a sinkhole")
    func hostsFormat() {
        let list = DomainBlocklist(lines: [
            "0.0.0.0 ads.example.com",
            "127.0.0.1 tracker.example.com",
            ":: ipv6.example.com",
            // A real host mapping, not a block — the user is naming a machine.
            "192.168.1.10 nas.home.lan",
        ])
        #expect(list.decision(for: "ads.example.com") == .block(matched: "ads.example.com"))
        #expect(list.decision(for: "tracker.example.com") == .block(matched: "tracker.example.com"))
        #expect(list.decision(for: "ipv6.example.com") == .block(matched: "ipv6.example.com"))
        #expect(list.decision(for: "nas.home.lan") == .noMatch)
    }

    @Test("the boilerplate at the top of every hosts file is ignored")
    func hostsBoilerplate() {
        let list = DomainBlocklist(lines: [
            "# Standard host addresses",
            "127.0.0.1 localhost",
            "255.255.255.255 broadcasthost",
            "::1 localhost",
            "0.0.0.0 real-ad.example",
        ])
        #expect(list.decision(for: "localhost") == .noMatch)
        #expect(list.decision(for: "broadcasthost") == .noMatch)
        #expect(list.decision(for: "real-ad.example") == .block(matched: "real-ad.example"))
        #expect(list.stats.blockEntries == 1)
    }

    @Test("AdGuard DNS syntax is accepted, network-only rules are not")
    func adguardSyntax() {
        let list = DomainBlocklist(lines: [
            "||ads.example.com^",
            "||tracker.example.org",
            "@@||safe.ads.example.com^",
            // Carries modifiers or a path: a network rule, not a DNS rule. Applying it
            // at the DNS layer would block far more than its author intended.
            "||cdn.example.com^$third-party",
            "||example.com/ads/",
        ])
        #expect(list.decision(for: "ads.example.com") == .block(matched: "ads.example.com"))
        #expect(list.decision(for: "tracker.example.org") == .block(matched: "tracker.example.org"))
        #expect(list.decision(for: "cdn.example.com") == .noMatch)
        // Not parser gaps: a modifier DNS cannot evaluate, and a path-bearing rule.
        #expect(list.stats.notApplicableToDNS == 2)
        #expect(list.stats.skipped == 0)
    }

    /// A modifier that does not restrict *which requests* a rule covers is safe to
    /// ignore at the DNS layer; one that narrows the rule using information DNS does
    /// not have is not. Dropping the second kind loses a block, honouring it would
    /// block far more than its author intended.
    @Test("only non-narrowing modifiers are tolerated", arguments: [
        ("||ads.example.com^$important", true),
        ("||ads.example.com^$third-party", false),
        ("||ads.example.com^$app=com.example.app", false),
        ("||ads.example.com^$denyallow=cdn.example.com", false),
        ("||ads.example.com^$important,third-party", false),
    ])
    func modifierTolerance(rule: String, shouldBlock: Bool) {
        let list = DomainBlocklist(lines: [rule])
        let blocked = list.decision(for: "ads.example.com") != .noMatch
        #expect(blocked == shouldBlock)
    }

    @Test("matching walks up the labels, so subdomains inherit")
    func subdomainInheritance() {
        let list = DomainBlocklist(lines: ["||doubleclick.net^"])
        #expect(list.decision(for: "doubleclick.net") == .block(matched: "doubleclick.net"))
        #expect(list.decision(for: "ads.g.doubleclick.net") == .block(matched: "doubleclick.net"))
        // A different registrable domain that merely ends with the same letters.
        #expect(list.decision(for: "notdoubleclick.net") == .noMatch)
    }

    @Test("the most specific rule wins, so an exception can carve out a subdomain")
    func mostSpecificWins() {
        let list = DomainBlocklist(lines: [
            "||example.com^",
            "@@||cdn.example.com^",
        ])
        #expect(list.decision(for: "example.com") == .block(matched: "example.com"))
        #expect(list.decision(for: "ads.example.com") == .block(matched: "example.com"))
        #expect(list.decision(for: "cdn.example.com") == .allow(matched: "cdn.example.com"))
        // The exception is inherited downwards too.
        #expect(list.decision(for: "img.cdn.example.com") == .allow(matched: "cdn.example.com"))
    }

    /// `.example.com^` and `||example.com^` are different rules, and real lists carry
    /// both for the same domain — which is the evidence that the leading dot means
    /// "subdomains, not the apex".
    @Test("the leading-dot form covers subdomains but spares the apex")
    func subdomainOnlyForm() {
        let list = DomainBlocklist(lines: [".bbelements.com^"])
        #expect(list.decision(for: "www.bbelements.com") == .block(matched: ".bbelements.com"))
        #expect(list.decision(for: "a.b.bbelements.com") == .block(matched: ".bbelements.com"))
        #expect(list.decision(for: "bbelements.com") == .noMatch)
        #expect(list.stats.subdomainOnlyEntries == 1)
    }

    /// In a URL, `://` sits immediately before the host, so `://example.com^` cannot
    /// match `https://sub.example.com/` — there are characters in between. The rule
    /// therefore means the exact host and nothing under it.
    @Test("the ://host^ form blocks the exact host, not its subdomains")
    func exactHostForm() {
        let list = DomainBlocklist(lines: ["://mine.torrent.pw^"])
        #expect(list.decision(for: "mine.torrent.pw") == .block(matched: "://mine.torrent.pw"))
        #expect(list.decision(for: "www.mine.torrent.pw") == .noMatch)
        #expect(list.stats.exactOnlyEntries == 1)
    }

    @Test("the three block scopes do not bleed into one another")
    func scopesAreDistinct() {
        let list = DomainBlocklist(
            blocking: ["all.example"],
            blockingSubdomainsOf: ["sub.example"],
            blockingExactly: ["exact.example"]
        )
        // ||all.example^ — apex and everything under it.
        #expect(list.decision(for: "all.example") != .noMatch)
        #expect(list.decision(for: "x.all.example") != .noMatch)
        // .sub.example^ — subdomains only.
        #expect(list.decision(for: "sub.example") == .noMatch)
        #expect(list.decision(for: "x.sub.example") != .noMatch)
        // ://exact.example^ — that host alone.
        #expect(list.decision(for: "exact.example") != .noMatch)
        #expect(list.decision(for: "x.exact.example") == .noMatch)
    }

    /// A `*` inside a hostname defeats a set lookup, but DNS carries the full queried
    /// name, so these rules are expressible — anchored on their longest wildcard-free
    /// suffix so they are only tested for queries that could plausibly match.
    @Test("wildcard host patterns are matched against the queried name")
    func wildcardHosts() {
        let list = DomainBlocklist(lines: ["-adx-*.rayjump.com^", "|c.blue.*.com^|"])
        #expect(list.decision(for: "-adx-eu.rayjump.com") == .block(matched: "-adx-*.rayjump.com"))
        #expect(list.decision(for: "-adx-.rayjump.com") == .block(matched: "-adx-*.rayjump.com"))
        #expect(list.decision(for: "cdn.rayjump.com") == .noMatch)
        #expect(list.decision(for: "c.blue.tracker.com") == .block(matched: "c.blue.*.com"))
        #expect(list.stats.wildcardEntries == 2)
    }

    @Test("glob matching does not backtrack itself to death", arguments: [
        ("a*b", "ab", true),
        ("a*b", "axxxb", true),
        ("a*b", "ba", false),
        ("*", "anything", true),
        ("a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false),
    ])
    func globSemantics(pattern: String, text: String, expected: Bool) {
        #expect(DomainBlocklist.globMatches(pattern, text) == expected)
    }

    @Test("$badfilter cancels the identical rule, wherever it was declared")
    func badFilter() {
        let list = DomainBlocklist(lines: [
            "||tracker.example^",
            "0.0.0.0 ads.example",
            "||tracker.example^$badfilter",
            "ads.example$badfilter",
        ])
        #expect(list.decision(for: "tracker.example") == .noMatch)
        #expect(list.decision(for: "ads.example") == .noMatch)
        #expect(list.stats.badFilterEntries == 2)
        #expect(list.stats.removedByBadFilter == 2)
    }

    /// Separated from `skipped` on purpose: these are not parser gaps. A regex over
    /// URLs, or a rule narrowed by information DNS does not carry, cannot be honoured
    /// by any DNS resolver.
    @Test("rules that DNS structurally cannot express are counted apart")
    func notApplicableAreCountedApart() {
        let list = DomainBlocklist(lines: [
            #"/^139\.45\.197\.2(4[0-9]|5[0-4]):/"#,
            "||cdn.example.com^$third-party",
            "0.0.0.0 real-ad.example",
        ])
        #expect(list.stats.notApplicableToDNS == 2)
        #expect(list.stats.skipped == 0)
        #expect(list.stats.blockEntries == 1)
    }

    @Test("inline comments are stripped")
    func inlineComments() {
        let list = DomainBlocklist(lines: ["0.0.0.0 ads.example.com # analytics"])
        #expect(list.decision(for: "ads.example.com") == .block(matched: "ads.example.com"))
    }
}

@Suite("Resolver policy")
struct ResolverPolicyTests {

    @Test("the user's blocklist is applied")
    func userBlocklist() {
        let policy = ResolverPolicy(blocklist: DomainBlocklist(blocking: ["doubleclick.net"]))
        #expect(policy.outcome(forName: "ads.doubleclick.net") == .block(reason: .blocklist(matched: "doubleclick.net")))
        #expect(policy.outcome(forName: "example.com") == .forward)
    }

    /// The self-lockout guard. A list containing `raw.githubusercontent.com` would
    /// otherwise stop Tamis from ever updating its lists — or itself — permanently,
    /// with no way for the user to work out why.
    @Test("Tamis's own domains are unblockable")
    func systemAllowlistWins() {
        let hostile = DomainBlocklist(blocking: [
            "raw.githubusercontent.com", "api.github.com", "cloudflare-dns.com",
        ])
        let policy = ResolverPolicy(blocklist: hostile)
        #expect(policy.outcome(forName: "raw.githubusercontent.com") == .forward)
        #expect(policy.outcome(forName: "api.github.com") == .forward)
        #expect(policy.outcome(forName: "cloudflare-dns.com") == .forward)
    }

    @Test("the Firefox canary is answered NXDOMAIN so Firefox disables its own DoH")
    func firefoxCanary() {
        let policy = ResolverPolicy(blocklist: DomainBlocklist(blocking: []))
        #expect(policy.outcome(forName: "use-application-dns.net") == .block(reason: .firefoxCanary))
        #expect(policy.outcome(forName: "sub.use-application-dns.net") == .block(reason: .firefoxCanary))
    }

    @Test("the canary can be turned off without touching the blocklist")
    func canaryOptOut() {
        let policy = ResolverPolicy(blocklist: DomainBlocklist(blocking: []), blocksFirefoxCanary: false)
        #expect(policy.outcome(forName: "use-application-dns.net") == .forward)
    }
}
