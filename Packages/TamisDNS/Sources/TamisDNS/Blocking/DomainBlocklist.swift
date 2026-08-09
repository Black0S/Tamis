import Foundation

/// A set of domain rules gathered from hosts files and AdGuard-style DNS lists.
///
/// Matching walks from the most specific label upwards, so the closest rule wins:
/// `@@||cdn.example.com^` beats `||example.com^` for `cdn.example.com`, which is the
/// only behaviour that makes exception entries usable.
public struct DomainBlocklist: Sendable {

    public enum Decision: Sendable, Equatable {
        case block(matched: String)
        case allow(matched: String)
        case noMatch
    }

    public struct Stats: Sendable, Equatable {
        public var lines = 0
        public var comments = 0
        public var blockEntries = 0
        /// `.domain^` — subdomains only, the apex left alone.
        public var subdomainOnlyEntries = 0
        /// `://host^` — that exact host, nothing under it.
        public var exactOnlyEntries = 0
        /// Host patterns containing `*`, glob-matched against the queried name.
        public var wildcardEntries = 0
        public var allowEntries = 0
        public var badFilterEntries = 0
        public var removedByBadFilter = 0
        /// Rules that cannot be expressed at the DNS layer at all — regex filters over
        /// URLs, rules carrying a modifier that narrows them using information DNS does
        /// not have. Counted apart from ``skipped`` because these are not gaps in the
        /// parser: no DNS resolver can honour them.
        public var notApplicableToDNS = 0
        /// Lines that parsed as nothing usable — hosts boilerplate, host mappings
        /// pointing at a real address, malformed entries.
        public var skipped = 0
        /// A bounded sample of the skipped lines, so a list can be audited instead of
        /// trusted. Surfaced in the UI when a list contributes far fewer rules than
        /// its size suggests.
        public var skippedSamples: [String] = []

        static let maxSkippedSamples = 50
    }

    private let blocked: Set<String>
    /// Domains whose *subdomains* are blocked while the apex is not.
    private let blockedSubdomains: Set<String>
    /// Hosts blocked exactly, with nothing under them.
    private let blockedExact: Set<String>
    /// Glob patterns, filed under their longest wildcard-free suffix so they are only
    /// tested for queries that could plausibly match.
    private let wildcards: [String: [String]]
    private let allowed: Set<String>
    public let stats: Stats

    public var count: Int {
        blocked.count + blockedSubdomains.count + blockedExact.count
            + wildcards.values.reduce(0) { $0 + $1.count } + allowed.count
    }

    // MARK: Building

    public init(lines: [String]) {
        var blocked = Set<String>()
        var blockedSubdomains = Set<String>()
        var blockedExact = Set<String>()
        var wildcards: [String: [String]] = [:]
        var allowed = Set<String>()
        var cancelled = Set<String>()
        var stats = Stats()

        for line in lines {
            stats.lines += 1
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("#") || trimmed.hasPrefix("!") {
                stats.comments += 1
                continue
            }

            // `$badfilter` cancels the identical rule from every loaded list, so it is
            // resolved after everything has been read rather than in place.
            if let target = Self.badFilterTarget(trimmed) {
                stats.badFilterEntries += 1
                cancelled.insert(target)
                continue
            }

            switch Self.parse(trimmed) {
            case .block(let domain):
                blocked.insert(domain)
                stats.blockEntries += 1
            case .blockSubdomains(let domain):
                blockedSubdomains.insert(domain)
                stats.subdomainOnlyEntries += 1
            case .blockExact(let domain):
                blockedExact.insert(domain)
                stats.exactOnlyEntries += 1
            case .blockWildcard(let pattern, let anchor):
                wildcards[anchor, default: []].append(pattern)
                stats.wildcardEntries += 1
            case .allow(let domain):
                allowed.insert(domain)
                stats.allowEntries += 1
            case .notApplicable:
                stats.notApplicableToDNS += 1
            case .none:
                stats.skipped += 1
                if stats.skippedSamples.count < Stats.maxSkippedSamples {
                    stats.skippedSamples.append(trimmed)
                }
            }
        }

        for domain in cancelled {
            var removed = false
            if blocked.remove(domain) != nil { removed = true }
            if blockedSubdomains.remove(domain) != nil { removed = true }
            if blockedExact.remove(domain) != nil { removed = true }
            if allowed.remove(domain) != nil { removed = true }
            if removed { stats.removedByBadFilter += 1 }
        }

        self.blocked = blocked
        self.blockedSubdomains = blockedSubdomains
        self.blockedExact = blockedExact
        self.wildcards = wildcards
        self.allowed = allowed
        self.stats = stats
    }

    public init(
        blocking domains: [String],
        blockingSubdomainsOf subdomainDomains: [String] = [],
        blockingExactly exactDomains: [String] = [],
        allowing allowedDomains: [String] = []
    ) {
        self.blocked = Set(domains.map { $0.lowercased() })
        self.blockedSubdomains = Set(subdomainDomains.map { $0.lowercased() })
        self.blockedExact = Set(exactDomains.map { $0.lowercased() })
        self.wildcards = [:]
        self.allowed = Set(allowedDomains.map { $0.lowercased() })
        self.stats = Stats()
    }

    enum Entry {
        case block(String)
        case blockSubdomains(String)
        case blockExact(String)
        case blockWildcard(pattern: String, anchor: String)
        case allow(String)
        /// Expressible in a filter list, but not at the DNS layer.
        case notApplicable
        case none
    }

    /// The domain a `$badfilter` rule cancels, or `nil` if this is not one.
    static func badFilterTarget(_ line: String) -> String? {
        guard line.contains("$badfilter") else { return nil }
        let stripped = line
            .replacingOccurrences(of: ",badfilter", with: "")
            .replacingOccurrences(of: "$badfilter", with: "")
        switch parse(stripped) {
        case .block(let d), .blockSubdomains(let d), .blockExact(let d), .allow(let d): return d
        case .blockWildcard, .notApplicable, .none: return nil
        }
    }

    /// Recognises the three shapes that make up real DNS lists.
    static func parse(_ line: String) -> Entry {
        // A cosmetic rule has to be recognised *before* the comment is stripped, and
        // getting that order wrong is not a small mistake. `lemonde.fr##.dfp__container`
        // hides one element on one newspaper; cut at the first `#` and it becomes a
        // bare domain, which reads as a DNS block of the whole site. EasyList carries
        // fifteen thousand of these, so the order below decides between an ad blocker
        // and an outage.
        if isCosmeticRule(line) { return .notApplicable }

        // Strip an inline comment, which hosts files use freely.
        let withoutComment = line.split(separator: "#", maxSplits: 1).first.map(String.init) ?? line
        let text = withoutComment.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return .none }

        // 0. A regex filter matches URLs, not names. No DNS resolver can honour it.
        if text.hasPrefix("/"), text.hasSuffix("/"), text.count > 2 { return .notApplicable }

        // 1. AdGuard DNS syntax: ||domain^ and @@||domain^
        if text.hasPrefix("@@") {
            guard let domain = adguardDomain(text.dropFirst(2)) else { return .notApplicable }
            return .allow(domain)
        }
        if text.hasPrefix("||") {
            guard let domain = adguardDomain(Substring(text)) else { return .notApplicable }
            return .block(domain)
        }

        // 1b. `://host^` — in a URL, `://` sits immediately before the host, so this
        //     matches that host and nothing under it: `https://sub.example.com/` does
        //     not contain `://example.com`. Exact host, no subdomains.
        if text.hasPrefix("://"), text.hasSuffix("^") {
            guard let domain = plainDomain(String(text.dropFirst(3).dropLast())) else { return .notApplicable }
            return .blockExact(domain)
        }

        // 1c. Wildcard host patterns: `-adx-*.rayjump.com^`, `|c.blue.*.com^|`.
        //     A `*` inside a hostname cannot be answered from a set lookup, but DNS
        //     does carry the full queried name, so these are expressible — they are
        //     anchored on their longest wildcard-free suffix and glob-matched.
        if text.hasSuffix("^") || text.hasSuffix("^|") {
            var host = Substring(text)
            if host.hasSuffix("|") { host = host.dropLast() }
            host = host.dropLast()                       // the `^`
            if host.hasPrefix("|") { host = host.dropFirst() }
            if host.contains("*"), host.contains("."), !host.contains("/") {
                let candidate = host.lowercased()
                if let anchor = wildcardAnchor(candidate) {
                    return .blockWildcard(pattern: candidate, anchor: anchor)
                }
            }
        }

        // 2. Leading-dot form: `.example.com^` covers subdomains but not the apex,
        //    which lists state separately with `||example.com^` when they mean both.
        //    Entries that are really filename patterns (`.n.2.1.js^`) parse as inert
        //    rules that no real query can match, rather than over-blocking anything.
        if text.hasPrefix("."), text.hasSuffix("^") {
            guard let domain = plainDomain(String(text.dropFirst().dropLast())) else { return .none }
            return .blockSubdomains(domain)
        }

        // 2. Hosts format: `0.0.0.0 domain` — only sinkhole addresses count. An entry
        //    pointing at a real address is a genuine host mapping, not a block.
        let fields = text.split(whereSeparator: \.isWhitespace)
        if fields.count >= 2 {
            let address = String(fields[0])
            guard address == "0.0.0.0" || address == "127.0.0.1" || address == "::"
                    || address == "::1" else { return .none }
            guard let domain = plainDomain(String(fields[1])) else { return .none }
            return .block(domain)
        }

        // 3. A bare domain on its own line — or, if it is not a valid domain, a URL
        //    substring pattern such as `-banner-ads.` or `-ad123-`, which matches
        //    inside a path and has no DNS equivalent.
        if fields.count == 1 {
            if let domain = plainDomain(String(fields[0])) { return .block(domain) }
            return .notApplicable
        }
        return .none
    }

    /// Modifiers that do not restrict *which requests* a rule covers, and are
    /// therefore safe to ignore at the DNS layer.
    ///
    /// Everything else — `$third-party`, `$app`, `$denyallow`, request types — narrows
    /// the rule using information DNS does not have. Honouring such a rule without its
    /// modifier would block far more than its author intended, so the rule is dropped
    /// instead. Same principle as the network engine, opposite direction of caution
    /// from simply "ignore what you don't know".
    static let harmlessModifiers: Set<String> = ["important"]

    /// Extracts the domain from `||domain^`, refusing anything carrying a narrowing
    /// modifier or a path — those are network rules, not DNS rules.
    static func adguardDomain(_ text: Substring) -> String? {
        guard text.hasPrefix("||") else { return nil }
        var body = text.dropFirst(2)

        if let caret = body.firstIndex(of: "^") {
            var rest = body[body.index(after: caret)...]
            body = body[..<caret]

            if rest.hasPrefix("$") {
                rest = rest.dropFirst()
                let names = rest.split(separator: ",").map {
                    $0.trimmingCharacters(in: .whitespaces).lowercased()
                }
                guard names.allSatisfy({ harmlessModifiers.contains($0) }) else { return nil }
            } else if !rest.isEmpty {
                return nil   // a path, a wildcard, anything else
            }
        }
        return plainDomain(String(body))
    }

    /// The longest wildcard-free suffix of a host pattern, used to file it under a
    /// domain so it is only tested for queries that could plausibly match.
    ///
    /// `-adx-*.rayjump.com` anchors on `rayjump.com`; `c.blue.*.com` anchors on `com`.
    static func wildcardAnchor(_ pattern: String) -> String? {
        let labels = pattern.split(separator: ".", omittingEmptySubsequences: false)
        var suffix: [Substring] = []
        for label in labels.reversed() {
            if label.contains("*") { break }
            suffix.insert(label, at: 0)
        }
        guard !suffix.isEmpty else { return nil }
        return suffix.joined(separator: ".")
    }

    /// Glob match where `*` stands for any run of characters, including none.
    ///
    /// Iterative with a single backtrack point rather than recursive: patterns come
    /// from downloaded lists, and a recursive matcher on `a*a*a*a*…` is a denial of
    /// service waiting to be published.
    static func globMatches(_ pattern: String, _ text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0
        var starIndex = -1, matchIndex = 0

        while ti < t.count {
            if pi < p.count, p[pi] == "*" {
                starIndex = pi
                matchIndex = ti
                pi += 1
            } else if pi < p.count, p[pi] == t[ti] {
                pi += 1
                ti += 1
            } else if starIndex >= 0 {
                pi = starIndex + 1
                matchIndex += 1
                ti = matchIndex
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }

    /// Whether a line is a cosmetic rule rather than anything a resolver can act on.
    ///
    /// The separator is a `#` followed by one of `#@?$%`, with a domain in front of it:
    /// `##`, `#@#`, `#?#`, `#$#`, `#%#` and their exception forms. A hosts-file comment
    /// (`0.0.0.0 host # note`) is a `#` followed by an ordinary character, and a
    /// full-line comment starts at position zero, so neither is caught here.
    ///
    /// `$$` and `$@$` — AdGuard's HTML filtering — carry no `#` at all, and are refused
    /// downstream by ``plainDomain``, which allows no character a host name cannot have.
    static func isCosmeticRule(_ line: String) -> Bool {
        var index = line.startIndex
        while let hash = line[index...].firstIndex(of: "#") {
            guard hash > line.startIndex else { return false }   // a full-line comment
            let next = line.index(after: hash)
            guard next < line.endIndex else { return false }
            if "#@?$%".contains(line[next]) { return true }
            index = next
        }
        return false
    }

    static func plainDomain(_ text: String) -> String? {
        let domain = text.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !domain.isEmpty, domain.count <= 253 else { return nil }
        // Nothing that cannot appear in a host name. Filter syntax leaks in through
        // more shapes than are worth enumerating one at a time — `$$`, `[]`, `^`, `|` —
        // and every one of them, read as a domain, is either inert or an outage.
        // Non-ASCII passes: hosts files do carry internationalised names.
        guard !domain.unicodeScalars.contains(where: { scalar in
            scalar.isASCII && !(scalar.properties.isAlphabetic || ("0"..."9").contains(scalar)
                                || scalar == "." || scalar == "-" || scalar == "_")
        }) else { return nil }
        // `localhost` and friends appear at the top of every hosts file and must not
        // become blocking rules.
        if domain == "localhost" || domain == "localhost.localdomain"
            || domain == "broadcasthost" || domain == "local" { return nil }
        guard !domain.contains("/"), !domain.contains("*"), !domain.contains(" ") else { return nil }
        guard domain.contains(".") else { return nil }
        return domain
    }

    // MARK: Matching

    /// The most specific rule covering `name`, walking up the label hierarchy.
    public func decision(for name: String) -> Decision {
        guard !blocked.isEmpty || !blockedSubdomains.isEmpty || !blockedExact.isEmpty
                || !wildcards.isEmpty || !allowed.isEmpty else { return .noMatch }
        let host = name.lowercased()

        var start = host.startIndex
        var isQueriedName = true
        while true {
            let candidate = String(host[start...])
            if allowed.contains(candidate) { return .allow(matched: candidate) }
            if blocked.contains(candidate) { return .block(matched: candidate) }
            // An exact rule fires only on the queried name itself.
            if isQueriedName, blockedExact.contains(candidate) {
                return .block(matched: "://" + candidate)
            }
            // Guarded: most lists carry no wildcard rule at all, and a dictionary
            // lookup per label on every query is not free.
            if !wildcards.isEmpty, let patterns = wildcards[candidate] {
                for pattern in patterns where Self.globMatches(pattern, host) {
                    return .block(matched: pattern)
                }
            }
            // A subdomain-only rule must not fire on the apex itself, which is exactly
            // what distinguishes `.example.com^` from `||example.com^`.
            if !isQueriedName, blockedSubdomains.contains(candidate) {
                return .block(matched: "." + candidate)
            }
            guard let dot = host[start...].firstIndex(of: "."),
                  host.index(after: dot) < host.endIndex else { return .noMatch }
            start = host.index(after: dot)
            isQueriedName = false
        }
    }
}
