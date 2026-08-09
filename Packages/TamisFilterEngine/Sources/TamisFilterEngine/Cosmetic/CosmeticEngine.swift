import Foundation

/// What to apply to one page.
public struct CosmeticSet: Sendable, Equatable {
    /// Plain CSS selectors scoped to this site. Small enough to inline.
    public var specificSelectors: [String] = []
    /// Plain CSS selectors that apply everywhere.
    ///
    /// Kept apart because real lists carry tens of thousands of them, far too many to
    /// inline into every page. The injected runtime applies them against the document
    /// instead of the browser being handed a megabyte of stylesheet.
    public var genericSelectors: [String] = []
    /// Selectors a stylesheet cannot express — `:has-text()` and friends. Handed to
    /// the runtime.
    public var proceduralSelectors: [String] = []
    /// `#$#` style declarations, injected verbatim.
    public var styleRules: [String] = []
    /// `##+js()` invocations.
    public var scriptlets: [String] = []
    /// `##^` selectors, applied to the HTML stream before the browser parses it.
    public var htmlFilters: [String] = []

    public var isEmpty: Bool {
        specificSelectors.isEmpty && genericSelectors.isEmpty && proceduralSelectors.isEmpty
            && styleRules.isEmpty && scriptlets.isEmpty && htmlFilters.isEmpty
    }

    /// The stylesheet to inline for this page.
    ///
    /// `display: none !important` rather than `visibility` or a class: it removes the
    /// element from layout, which is what closes the hole a blocked advert leaves, and
    /// `!important` survives the inline styles ad frames set on themselves.
    public func inlineCSS() -> String {
        // Generic selectors are included only because the caller narrowed them to what
        // the document can actually match; unnarrowed they would be 216 KB per page.
        let hiding = specificSelectors + genericSelectors
        guard !hiding.isEmpty || !styleRules.isEmpty else { return "" }
        var css = ""
        if !hiding.isEmpty {
            css += hiding.joined(separator: ",\n") + " { display: none !important; }\n"
        }
        css += styleRules.joined(separator: "\n")
        return css
    }
}

/// Resolves which cosmetic rules apply to a given page.
public struct CosmeticEngine: Sendable {

    public struct Stats: Sendable, Equatable {
        public var rules = 0
        public var generic = 0
        public var specific = 0
        public var exceptions = 0
        public var procedural = 0
        public var scriptlets = 0
        public var htmlFilters = 0
    }

    /// Generic rules indexed by the class or id their selector leads with.
    ///
    /// Real lists carry over thirteen thousand of these, 216 KB of stylesheet if
    /// inlined into every page. Indexing them by token means a page receives only the
    /// handful that could possibly match the markup it actually contains.
    private var genericIndex: [String: [CosmeticRule]] = [:]
    /// Generic rules with no leading class or id — attribute selectors, bare tags.
    /// Few enough to always apply.
    private var genericUnkeyed: [CosmeticRule] = []
    private var genericRules: [CosmeticRule] = []
    /// Indexed by domain so a page consults a handful of rules, not all of them.
    private var specificRules: [String: [CosmeticRule]] = [:]
    private var exceptions: [CosmeticRule] = []
    public private(set) var stats = Stats()

    public init(rules lines: [String]) {
        for line in lines {
            guard let rule = CosmeticRule.parse(line) else { continue }
            stats.rules += 1

            switch rule.kind {
            case .unhide:
                exceptions.append(rule)
                stats.exceptions += 1
                continue
            case .scriptlet:  stats.scriptlets += 1
            case .htmlFilter: stats.htmlFilters += 1
            case .hide where rule.isProcedural: stats.procedural += 1
            default: break
            }

            if rule.includedDomains.isEmpty {
                genericRules.append(rule)
                if rule.kind == .hide, !rule.isProcedural,
                   let token = Self.primaryToken(of: rule.body) {
                    genericIndex[token, default: []].append(rule)
                } else {
                    genericUnkeyed.append(rule)
                }
                stats.generic += 1
            } else {
                for domain in rule.includedDomains {
                    specificRules[domain, default: []].append(rule)
                }
                stats.specific += 1
            }
        }
    }

    public init(rules text: String) {
        self.init(rules: text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init))
    }

    /// Everything that applies to a page served from `hostname`.
    ///
    /// - Parameter documentTokens: class and id names present in the document. When
    ///   supplied, generic rules are narrowed to those that could match the markup at
    ///   hand — the difference between a few hundred bytes and 216 KB per page. When
    ///   absent, every generic rule is returned.
    public func set(forHostname hostname: String, documentTokens: Set<String>? = nil) -> CosmeticSet {
        let host = hostname.lowercased()
        let candidates = Self.domainChain(of: host)

        // Exceptions first: a rule cancelled here must not be collected at all, since
        // an exception exists precisely because the hide broke that site.
        var cancelled = Set<String>()
        var cancelsEverything = false
        for exception in exceptions where Self.applies(exception, to: host, chain: candidates) {
            if exception.body == "*" {
                cancelsEverything = true
            } else {
                cancelled.insert(exception.body)
            }
        }
        if cancelsEverything { return CosmeticSet() }

        var result = CosmeticSet()

        for domain in candidates {
            guard let rules = specificRules[domain] else { continue }
            for rule in rules where Self.applies(rule, to: host, chain: candidates) {
                Self.add(rule, to: &result, cancelled: cancelled, isGeneric: false)
            }
        }
        if let documentTokens {
            for token in documentTokens {
                guard let rules = genericIndex[token] else { continue }
                for rule in rules where Self.applies(rule, to: host, chain: candidates) {
                    Self.add(rule, to: &result, cancelled: cancelled, isGeneric: true)
                }
            }
            for rule in genericUnkeyed where Self.applies(rule, to: host, chain: candidates) {
                Self.add(rule, to: &result, cancelled: cancelled, isGeneric: true)
            }
        } else {
            for rule in genericRules where Self.applies(rule, to: host, chain: candidates) {
                Self.add(rule, to: &result, cancelled: cancelled, isGeneric: true)
            }
        }

        return result
    }

    private static func add(
        _ rule: CosmeticRule,
        to result: inout CosmeticSet,
        cancelled: Set<String>,
        isGeneric: Bool
    ) {
        guard !cancelled.contains(rule.body) else { return }
        switch rule.kind {
        case .hide:
            if rule.isProcedural {
                result.proceduralSelectors.append(rule.body)
            } else if isGeneric {
                result.genericSelectors.append(rule.body)
            } else {
                result.specificSelectors.append(rule.body)
            }
        case .style:      result.styleRules.append(rule.body)
        case .scriptlet:  result.scriptlets.append(rule.body)
        case .htmlFilter: result.htmlFilters.append(rule.body)
        case .unhide:     break
        }
    }

    /// A rule applies when the host is covered by one of its domains and by none of
    /// its exclusions. Exclusions are checked first, so `example.com,~ads.example.com`
    /// spares the subdomain.
    static func applies(_ rule: CosmeticRule, to host: String, chain: [String]) -> Bool {
        if !rule.excludedDomains.isEmpty {
            for excluded in rule.excludedDomains where chain.contains(excluded) { return false }
        }
        guard !rule.includedDomains.isEmpty else { return true }
        return rule.includedDomains.contains { chain.contains($0) }
    }

    /// The class or id a selector leads with, which any element it matches must carry.
    ///
    /// `.ad-banner` and `div.promo > span` key on `ad-banner` and `promo`. A selector
    /// leading with an attribute or a bare tag has no such token and is always applied;
    /// there are few of those.
    static func primaryToken(of selector: String) -> String? {
        var index = selector.startIndex
        while index < selector.endIndex {
            let character = selector[index]
            guard character == "." || character == "#" else {
                index = selector.index(after: index)
                continue
            }
            var end = selector.index(after: index)
            while end < selector.endIndex, Self.isTokenCharacter(selector[end]) {
                end = selector.index(after: end)
            }
            let token = String(selector[selector.index(after: index)..<end])
            return token.isEmpty ? nil : token
        }
        return nil
    }

    static func isTokenCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber || character == "-" || character == "_"
            || character == "\\"
    }

    /// `a.b.example.com` → `[a.b.example.com, b.example.com, example.com, com]`, so a
    /// rule written for a domain also covers everything under it.
    static func domainChain(of host: String) -> [String] {
        var chain: [String] = []
        var start = host.startIndex
        while true {
            chain.append(String(host[start...]))
            guard let dot = host[start...].firstIndex(of: "."),
                  host.index(after: dot) < host.endIndex else { return chain }
            start = host.index(after: dot)
        }
    }
}
