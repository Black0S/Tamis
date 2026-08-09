import Foundation

/// The `$…` modifiers of a network rule.
///
/// Split into two families:
/// - **matching** modifiers narrow *when* the rule applies (types, `$domain=`,
///   `$third-party`, `$method=`). They are evaluated by ``NetworkRule/matches(_:)``.
/// - **action** modifiers change *what happens* on a match (`$redirect`, `$csp`,
///   `$removeparam`, …). They are parsed and carried here, but applied downstream by
///   the proxy — the engine's job is only to decide.
public struct RuleOptions: Sendable, Equatable {

    // MARK: Matching

    public var types: RequestTypeSet = .defaultForRules
    /// `nil` means the rule is indifferent to party.
    public var thirdParty: Bool?
    /// `$domain=a.com|b.com` — the *document* domain must match one of these.
    public var includedDomains: [String] = []
    /// `$domain=~a.com` — never applies when the document domain matches.
    public var excludedDomains: [String] = []
    /// `$denyallow=` — the rule does not apply when the *request* domain matches.
    public var denyAllowDomains: [String] = []
    public var includedMethods: Set<String> = []
    public var excludedMethods: Set<String> = []
    public var matchCase = false

    // MARK: Precedence

    /// `$important` — beats exception rules.
    public var isImportant = false
    /// `$badfilter` — removes an identical rule from every loaded list.
    public var isBadFilter = false

    // MARK: Action (carried, not applied here)

    public var redirect: String?
    public var redirectRule: String?
    public var removeParam: String?
    public var csp: String?
    public var header: String?
    public var replace: String?
    public var permissions: String?
    public var urlTransform: String?

    /// Modifiers the parser did not recognise.
    ///
    /// Kept rather than discarded so a list's real coverage can be reported instead of
    /// guessed — the spec calls for counting what we skip, not pretending it is zero.
    public var unsupported: [String] = []

    /// Whether this rule answers the question "does this request happen?" at all.
    ///
    /// Most of the action modifiers do not. `$csp`, `$permissions`, `$removeparam`,
    /// `$replace` and `$urltransform` alter the request or the response and let it
    /// through; `$redirect-rule` acts only when some *other* rule blocks. Matching them
    /// as blocks is not a small error — EasyList carries
    /// `*$permissions=compute-pressure=(),from=~localhost|…`, whose pattern is `*`, and
    /// reading that as a block stops the entire web.
    ///
    /// `$header` genuinely blocks, but on a condition read from the response, which is
    /// not available when the request is decided. Applying it anyway would widen it
    /// from "block when this header is present" to "block always" — the same reasoning
    /// that drops rules with unrecognised modifiers.
    ///
    /// `$redirect` is deliberately absent: it blocks the request and substitutes a
    /// resource, so it is a block.
    public var changesRatherThanBlocks: Bool {
        csp != nil || permissions != nil || removeParam != nil || replace != nil
            || urlTransform != nil || redirectRule != nil || header != nil
    }

    public init() {}
}

// MARK: - Parsing

extension RuleOptions {

    /// Parses the modifier string that follows `$`.
    public static func parse(_ raw: String) -> RuleOptions {
        var options = RuleOptions()
        var explicitTypes: RequestTypeSet = []
        var negatedTypes: RequestTypeSet = []

        for item in splitOnUnescapedCommas(raw) {
            let piece = item.trimmingCharacters(in: .whitespaces)
            guard !piece.isEmpty else { continue }

            var negated = false
            var body = Substring(piece)
            if body.hasPrefix("~") {
                negated = true
                body = body.dropFirst()
            }

            let name: String
            let value: String?
            if let eq = body.firstIndex(of: "=") {
                name = String(body[body.startIndex..<eq]).lowercased()
                value = String(body[body.index(after: eq)...])
            } else {
                name = String(body).lowercased()
                value = nil
            }

            if let type = RequestTypeSet.named(name), value == nil {
                if negated { negatedTypes.insert(type) } else { explicitTypes.insert(type) }
                continue
            }

            switch (name, value) {
            case ("third-party", nil), ("3p", nil):
                options.thirdParty = !negated
            case ("first-party", nil), ("1p", nil):
                options.thirdParty = negated
            case ("strict1p", nil):
                options.thirdParty = false
            case ("strict3p", nil):
                options.thirdParty = true
            case ("all", nil):
                explicitTypes.formUnion(.all)
            case ("match-case", nil):
                options.matchCase = !negated
            case ("important", nil):
                options.isImportant = true
            case ("badfilter", nil):
                options.isBadFilter = true

            case ("domain", let v?), ("from", let v?):
                let (included, excluded) = splitNegatable(v)
                options.includedDomains = included
                options.excludedDomains = excluded
            case ("denyallow", let v?):
                options.denyAllowDomains = splitNegatable(v).included
            case ("method", let v?):
                let (included, excluded) = splitNegatable(v)
                options.includedMethods = Set(included.map { $0.uppercased() })
                options.excludedMethods = Set(excluded.map { $0.uppercased() })

            case ("redirect", let v):          options.redirect = v ?? ""
            case ("redirect-rule", let v):     options.redirectRule = v ?? ""
            case ("removeparam", let v):       options.removeParam = v ?? ""
            case ("csp", let v):               options.csp = v ?? ""
            case ("header", let v):            options.header = v ?? ""
            case ("replace", let v):           options.replace = v ?? ""
            case ("permissions", let v):       options.permissions = v ?? ""
            case ("urltransform", let v):      options.urlTransform = v ?? ""

            default:
                options.unsupported.append(piece)
            }
        }

        // Positive types, when present, define the set exactly. Otherwise the default
        // set applies and negations carve out of it.
        if !explicitTypes.isEmpty {
            options.types = explicitTypes.subtracting(negatedTypes)
        } else if !negatedTypes.isEmpty {
            options.types = RequestTypeSet.defaultForRules.subtracting(negatedTypes)
        }

        return options
    }

    /// Splits on `,` while honouring `\,` escapes, which appear inside `$replace` and
    /// `$removeparam` values.
    static func splitOnUnescapedCommas(_ s: String) -> [String] {
        var parts: [String] = []
        var current = ""
        var escaped = false
        for ch in s {
            if escaped {
                current.append(ch)
                escaped = false
            } else if ch == "\\" {
                current.append(ch)
                escaped = true
            } else if ch == "," {
                parts.append(current)
                current = ""
            } else {
                current.append(ch)
            }
        }
        parts.append(current)
        return parts
    }

    /// Splits a `a|~b|c` value into its positive and negated halves.
    static func splitNegatable(_ value: String) -> (included: [String], excluded: [String]) {
        var included: [String] = []
        var excluded: [String] = []
        for entry in value.split(separator: "|") {
            let text = entry.trimmingCharacters(in: .whitespaces).lowercased()
            guard !text.isEmpty else { continue }
            if text.hasPrefix("~") {
                excluded.append(String(text.dropFirst()))
            } else {
                included.append(text)
            }
        }
        return (included, excluded)
    }
}

// MARK: - Domain scoping

extension RuleOptions {

    /// Whether a rule scoped by `$domain=` applies to this document domain.
    ///
    /// Entries match the domain itself and any subdomain, and exclusions are checked
    /// first because `$domain=example.com|~ads.example.com` must reject the subdomain.
    func domainScopeAllows(hostname: String?) -> Bool {
        if includedDomains.isEmpty && excludedDomains.isEmpty { return true }
        guard let hostname, !hostname.isEmpty else {
            // A rule scoped to specific documents cannot fire without knowing the
            // document — unless it only lists exclusions, which then cannot apply.
            return includedDomains.isEmpty
        }
        if excludedDomains.contains(where: { Self.hostMatches(hostname, suffix: $0) }) { return false }
        if includedDomains.isEmpty { return true }
        return includedDomains.contains { Self.hostMatches(hostname, suffix: $0) }
    }

    func denyAllowAllows(requestHostname: String) -> Bool {
        guard !denyAllowDomains.isEmpty else { return true }
        return !denyAllowDomains.contains { Self.hostMatches(requestHostname, suffix: $0) }
    }

    /// `host == suffix`, or `host` ends with `.suffix`.
    static func hostMatches(_ host: String, suffix: String) -> Bool {
        if host == suffix { return true }
        return host.count > suffix.count
            && host.hasSuffix(suffix)
            && host[host.index(host.endIndex, offsetBy: -suffix.count - 1)] == "."
    }
}
