import Foundation

/// One parsed network filtering rule.
public struct NetworkRule: Sendable {
    /// The original line, kept so the UI can show exactly which rule fired.
    public let raw: String
    public let pattern: URLPattern
    public let options: RuleOptions
    /// `@@` — an allow rule, which cancels blocking rules.
    public let isException: Bool

    public var indexToken: String? { pattern.indexToken }
    public var isImportant: Bool { options.isImportant }
    public var isBadFilter: Bool { options.isBadFilter }

    public init(raw: String, pattern: URLPattern, options: RuleOptions, isException: Bool) {
        self.raw = raw
        self.pattern = pattern
        self.options = options
        self.isException = isException
    }

    // MARK: Parsing

    /// Parses one line, or returns `nil` if it is not a network rule.
    ///
    /// Blank lines, comments and cosmetic rules are *not* errors — they simply belong
    /// to another parser — so they come back as `nil` rather than throwing.
    public static func parse(_ line: String) throws -> NetworkRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        // `!` and `[Adblock Plus 2.0]` headers are comments.
        if trimmed.hasPrefix("!") || trimmed.hasPrefix("[") { return nil }
        // Cosmetic rules: ## #@# #$# #%# and the HTML variant ##^
        if trimmed.contains("##") || trimmed.contains("#@#")
            || trimmed.contains("#$#") || trimmed.contains("#%#") { return nil }

        var body = Substring(trimmed)
        var isException = false
        if body.hasPrefix("@@") {
            isException = true
            body = body.dropFirst(2)
        }

        let (patternText, optionText) = splitPatternAndOptions(String(body))
        guard !patternText.isEmpty || optionText != nil else { throw FilterParseError.emptyPattern }

        let options = optionText.map(RuleOptions.parse) ?? RuleOptions()
        // A rule reduced to nothing but modifiers (`$domain=x.com`) matches every URL.
        let pattern = try URLPattern(patternText.isEmpty ? "*" : patternText)

        return NetworkRule(raw: trimmed, pattern: pattern, options: options, isException: isException)
    }

    /// Finds the `$` that introduces modifiers.
    ///
    /// `$` is legal inside a pattern — regular expressions use it as an end anchor, and
    /// `$replace=` values contain it. Rather than guess, candidates are tried from the
    /// right and the first one whose tail actually parses as a modifier list wins.
    static func splitPatternAndOptions(_ line: String) -> (pattern: String, options: String?) {
        let chars = Array(line)
        var index = chars.count - 1
        // Position 0 is included: `$domain=example.com` is a valid rule whose pattern
        // is empty and which therefore matches every URL.
        while index >= 0 {
            if chars[index] == "$" && (index == 0 || chars[index - 1] != "\\") {
                let tail = String(chars[(index + 1)...])
                if looksLikeOptionList(tail) {
                    return (String(chars[..<index]), tail)
                }
            }
            index -= 1
        }
        return (line, nil)
    }

    /// Whether a string is plausibly a modifier list: every comma-separated entry
    /// starts with an optional `~` then a `[a-z0-9-]` name.
    static func looksLikeOptionList(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        for item in RuleOptions.splitOnUnescapedCommas(s) {
            var entry = Substring(item.trimmingCharacters(in: .whitespaces))
            if entry.hasPrefix("~") { entry = entry.dropFirst() }
            guard let first = entry.first, first.isLetter else { return false }
            let name = entry.prefix { $0.isLetter || $0.isNumber || $0 == "-" }
            guard !name.isEmpty else { return false }
            let rest = entry.dropFirst(name.count)
            if !rest.isEmpty && !rest.hasPrefix("=") { return false }
        }
        return true
    }

    // MARK: Matching

    /// Whether this rule applies to `request`.
    ///
    /// Ordered cheapest-first: a bitmask test, then integer/string comparisons, and
    /// only then the pattern scan. On a hot path that runs across every candidate rule
    /// of every request, that ordering matters more than any micro-optimisation inside
    /// the scan itself.
    public func matches(_ request: Request) -> Bool {
        guard options.types.contains(request.type) else { return false }

        if let wantsThirdParty = options.thirdParty, wantsThirdParty != request.isThirdParty {
            return false
        }

        if !options.includedMethods.isEmpty, !options.includedMethods.contains(request.method) {
            return false
        }
        if options.excludedMethods.contains(request.method) { return false }

        guard options.domainScopeAllows(hostname: request.sourceHostname) else { return false }
        guard options.denyAllowAllows(requestHostname: request.hostname) else { return false }

        return pattern.matches(
            url: request.urlBytes,
            urlString: request.url,
            hostStart: request.hostStart,
            hostEnd: request.hostEnd
        )
    }
}
