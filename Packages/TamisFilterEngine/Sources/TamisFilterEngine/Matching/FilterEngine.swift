import Foundation

/// What the engine decided about a request.
public struct MatchResult: Sendable, Equatable {
    public enum Action: Sendable, Equatable {
        case allow
        case block
    }

    public let action: Action
    /// The rule responsible, so the UI can show exactly why — the difference between
    /// "it was blocked" and "it was blocked by *this* line of *that* list".
    public let rule: String?

    public static let allowed = MatchResult(action: .allow, rule: nil)
}

/// Counters describing what a build actually absorbed.
///
/// Reported rather than estimated: the spec requires knowing which share of a list is
/// really enforced, and silent skipping is how a blocker ends up quietly doing less
/// than it claims.
public struct BuildStats: Sendable, Equatable {
    public var lines = 0
    public var comments = 0
    public var networkRules = 0
    public var cosmeticSkipped = 0
    public var badFilters = 0
    public var removedByBadFilter = 0
    public var parseErrors = 0
    /// Rules carrying at least one modifier the parser does not know.
    public var rulesWithUnsupportedModifiers = 0
    /// Rules that landed in the always-checked bucket, block and allow combined.
    public var unindexedRules = 0
    /// Rules backed by `NSRegularExpression`.
    public var regexRules = 0
    /// Regex rules that are *also* unindexed — evaluated on every single request, and
    /// the most expensive thing the engine can do. The number to drive down.
    public var unindexedRegexRules = 0
}

/// An immutable, queryable set of network rules.
public struct FilterEngine: Sendable {
    private let blockRules: [NetworkRule]
    private let allowRules: [NetworkRule]
    private let blockIndex: TokenIndex
    private let allowIndex: TokenIndex

    public let stats: BuildStats

    // MARK: Building

    public init(rules text: String) {
        self.init(lines: text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init))
    }

    public init(lines: [String]) {
        var stats = BuildStats()
        var parsed: [NetworkRule] = []
        var badFilterSignatures = Set<String>()

        for line in lines {
            stats.lines += 1
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if trimmed.hasPrefix("!") || trimmed.hasPrefix("[") {
                stats.comments += 1
                continue
            }

            do {
                guard let rule = try NetworkRule.parse(trimmed) else {
                    stats.cosmeticSkipped += 1
                    continue
                }
                if rule.isBadFilter {
                    stats.badFilters += 1
                    badFilterSignatures.insert(Self.signature(ofBadFilter: trimmed))
                    continue
                }
                // A modifier we do not understand almost always *narrows* a rule —
                // `$popup`, `$webrtc`, `$inline-script`. Applying the rule without it
                // widens the rule far beyond its author's intent: `://ads.$popup`
                // would go from blocking popups to blocking every URL containing
                // `://ads.`. Dropping the rule loses a block; keeping it breaks sites.
                if !rule.options.unsupported.isEmpty {
                    stats.rulesWithUnsupportedModifiers += 1
                    continue
                }
                parsed.append(rule)
            } catch {
                stats.parseErrors += 1
            }
        }

        var blocks: [NetworkRule] = []
        var allows: [NetworkRule] = []
        for rule in parsed {
            if !badFilterSignatures.isEmpty, badFilterSignatures.contains(rule.raw) {
                stats.removedByBadFilter += 1
                continue
            }
            if rule.isException { allows.append(rule) } else { blocks.append(rule) }
        }
        stats.networkRules = blocks.count + allows.count

        var blockIndex = TokenIndex()
        for (i, rule) in blocks.enumerated() { blockIndex.insert(ruleIndex: i, token: rule.indexToken) }
        var allowIndex = TokenIndex()
        for (i, rule) in allows.enumerated() { allowIndex.insert(ruleIndex: i, token: rule.indexToken) }

        stats.unindexedRules = blockIndex.catchAllCount + allowIndex.catchAllCount
        for rule in blocks + allows where rule.pattern.regex != nil {
            stats.regexRules += 1
            if rule.indexToken == nil { stats.unindexedRegexRules += 1 }
        }

        self.blockRules = blocks
        self.allowRules = allows
        self.blockIndex = blockIndex
        self.allowIndex = allowIndex
        self.stats = stats
    }

    /// The line a `$badfilter` rule cancels: itself, minus the modifier.
    static func signature(ofBadFilter line: String) -> String {
        let (pattern, options) = NetworkRule.splitPatternAndOptions(line)
        guard let options else { return pattern }
        let kept = RuleOptions.splitOnUnescapedCommas(options)
            .filter { $0.trimmingCharacters(in: .whitespaces).lowercased() != "badfilter" }
        return kept.isEmpty ? pattern : pattern + "$" + kept.joined(separator: ",")
    }

    // MARK: Querying

    /// Decides a single request.
    ///
    /// Precedence follows ABP: an exception cancels a block, except when the block
    /// carries `$important`. Blocks are searched first because the common case — no
    /// block at all — then costs nothing on the exception side.
    public func match(_ request: Request) -> MatchResult {
        guard let blocker = firstMatch(in: blockRules, index: blockIndex, request: request) else {
            return .allowed
        }

        if blocker.isImportant {
            return MatchResult(action: .block, rule: blocker.raw)
        }

        if let exception = firstMatch(in: allowRules, index: allowIndex, request: request) {
            return MatchResult(action: .allow, rule: exception.raw)
        }

        return MatchResult(action: .block, rule: blocker.raw)
    }

    /// First matching rule, preferring an `$important` one when several match.
    private func firstMatch(
        in rules: [NetworkRule],
        index: TokenIndex,
        request: Request
    ) -> NetworkRule? {
        var fallback: NetworkRule?
        var important: NetworkRule?
        index.forEachCandidate(forURL: request.urlBytes) { i in
            let rule = rules[Int(i)]
            guard rule.matches(request) else { return true }
            if rule.isImportant {
                important = rule
                return false  // nothing can outrank it — stop scanning
            }
            if fallback == nil { fallback = rule }
            return true
        }
        return important ?? fallback
    }
}
