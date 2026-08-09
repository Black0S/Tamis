import Foundation

/// One parsed cosmetic rule.
///
/// Cosmetic rules are what turn "the advert did not load" into "the page looks
/// normal". Blocking a request leaves the space it occupied — a 300×250 hole with the
/// container still holding its height — and hiding the container is what closes it.
public struct CosmeticRule: Sendable, Equatable {

    public enum Kind: Sendable, Equatable {
        /// `##selector` — hide matching elements.
        case hide
        /// `#@#selector` — cancel a hide rule.
        case unhide
        /// `#$#body { … }` — inject a style declaration.
        case style
        /// `##+js(name, args)` — run a scriptlet.
        case scriptlet
        /// `##^selector` — remove from the HTML stream, before the browser parses it.
        case htmlFilter
    }

    public let kind: Kind
    /// The selector, style body or scriptlet invocation, depending on ``kind``.
    public let body: String
    /// Domains the rule applies to. Empty means every site.
    public let includedDomains: [String]
    /// Domains the rule never applies to.
    public let excludedDomains: [String]
    public let raw: String

    /// Whether the selector needs the injected runtime rather than plain CSS.
    ///
    /// A stylesheet cannot express "the element containing this text", so these are
    /// handed to JavaScript instead. Mixing them into the CSS would make the browser
    /// discard the whole rule.
    public var isProcedural: Bool {
        kind == .hide && Self.proceduralMarkers.contains { body.contains($0) }
    }

    static let proceduralMarkers = [
        ":has(", ":has-text(", ":matches-css(", ":matches-media(", ":matches-path(",
        ":matches-attr(", ":min-text-length(", ":others(", ":upward(", ":xpath(",
        ":watch-attr(", ":remove(", ":style(", ":contains(", ":if(", ":if-not(",
        ":nth-ancestor(",
    ]

    /// Whether the rule is generic — applying to every site rather than a named one.
    ///
    /// The distinction drives injection: specific rules are a short, targeted
    /// stylesheet, while the generic set runs to tens of thousands of selectors and
    /// cannot be inlined into every page.
    public var isGeneric: Bool { includedDomains.isEmpty }
}

// MARK: - Parsing

extension CosmeticRule {

    /// Parses one line, or returns `nil` if it is not a cosmetic rule.
    ///
    /// Network rules, comments and blank lines come back as `nil` rather than as
    /// errors — they simply belong to the other parser.
    public static func parse(_ line: String) -> CosmeticRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("!"), !trimmed.hasPrefix("[") else { return nil }

        // Separators are ordered longest-first: `#@#` contains `#`, and `#$#` would be
        // mistaken for `##` if `##` were tried first.
        let separators: [(marker: String, kind: Kind)] = [
            ("#@$#", .style), ("#@#", .unhide), ("#$#", .style),
            ("#%#", .scriptlet), ("##", .hide),
        ]

        for (marker, kind) in separators {
            guard let range = trimmed.range(of: marker) else { continue }
            let domainPart = String(trimmed[trimmed.startIndex..<range.lowerBound])
            var body = String(trimmed[range.upperBound...])
            guard !body.isEmpty else { return nil }

            var resolvedKind = kind
            if kind == .hide {
                if body.hasPrefix("+js(") {
                    resolvedKind = .scriptlet
                    body = String(body.dropFirst(4).dropLast(body.hasSuffix(")") ? 1 : 0))
                } else if body.hasPrefix("^") {
                    resolvedKind = .htmlFilter
                    body = String(body.dropFirst())
                }
            }
            if kind == .scriptlet, body.hasPrefix("//scriptlet") {
                body = String(body.dropFirst("//scriptlet".count)).trimmingCharacters(in: .whitespaces)
            }

            let (included, excluded) = splitDomains(domainPart)
            return CosmeticRule(
                kind: resolvedKind,
                body: body.trimmingCharacters(in: .whitespaces),
                includedDomains: included,
                excludedDomains: excluded,
                raw: trimmed
            )
        }
        return nil
    }

    /// `example.com,~ads.example.com` — the negated half never receives the rule.
    static func splitDomains(_ text: String) -> (included: [String], excluded: [String]) {
        guard !text.isEmpty else { return ([], []) }
        var included: [String] = []
        var excluded: [String] = []
        for entry in text.split(separator: ",") {
            let domain = entry.trimmingCharacters(in: .whitespaces).lowercased()
            guard !domain.isEmpty else { continue }
            if domain.hasPrefix("~") {
                excluded.append(String(domain.dropFirst()))
            } else {
                included.append(domain)
            }
        }
        return (included, excluded)
    }
}
