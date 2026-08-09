import Foundation

/// One line of an HTTPS exclusion list: a host that must never be decrypted.
public struct ExclusionEntry: Sendable, Equatable, Hashable {

    public enum Scope: Sendable, Equatable, Hashable {
        /// `example.com` — the domain and everything under it.
        case domainAndSubdomains
        /// `"example.com"` — that host and nothing else.
        case exact
        /// `ping.*.adguard.io` — a pattern.
        case wildcard
    }

    /// Lowercased, Punycode where the source wrote Unicode. See ``IDNA``.
    public let pattern: String
    public let scope: Scope
    /// Bundle identifiers this entry is restricted to. Empty means every application.
    public let apps: Set<String>

    public init(pattern: String, scope: Scope, apps: Set<String> = []) {
        self.pattern = pattern
        self.scope = scope
        self.apps = apps
    }

    /// Whether this entry covers `host`, which the caller has already normalised.
    public func matches(host: String) -> Bool {
        switch scope {
        case .exact:
            return host == pattern
        case .domainAndSubdomains:
            if host == pattern { return true }
            return host.hasSuffix(pattern) && host.dropLast(pattern.count).hasSuffix(".")
        case .wildcard:
            return Self.glob(pattern: pattern, matches: host)
        }
    }

    /// `*` spans any run of characters, dots included.
    ///
    /// The looser reading is deliberate. Being too generous excludes a host from
    /// decryption that did not need excluding — a filtering miss. Being too strict
    /// decrypts a host the list said not to touch. Only one of those two is a
    /// security failure, and it is not the first.
    static func glob(pattern: String, matches host: String) -> Bool {
        let parts = pattern.split(separator: "*", omittingEmptySubsequences: false).map(String.init)
        guard parts.count > 1 else { return pattern == host }

        var rest = Substring(host)
        guard rest.hasPrefix(parts[0]) else { return false }
        rest = rest.dropFirst(parts[0].count)

        for part in parts[1..<(parts.count - 1)] where !part.isEmpty {
            guard let found = rest.range(of: part) else { return false }
            rest = rest[found.upperBound...]
        }

        let last = parts[parts.count - 1]
        return last.isEmpty || rest.hasSuffix(last)
    }
}
