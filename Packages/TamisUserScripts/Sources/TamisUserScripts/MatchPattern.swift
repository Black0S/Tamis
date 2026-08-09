import Foundation

/// A Chrome-style match pattern, as used by `@match`.
///
/// The syntax looks forgiving and is not: `*://*.example.com/*` covers `example.com`
/// and every subdomain, while `*://example.com/*` covers only the exact host. Scripts
/// are written against those rules, and an implementation that treats `*.` as a plain
/// wildcard runs them on hosts their authors never intended — `notexample.com` among
/// them.
public struct MatchPattern: Sendable, Equatable {

    public enum Scheme: Sendable, Equatable {
        case any            // `*` — http and https only, per the specification
        case exact(String)
    }

    public enum Host: Sendable, Equatable {
        /// `*` — any host.
        case any
        /// `*.example.com` — that domain and everything under it.
        case suffix(String)
        /// `example.com` — exactly this host.
        case exact(String)
    }

    public let scheme: Scheme
    public let host: Host
    /// Path glob, where `*` matches any run of characters.
    public let path: String
    public let raw: String

    /// Parses `<scheme>://<host><path>`, or returns `nil` when the pattern is not one.
    ///
    /// Refusing is better than approximating: a pattern we misread runs a script
    /// somewhere its author did not choose, which is a page break the user cannot
    /// attribute.
    public static func parse(_ text: String) -> MatchPattern? {
        let raw = text.trimmingCharacters(in: .whitespaces)
        guard !raw.isEmpty else { return nil }

        // `<all_urls>` is the documented spelling for "everywhere".
        if raw == "<all_urls>" {
            return MatchPattern(scheme: .any, host: .any, path: "/*", raw: raw)
        }

        guard let separator = raw.range(of: "://") else { return nil }
        let schemeText = String(raw[raw.startIndex..<separator.lowerBound]).lowercased()
        let rest = String(raw[separator.upperBound...])
        guard !schemeText.isEmpty, !rest.isEmpty else { return nil }

        let scheme: Scheme
        switch schemeText {
        case "*":                     scheme = .any
        case "http", "https", "file", "ftp": scheme = .exact(schemeText)
        default:                      return nil
        }

        // The path begins at the first `/`; a pattern without one is malformed.
        guard let slash = rest.firstIndex(of: "/") else { return nil }
        let hostText = String(rest[rest.startIndex..<slash]).lowercased()
        let path = String(rest[slash...])
        guard !path.isEmpty else { return nil }

        let host: Host
        if hostText == "*" {
            host = .any
        } else if hostText.hasPrefix("*.") {
            let domain = String(hostText.dropFirst(2))
            guard !domain.isEmpty, !domain.contains("*") else { return nil }
            host = .suffix(domain)
        } else {
            guard !hostText.isEmpty, !hostText.contains("*") else { return nil }
            host = .exact(hostText)
        }

        return MatchPattern(scheme: scheme, host: host, path: path, raw: raw)
    }

    public func matches(scheme candidateScheme: String, host candidateHost: String, path candidatePath: String) -> Bool {
        switch self.scheme {
        case .any:
            // `*` is http and https only — not file or ftp, whatever it looks like.
            guard candidateScheme == "http" || candidateScheme == "https" else { return false }
        case .exact(let expected):
            guard candidateScheme == expected else { return false }
        }

        switch host {
        case .any:
            break
        case .exact(let expected):
            guard candidateHost == expected else { return false }
        case .suffix(let domain):
            // The dot matters: `*.example.com` must not accept `notexample.com`.
            let matchesDomain = candidateHost == domain
                || (candidateHost.hasSuffix(domain)
                    && candidateHost.count > domain.count
                    && candidateHost[candidateHost.index(
                        candidateHost.endIndex, offsetBy: -domain.count - 1
                    )] == ".")
            guard matchesDomain else { return false }
        }

        return Glob.matches(pattern: path, text: candidatePath)
    }

    public func matches(url: URL) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased() else {
            return false
        }
        var path = url.path.isEmpty ? "/" : url.path
        if let query = url.query { path += "?" + query }
        return matches(scheme: scheme, host: host, path: path)
    }
}

/// `*` wildcards, matched without recursion.
///
/// A recursive matcher over patterns that arrive from downloaded scripts is a denial of
/// service waiting to be published; this uses a single backtrack point instead.
public enum Glob {
    public static func matches(pattern: String, text: String) -> Bool {
        let p = Array(pattern), t = Array(text)
        var pi = 0, ti = 0, star = -1, mark = 0

        while ti < t.count {
            if pi < p.count, p[pi] == "*" {
                star = pi
                mark = ti
                pi += 1
            } else if pi < p.count, p[pi] == t[ti] {
                pi += 1
                ti += 1
            } else if star >= 0 {
                pi = star + 1
                mark += 1
                ti = mark
            } else {
                return false
            }
        }
        while pi < p.count, p[pi] == "*" { pi += 1 }
        return pi == p.count
    }
}

/// An `@include` or `@exclude` rule, which is looser than `@match`.
///
/// Greasemonkey allowed both a glob over the whole URL and a regular expression, and
/// scripts in the wild use each. They are kept apart from ``MatchPattern`` because
/// their semantics differ: an include glob matches the entire URL string, not a
/// scheme/host/path triple.
public enum IncludeRule: Sendable, Equatable {
    case glob(String)
    case regex(pattern: String, flags: String)

    public static func parse(_ text: String) -> IncludeRule? {
        let raw = text.trimmingCharacters(in: .whitespaces)
        guard !raw.isEmpty else { return nil }
        if raw.hasPrefix("/"), raw.count > 1, let last = raw.lastIndex(of: "/"), last > raw.startIndex {
            let pattern = String(raw[raw.index(after: raw.startIndex)..<last])
            let flags = String(raw[raw.index(after: last)...])
            return pattern.isEmpty ? nil : .regex(pattern: pattern, flags: flags)
        }
        return .glob(raw)
    }

    public func matches(url: String) -> Bool {
        switch self {
        case .glob(let pattern):
            // A bare `*` is how scripts say "everywhere".
            return pattern == "*" || Glob.matches(pattern: pattern, text: url)
        case .regex(let pattern, let flags):
            var options: NSRegularExpression.Options = []
            if flags.contains("i") { options.insert(.caseInsensitive) }
            guard let expression = try? NSRegularExpression(pattern: pattern, options: options) else {
                return false
            }
            let range = NSRange(url.startIndex..., in: url)
            return expression.firstMatch(in: url, options: [], range: range) != nil
        }
    }
}
