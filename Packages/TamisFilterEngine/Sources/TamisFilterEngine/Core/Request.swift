import Foundation

/// Everything the engine needs to decide about one request.
///
/// Built once per request by the proxy and passed by value. All string fields are
/// pre-lowercased: ABP matching is case-insensitive unless `$match-case` is present,
/// and lowercasing once here is far cheaper than doing it inside the matching loop.
public struct Request: Sendable {
    /// Full URL, lowercased.
    public let url: String
    /// Host component, lowercased, without port.
    public let hostname: String
    /// Registrable domain of ``hostname`` (eTLD+1).
    public let domain: String
    /// Hostname of the document that initiated the request, if known.
    public let sourceHostname: String?
    /// Registrable domain of ``sourceHostname``.
    public let sourceDomain: String?
    public let type: RequestType
    public let method: String

    /// True when the request leaves the site the user is looking at.
    ///
    /// Unknown origin counts as first-party: a rule scoped to third-party traffic
    /// should not fire on a request we failed to attribute.
    public let isThirdParty: Bool

    /// ``url`` as UTF-8 bytes. Computed once here rather than inside the matching
    /// loop, which runs against thousands of candidate rules per request.
    public let urlBytes: [UInt8]
    /// Index of the first byte of the hostname within ``urlBytes``.
    public let hostStart: Int
    /// Index one past the last byte of the hostname within ``urlBytes``.
    public let hostEnd: Int

    public init(
        url: String,
        hostname: String,
        sourceHostname: String? = nil,
        type: RequestType,
        method: String = "GET"
    ) {
        let lowerURL = url.lowercased()
        let lowerHost = hostname.lowercased()
        let lowerSource = sourceHostname?.lowercased()

        let bytes = Array(lowerURL.utf8)
        let bounds = Self.hostBounds(in: bytes)
        self.urlBytes = bytes
        self.hostStart = bounds.start
        self.hostEnd = bounds.end

        self.url = lowerURL
        self.hostname = lowerHost
        self.domain = PublicSuffix.registrableDomain(of: lowerHost)
        self.sourceHostname = lowerSource
        self.sourceDomain = lowerSource.map { PublicSuffix.registrableDomain(of: $0) }
        self.type = type
        self.method = method.uppercased()

        if let source = self.sourceDomain, !source.isEmpty {
            self.isThirdParty = source != self.domain
        } else {
            self.isThirdParty = false
        }
    }

    /// Locates the hostname inside a URL's bytes.
    ///
    /// Scans rather than using `URLComponents`: this runs on every request, and the
    /// only thing needed is a pair of offsets. Userinfo (`user:pass@host`) is skipped
    /// so that `||host` anchoring cannot be fooled by a crafted `http://evil.com@host`.
    static func hostBounds(in bytes: [UInt8]) -> (start: Int, end: Int) {
        let slash = UInt8(ascii: "/"), colon = UInt8(ascii: ":")
        let at = UInt8(ascii: "@"), question = UInt8(ascii: "?"), hash = UInt8(ascii: "#")

        var start = 0
        // Skip the scheme, if any: find "://".
        var i = 0
        while i + 2 < bytes.count {
            if bytes[i] == colon, bytes[i + 1] == slash, bytes[i + 2] == slash {
                start = i + 3
                break
            }
            // A path or query begins before any scheme separator: no authority here.
            if bytes[i] == slash || bytes[i] == question || bytes[i] == hash { break }
            i += 1
        }

        var end = bytes.count
        var j = start
        var userinfoEnd: Int?
        while j < bytes.count {
            let b = bytes[j]
            if b == slash || b == question || b == hash { end = j; break }
            if b == at { userinfoEnd = j }
            j += 1
        }
        if let userinfoEnd, userinfoEnd < end { start = userinfoEnd + 1 }

        // Trim the port.
        var k = start
        while k < end {
            if bytes[k] == colon { end = k; break }
            k += 1
        }

        return (min(start, end), end)
    }
}

// MARK: - Registrable domain

/// Computes the registrable domain (eTLD+1) of a hostname.
///
/// - Important: This is a placeholder. Correct first-party determination requires the
///   full Public Suffix List — `a.co.uk` and `b.co.uk` are *different* sites, and no
///   label-counting heuristic can know that in general. The embedded set below covers
///   the common multi-label suffixes so that tests and development are not misleading;
///   the real list must be loaded before any release.
public enum PublicSuffix {
    /// Second-level suffixes that behave as public suffixes.
    /// Replace with the full PSL — see the note above.
    static let multiLabelSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "net.br", "org.br", "gov.br",
        "co.nz", "net.nz", "org.nz", "govt.nz",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.in", "net.in", "org.in", "gov.in",
        "com.mx", "com.ar", "com.tr", "com.tw", "com.hk", "com.sg",
        "co.za", "co.kr", "co.il", "co.id", "co.th",
        "gouv.fr", "asso.fr", "com.fr", "tm.fr",
        "gov.it", "edu.it",
        "com.es", "org.es", "gob.es",
        "github.io", "gitlab.io", "pages.dev", "workers.dev",
        "vercel.app", "netlify.app", "herokuapp.com", "web.app", "firebaseapp.com",
        "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
    ]

    public static func registrableDomain(of hostname: String) -> String {
        guard !hostname.isEmpty else { return "" }

        // IP literals have no registrable domain; they are their own identity.
        if hostname.hasPrefix("[") || isIPv4Literal(hostname) { return hostname }

        let labels = hostname.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count > 2 else { return hostname }

        let lastTwo = labels.suffix(2).joined(separator: ".")
        if multiLabelSuffixes.contains(lastTwo) {
            return labels.suffix(3).joined(separator: ".")
        }
        return lastTwo
    }

    static func isIPv4Literal(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.count <= 3 && part.allSatisfy(\.isNumber)
        }
    }
}
