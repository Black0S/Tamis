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
