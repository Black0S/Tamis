import Foundation

/// An upstream DNS-over-HTTPS resolver, addressed **by IP**.
///
/// This is the crux of the whole DNS layer. Reaching `cloudflare-dns.com` would mean
/// resolving that name — through `mDNSResponder`, which points back at us, which is
/// waiting for this very answer. The resolver would deadlock and take the machine's
/// DNS down with it.
///
/// > **Invariant: nothing in this layer may resolve a hostname.**
///
/// The escape is that the major providers put their IP addresses in the certificate's
/// subjectAltName, so connecting to `https://1.1.1.1/dns-query` validates cleanly with
/// no name lookup anywhere. A custom server that does not do this needs the bootstrap
/// path instead (see ``BootstrapResolver``).
public struct DoHProvider: Sendable, Equatable, Hashable, Identifiable {
    public var id: String { name }

    public let name: String
    /// Endpoints in preference order, IP-literal so no lookup is required.
    public let endpoints: [URL]
    /// The provider's hostname. Documentation and UI only — never resolved.
    public let hostname: String

    public init(name: String, endpoints: [URL], hostname: String) {
        self.name = name
        self.endpoints = endpoints
        self.hostname = hostname
    }

    private static func url(_ address: String, _ path: String = "/dns-query") -> URL {
        // Bracket IPv6 literals for the URL authority component.
        let authority = address.contains(":") ? "[\(address)]" : address
        return URL(string: "https://\(authority)\(path)")!
    }

    public static let cloudflare = DoHProvider(
        name: "Cloudflare",
        endpoints: [url("1.1.1.1"), url("1.0.0.1"), url("2606:4700:4700::1111")],
        hostname: "cloudflare-dns.com"
    )

    public static let quad9 = DoHProvider(
        name: "Quad9",
        endpoints: [url("9.9.9.9"), url("149.112.112.112"), url("2620:fe::fe")],
        hostname: "dns.quad9.net"
    )

    public static let adguard = DoHProvider(
        name: "AdGuard",
        endpoints: [url("94.140.14.14"), url("94.140.15.15")],
        hostname: "dns.adguard-dns.com"
    )

    public static let google = DoHProvider(
        name: "Google",
        endpoints: [url("8.8.8.8"), url("8.8.4.4"), url("2001:4860:4860::8888")],
        hostname: "dns.google"
    )

    /// The presets offered in the UI, in the order they are shown.
    public static let presets: [DoHProvider] = [cloudflare, quad9, adguard, google]
}
