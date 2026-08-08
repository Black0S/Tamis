import Foundation

/// Decides what happens to a single DNS query, before any network is touched.
///
/// Order of authority, highest first — this is the part that must never be reordered
/// casually, so it is expressed once, here, rather than scattered through the server:
///
/// 1. **Tamis's own domains.** A blocklist containing `raw.githubusercontent.com`
///    would otherwise stop Tamis from ever updating its lists — or itself — and lock
///    the app permanently with no way for the user to understand why.
/// 2. **The Firefox canary.** Answering NXDOMAIN for `use-application-dns.net` is the
///    signal Mozilla defined for "a network filter is present"; Firefox then disables
///    its own DoH and comes back through us.
/// 3. **The user's rules.**
public struct ResolverPolicy: Sendable {

    public enum Outcome: Sendable, Equatable {
        /// Forward upstream unchanged.
        case forward
        /// Answer NXDOMAIN without asking anyone.
        case block(reason: Reason)
    }

    public enum Reason: Sendable, Equatable {
        case blocklist(matched: String)
        case firefoxCanary
    }

    /// Mozilla's opt-out domain. Answering NXDOMAIN here is a documented protocol,
    /// not a trick: it is how a resolver declares that it filters.
    public static let firefoxCanary = "use-application-dns.net"

    /// Domains Tamis must always be able to reach, whatever any list says.
    ///
    /// Surfaced in the UI as "Tamis system domains", read-only, each with its reason —
    /// a hidden hard-coded allowlist inside software that intercepts all traffic has
    /// exactly the shape of a backdoor.
    public static let systemAllowlist: [String: String] = [
        "raw.githubusercontent.com": "Filter list updates",
        "api.github.com": "Application update checks",
        "objects.githubusercontent.com": "Application update downloads",
        "easylist.to": "Filter list source",
        "filters.adtidy.org": "Filter list source",
        "cloudflare-dns.com": "Encrypted DNS resolver",
        "dns.quad9.net": "Encrypted DNS resolver",
        "dns.adguard-dns.com": "Encrypted DNS resolver",
        "dns.google": "Encrypted DNS resolver",
    ]

    private let blocklist: DomainBlocklist
    private let allowlist: DomainBlocklist
    private let canaryList: DomainBlocklist
    public let blocksFirefoxCanary: Bool

    public init(blocklist: DomainBlocklist, blocksFirefoxCanary: Bool = true) {
        self.blocklist = blocklist
        self.allowlist = DomainBlocklist(blocking: [], allowing: Array(Self.systemAllowlist.keys))
        self.canaryList = DomainBlocklist(blocking: [Self.firefoxCanary])
        self.blocksFirefoxCanary = blocksFirefoxCanary
    }

    public func outcome(forName name: String) -> Outcome {
        if case .allow = allowlist.decision(for: name) { return .forward }

        if blocksFirefoxCanary, case .block = canaryList.decision(for: name) {
            return .block(reason: .firefoxCanary)
        }

        switch blocklist.decision(for: name) {
        case .block(let matched): return .block(reason: .blocklist(matched: matched))
        case .allow, .noMatch:    return .forward
        }
    }
}
