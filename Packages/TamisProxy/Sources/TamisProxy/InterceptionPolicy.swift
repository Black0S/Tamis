import Foundation
import TamisLists

/// Decides, per connection, whether Tamis looks inside or gets out of the way.
///
/// This runs before a single byte of TLS is exchanged, and getting it wrong is not a
/// filtering miss — it breaks the site or the app outright. Hence the shape: an
/// explicit allow-through is always stronger than any reason to intercept.
public struct InterceptionPolicy: Sendable {

    public enum Decision: Sendable, Equatable {
        /// Terminate TLS, filter, re-encrypt upstream.
        case intercept
        /// Relay bytes blind. The client validates the origin's real certificate, and
        /// Tamis learns nothing about the contents — which is the point.
        case tunnel(reason: TunnelReason)
    }

    public enum TunnelReason: Sendable, Equatable {
        /// Banks, password managers, government services — never decrypted, by design.
        /// The source is carried along so a log entry, or the user asking why a page
        /// went unfiltered, gets an answer naming the list rather than a bare domain.
        case httpsExclusion(matched: String, source: String)
        /// The user (or the pre-filled list) excluded this application.
        case excludedApp(bundleID: String)
        /// Learned: this target refused our certificate, so it pins.
        case certificatePinning
        /// Learned: the origin asked for a client certificate we cannot supply.
        case clientCertificateRequired
        /// Tamis is paused, or has no reason to look.
        case filteringDisabled
    }

    /// Hosts never decrypted, keeping each source distinct. See `TamisLists`.
    private let exclusions: ExclusionSet
    /// Applications never decrypted, by bundle identifier.
    private let excludedApps: Set<String>
    /// Targets that have proved they cannot be intercepted, learned at run time.
    private var learnedPassthrough: DomainSet
    public let isEnabled: Bool

    public init(
        exclusions: ExclusionSet,
        excludedApps: Set<String> = [],
        learnedPassthrough: [String] = [],
        isEnabled: Bool = true
    ) {
        self.exclusions = exclusions
        self.excludedApps = excludedApps
        self.learnedPassthrough = DomainSet(learnedPassthrough)
        self.isEnabled = isEnabled
    }

    /// Bare host names, for tests and for the user's own exclusions.
    ///
    /// Real deployments pass `BundledExclusions.makeSet()`: the shipped lists carry
    /// exact-match quoting, `$app=` restrictions and Unicode hosts, none of which
    /// survive being flattened to strings.
    public init(
        exclusions: [String] = [],
        excludedApps: Set<String> = [],
        learnedPassthrough: [String] = [],
        isEnabled: Bool = true
    ) {
        let source = ExclusionSource(
            id: "user", name: "Mes exclusions", provider: "Tamis", licence: "GPLv3",
            lock: .editable,
            entries: exclusions.compactMap {
                IDNA.normalize(host: $0).map {
                    ExclusionEntry(pattern: $0, scope: .domainAndSubdomains)
                }
            }
        )
        self.init(
            exclusions: ExclusionSet(sources: [source]),
            excludedApps: excludedApps,
            learnedPassthrough: learnedPassthrough,
            isEnabled: isEnabled
        )
    }

    public func decision(forHost host: String, bundleID: String? = nil) -> Decision {
        guard isEnabled else { return .tunnel(reason: .filteringDisabled) }

        if let bundleID, excludedApps.contains(bundleID) {
            return .tunnel(reason: .excludedApp(bundleID: bundleID))
        }
        if let match = exclusions.match(host: host, bundleID: bundleID) {
            return .tunnel(reason: .httpsExclusion(
                matched: match.entry.pattern, source: match.sourceName
            ))
        }
        if learnedPassthrough.match(host) != nil {
            return .tunnel(reason: .certificatePinning)
        }
        return .intercept
    }

    public mutating func learnPassthrough(host: String) {
        learnedPassthrough.insert(host)
    }
}

/// Host matching that covers subdomains, sharing the semantics used by the DNS layer
/// so a domain excluded in one place behaves the same in the other.
struct DomainSet: Sendable {
    private var domains: Set<String>

    init(_ domains: [String]) {
        self.domains = Set(domains.map { $0.lowercased() })
    }

    mutating func insert(_ domain: String) {
        domains.insert(domain.lowercased())
    }

    /// The most specific entry covering `host`, walking up the labels.
    func match(_ host: String) -> String? {
        guard !domains.isEmpty else { return nil }
        let lower = host.lowercased()
        var start = lower.startIndex
        while true {
            let candidate = String(lower[start...])
            if domains.contains(candidate) { return candidate }
            guard let dot = lower[start...].firstIndex(of: "."),
                  lower.index(after: dot) < lower.endIndex else { return nil }
            start = lower.index(after: dot)
        }
    }
}
