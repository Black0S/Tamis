import Foundation

/// Hosts Tamis will never block, whatever any list says.
///
/// A blocklist can contain the domain the blocklists are downloaded from. One
/// aggressive list carrying `raw.githubusercontent.com` would lock Tamis shut
/// permanently, with no update, no new list, and no way for the user to work out why.
/// The failure is silent and self-sealing, which is what makes it worth a rule of its
/// own.
///
/// This allowlist outranks everything: blocklists, user rules, exclusions. It is the
/// only rule in the system with no exception.
///
/// **And it is visible.** A hard-coded, invisible allowlist inside software that
/// intercepts all traffic has the exact shape of a back door. Every entry carries its
/// justification, and the interface shows them.
public struct InternalAllowlist: Sendable {

    public struct Entry: Sendable, Hashable, Identifiable {
        public enum Purpose: String, Sendable, Hashable {
            case encryptedDNS
            case filterListSource
            case appUpdate

            public var title: String {
                switch self {
                case .encryptedDNS:     "Résolution DNS chiffrée"
                case .filterListSource: "Téléchargement des listes"
                case .appUpdate:        "Mise à jour de Tamis"
                }
            }
        }

        public var id: String { host }
        public let host: String
        public let purpose: Purpose
        /// Shown next to the entry. Written for someone auditing the app, not for a log.
        public let justification: String
    }

    public let entries: [Entry]
    private let hosts: Set<String>

    public init(entries: [Entry]) {
        self.entries = entries.sorted { $0.host < $1.host }
        self.hosts = Set(entries.map(\.host))
    }

    /// Covers subdomains, since a CDN answers on names the catalogue never spells out.
    public func contains(host: String) -> Bool {
        guard let host = IDNA.normalize(host: host) else { return false }
        var suffix = Substring(host)
        while true {
            if hosts.contains(String(suffix)) { return true }
            guard let dot = suffix.firstIndex(of: ".") else { return false }
            suffix = suffix[suffix.index(after: dot)...]
        }
    }

    public func entries(for purpose: Entry.Purpose) -> [Entry] {
        entries.filter { $0.purpose == purpose }
    }

    // MARK: The shipped allowlist

    /// Derived from the catalogue rather than typed out.
    ///
    /// Every host Tamis might download a list from is in the catalogue already. Reading
    /// it back means a list added tomorrow is protected the same day, and the two can
    /// never drift apart — which a hand-maintained copy would do quietly, and only
    /// become visible the day an update stopped working.
    public static let shared = make(catalog: .bundled)

    static func make(catalog: FilterListCatalog) -> InternalAllowlist {
        var entries: [Entry] = []
        var seen: Set<String> = []

        // Contacted by IP literal, never resolved — see TamisDNS. Listed anyway: the
        // proxy would otherwise be free to intercept them, and encrypted DNS that a
        // filter can read is not encrypted DNS.
        for (host, provider) in [
            ("cloudflare-dns.com", "Cloudflare"),
            ("dns.quad9.net", "Quad9"),
            ("dns.adguard-dns.com", "AdGuard"),
            ("dns.google", "Google"),
        ] where seen.insert(host).inserted {
            entries.append(Entry(
                host: host, purpose: .encryptedDNS,
                justification: "Résolveur DNS chiffré (\(provider)). Bloquer cet hôte "
                             + "couperait toute résolution de noms."
            ))
        }

        // Grouped first: raw.githubusercontent.com serves a dozen lists, and naming
        // whichever one happened to come first would read as the only reason it is here.
        var listsByHost: [String: [String]] = [:]
        for entry in catalog.entries {
            guard let host = entry.downloadURL.host() else { continue }
            listsByHost[host, default: []].append(entry.name)
        }
        for (host, names) in listsByHost.sorted(by: { $0.key < $1.key })
        where seen.insert(host).inserted {
            let served = names.count == 1
                ? "la liste « \(names[0]) »"
                : "\(names.count) listes de filtres, dont « \(names.sorted()[0]) »"
            entries.append(Entry(
                host: host, purpose: .filterListSource,
                justification: "Sert \(served). Bloquer cet hôte empêcherait leur mise à jour."
            ))
        }

        for (host, role) in [
            ("api.github.com", "consultation des versions publiées"),
            ("github.com", "page du dépôt"),
            ("objects.githubusercontent.com", "téléchargement des binaires publiés"),
            ("codeload.github.com", "téléchargement du code source"),
        ] where seen.insert(host).inserted {
            entries.append(Entry(
                host: host, purpose: .appUpdate,
                justification: "Mise à jour de Tamis — \(role). Bloquer cet hôte "
                             + "figerait l'application sur sa version actuelle."
            ))
        }

        return InternalAllowlist(entries: entries)
    }
}
