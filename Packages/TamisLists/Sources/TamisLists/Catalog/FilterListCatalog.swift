import Foundation

/// The lists Tamis knows about, and none that it has downloaded.
///
/// Only metadata is embedded — a hundred kilobytes or so. That is what makes the
/// founding rule workable: nothing is fetched until the user chooses, and a user cannot
/// choose in front of an empty screen. The catalogue is browsable, searchable and
/// complete on a first launch with no network.
///
/// Rebuilt by `Scripts/update-catalog.py` from uBlock Origin's `assets.json` and
/// AdGuard's `filters.json`.
public struct FilterListCatalog: Sendable {

    public struct Entry: Sendable, Identifiable, Hashable, Codable {
        public let id: String
        public let name: String
        /// AdGuard's registry carries prose; uBlock Origin's does not. Empty means the
        /// registry said nothing, not that the list is undocumented.
        public let description: String
        public let downloadURL: URL
        public let homepage: String
        /// Which registry described this list — not who wrote it.
        public let registry: String
        public let category: Category
        public let format: Format
        /// ISO codes, for the language-specific lists.
        public let languages: [String]
        /// The registry's own recommendation, passed through unchanged. AdGuard marks
        /// 42 lists this way, most of them for one language, so it means "worth knowing
        /// about" rather than "switch it on".
        public let recommendedByRegistry: Bool
        /// Part of the one-click selection. This is uBlock Origin's own out-of-the-box
        /// configuration, plus two DNS lists, because the resolver is the only layer
        /// that reaches Apple's telemetry and it would otherwise start empty.
        public let inSuggestedSelection: Bool
        public let deprecated: Bool
        /// AdGuard's `trustLevel`. `nil` where the registry does not publish one.
        public let trust: String?
    }

    public enum Category: String, Sendable, Codable, CaseIterable, Hashable {
        case base, ads, privacy, social, annoyances, security, multipurpose, regional
        case dns, other

        public var title: String {
            switch self {
            case .base:         "Base"
            case .ads:          "Publicité"
            case .privacy:      "Vie privée"
            case .social:       "Réseaux sociaux"
            case .annoyances:   "Nuisances"
            case .security:     "Sécurité"
            case .multipurpose: "Polyvalentes"
            case .regional:     "Par langue"
            case .dns:          "DNS"
            case .other:        "Autres"
            }
        }
    }

    public enum Format: String, Sendable, Codable, Hashable {
        /// Adblock Plus syntax — the filter engine, and the resolver for `||domain^`.
        case adblock
        /// A hosts file. DNS layer only.
        case hosts
    }

    public let generatedAt: String
    public let entries: [Entry]

    // MARK: Access

    public subscript(id: String) -> Entry? { index[id] }
    private let index: [String: Entry]

    public func entries(in category: Category) -> [Entry] {
        entries.filter { $0.category == category }
    }

    /// Categories that actually hold something, in the order the interface shows them.
    public var populatedCategories: [Category] {
        Category.allCases.filter { category in entries.contains { $0.category == category } }
    }

    public var suggestedSelection: [Entry] {
        entries.filter(\.inSuggestedSelection)
    }

    /// Lists written for a language the user actually reads.
    ///
    /// Offered rather than applied. A French list is a good guess for someone whose Mac
    /// is in French, but only a guess — plenty of people browse in three languages.
    public func entries(forLanguages codes: [String]) -> [Entry] {
        let wanted = Set(codes.map { $0.lowercased().prefix(2) }.map(String.init))
        return entries.filter { entry in
            entry.languages.contains { wanted.contains(String($0.lowercased().prefix(2))) }
        }
    }

    public func search(_ query: String) -> [Entry] {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return entries }
        return entries.filter {
            $0.name.lowercased().contains(needle)
                || $0.description.lowercased().contains(needle)
                || $0.registry.lowercased().contains(needle)
        }
    }

    // MARK: Loading

    private struct Document: Decodable {
        let generatedAt: String
        let entries: [Entry]
    }

    public init(entries: [Entry], generatedAt: String = "") {
        self.entries = entries
        self.generatedAt = generatedAt
        self.index = Dictionary(entries.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// The catalogue shipped in the bundle.
    ///
    /// A decode failure is a build mistake — the file is generated and committed — so it
    /// trips an assertion in debug and degrades to an empty catalogue in release. An
    /// empty catalogue is a visibly broken screen; a crash on launch is worse.
    public static let bundled: FilterListCatalog = {
        guard let url = Bundle.module.url(forResource: "catalog", withExtension: "json",
                                          subdirectory: "Resources")
                ?? Bundle.module.url(forResource: "catalog", withExtension: "json"),
              let data = try? Data(contentsOf: url)
        else {
            assertionFailure("catalog.json is missing from the bundle")
            return FilterListCatalog(entries: [])
        }
        do {
            let document = try JSONDecoder().decode(Document.self, from: data)
            return FilterListCatalog(entries: document.entries, generatedAt: document.generatedAt)
        } catch {
            assertionFailure("catalog.json did not decode: \(error)")
            return FilterListCatalog(entries: [])
        }
    }()
}
