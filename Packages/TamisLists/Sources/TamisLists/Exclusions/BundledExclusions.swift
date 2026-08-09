import Foundation

/// The exclusion lists shipped inside Tamis.
///
/// Everything else in Tamis downloads nothing until the user asks. These are the
/// exception, and it is not really one: they are not a filter but the mechanism that
/// keeps a filter from reading a banking session. Without them the first HTTPS
/// connection after installation would be decrypted, so they cannot wait for a choice —
/// or for a network.
public enum BundledExclusions {

    private struct Descriptor {
        let file: String
        let id: String
        let name: String
        let provider: String
        let lock: ExclusionSource.Lock
        let upstream: String
    }

    private static let descriptors: [Descriptor] = [
        .init(file: "adguard-banks", id: "adguard.banks",
              name: "Banques et services financiers", provider: "AdGuard", lock: .hard,
              upstream: "https://github.com/AdguardTeam/HttpsExclusions"),
        .init(file: "adguard-sensitive", id: "adguard.sensitive",
              name: "Données sensibles", provider: "AdGuard", lock: .hard,
              upstream: "https://github.com/AdguardTeam/HttpsExclusions"),
        // Compatibility fixes rather than protection: overridable one entry at a time.
        .init(file: "adguard-issues", id: "adguard.issues",
              name: "Correctifs de compatibilité", provider: "AdGuard",
              lock: .entriesOverridable,
              upstream: "https://github.com/AdguardTeam/HttpsExclusions"),
        .init(file: "adguard-mac", id: "adguard.mac",
              name: "Spécifique macOS", provider: "AdGuard", lock: .entriesOverridable,
              upstream: "https://github.com/AdguardTeam/HttpsExclusions"),
        .init(file: "adguard-firefox", id: "adguard.firefox",
              name: "Firefox", provider: "AdGuard", lock: .entriesOverridable,
              upstream: "https://github.com/AdguardTeam/HttpsExclusions"),
        .init(file: "zen-darwin", id: "zen.darwin",
              name: "Services Apple", provider: "Zen", lock: .entriesOverridable,
              upstream: "https://github.com/irbis-sh/zen-desktop"),
        .init(file: "zen-common", id: "zen.common",
              name: "Connexion et services publics", provider: "Zen", lock: .hard,
              upstream: "https://github.com/irbis-sh/zen-desktop"),
    ]

    /// Loaded once. A parse of seven files costs a few milliseconds, but it happens on
    /// the path that decides whether to decrypt, and that path runs per connection.
    private static let loaded = load()
    public static var sources: [ExclusionSource] { loaded.sources }
    public static var reports: [String: ExclusionSource.ParseReport] { loaded.reports }

    public static func makeSet() -> ExclusionSet {
        ExclusionSet(sources: sources)
    }

    private static func load() -> (
        sources: [ExclusionSource], reports: [String: ExclusionSource.ParseReport]
    ) {
        var sources: [ExclusionSource] = []
        var reports: [String: ExclusionSource.ParseReport] = [:]

        for descriptor in descriptors {
            guard let url = Bundle.module.url(
                    forResource: descriptor.file, withExtension: "txt",
                    subdirectory: "Resources/Exclusions"
                  ) ?? Bundle.module.url(forResource: descriptor.file, withExtension: "txt"),
                  let text = try? String(contentsOf: url, encoding: .utf8)
            else {
                // A missing resource is a build mistake, not a run-time condition. It
                // must be loud: a silently absent bank list is the worst outcome here.
                assertionFailure("Bundled exclusion list missing: \(descriptor.file).txt")
                continue
            }

            let (source, report) = ExclusionSource.parse(
                text,
                id: descriptor.id,
                name: descriptor.name,
                provider: descriptor.provider,
                licence: "MIT",
                url: URL(string: descriptor.upstream),
                lock: descriptor.lock
            )
            sources.append(source)
            reports[descriptor.id] = report
        }
        return (sources, reports)
    }
}
