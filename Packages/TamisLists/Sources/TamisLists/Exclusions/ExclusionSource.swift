import Foundation

/// One exclusion list, kept whole.
///
/// Sources are never merged into a single file. Merging would make a diff unreadable
/// — which source moved? — force a re-merge on every upstream change, dissolve
/// attribution, and leave nobody to report a missing domain to. They are combined only
/// at match time, by ``ExclusionSet``.
public struct ExclusionSource: Sendable, Identifiable, Equatable {

    /// How much of the list the user is allowed to countermand.
    public enum Lock: Sendable, Equatable {
        /// Banks and password managers. Nothing can be switched off, individually or
        /// otherwise. This is the guarantee the whole design rests on.
        case hard
        /// Compatibility fixes — `issues`, `mac`, `firefox`. The list stays enabled, but
        /// a single entry can be overridden: these exist to unbreak software, and the
        /// user is entitled to disagree about one application.
        case entriesOverridable
        /// The user's own exclusions. Theirs entirely, stored apart, never overwritten.
        case editable
    }

    public let id: String
    public let name: String
    public let provider: String
    public let licence: String
    public let url: URL?
    public let lock: Lock
    public let entries: [ExclusionEntry]
    public let updatedAt: Date?

    public init(
        id: String,
        name: String,
        provider: String,
        licence: String,
        url: URL? = nil,
        lock: Lock,
        entries: [ExclusionEntry],
        updatedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.provider = provider
        self.licence = licence
        self.url = url
        self.lock = lock
        self.entries = entries
        self.updatedAt = updatedAt
    }
}

// MARK: - Parsing

extension ExclusionSource {

    /// What a parse ran into, reported rather than swallowed.
    public struct ParseReport: Sendable, Equatable {
        public var accepted = 0
        /// Entries restricted to a Windows executable — `api.github.com$app=Discord.exe`.
        /// These are upstream fixes for a platform Tamis does not run on. Dropping them
        /// is correct; counting them separately keeps the total honest, so a shrinking
        /// list is never mistaken for a broken parse.
        public var notApplicableToMacOS = 0
        /// Lines that are neither comment, blank, nor a host we could make sense of.
        public var unparsed: [String] = []
    }

    /// Parses the AdGuard and Zen exclusion format.
    ///
    /// Both comment styles are accepted, and so is `!`. AdGuard's files use `//`, Zen's
    /// use `#`, AdGuard's README documents `#`, and one line of `issues.txt` uses `!`.
    /// Guessing from the provider would have missed that line.
    public static func parse(
        _ text: String,
        id: String,
        name: String,
        provider: String,
        licence: String,
        url: URL? = nil,
        lock: Lock,
        updatedAt: Date? = nil
    ) -> (source: ExclusionSource, report: ParseReport) {
        var entries: [ExclusionEntry] = []
        var seen: Set<ExclusionEntry> = []
        var report = ParseReport()

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("//") || line.hasPrefix("#") || line.hasPrefix("!") {
                continue
            }

            var host = line
            var apps: Set<String> = []
            if let marker = host.range(of: "$app=") {
                let values = host[marker.upperBound...]
                    .split(separator: "|")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
                host = String(host[..<marker.lowerBound])

                let usable = values.filter { !$0.lowercased().hasSuffix(".exe") }
                if usable.isEmpty && !values.isEmpty {
                    report.notApplicableToMacOS += 1
                    continue
                }
                apps = Set(usable)
            }

            var scope = ExclusionEntry.Scope.domainAndSubdomains
            if host.hasPrefix("\"") && host.hasSuffix("\"") && host.count >= 2 {
                host = String(host.dropFirst().dropLast())
                scope = .exact
            }
            if host.contains("*") { scope = .wildcard }

            // Wildcards cannot go through IDNA — `*` is not a legal label — so they are
            // only lowercased. Every wildcard seen so far is ASCII.
            let normalized = scope == .wildcard
                ? host.lowercased()
                : IDNA.normalize(host: host)

            guard let normalized, !normalized.isEmpty, !normalized.contains(" ") else {
                report.unparsed.append(line)
                continue
            }

            let entry = ExclusionEntry(pattern: normalized, scope: scope, apps: apps)
            if seen.insert(entry).inserted {
                entries.append(entry)
                report.accepted += 1
            }
        }

        let source = ExclusionSource(
            id: id, name: name, provider: provider, licence: licence,
            url: url, lock: lock, entries: entries, updatedAt: updatedAt
        )
        return (source, report)
    }
}
