import Foundation

/// Every exclusion source, combined only here.
///
/// A host excluded by any source is excluded, deduplicated on the fly. Overlaps —
/// `apple.com` is in two lists — cost nothing and are worth keeping: each source
/// retains its own origin, licence, update cadence and diff.
public struct ExclusionSet: Sendable {

    public struct Match: Sendable, Equatable {
        public let sourceID: String
        public let sourceName: String
        public let entry: ExclusionEntry
    }

    public private(set) var sources: [ExclusionSource]

    /// Per source, the entry patterns the user has switched off. Ignored for sources
    /// under a hard lock — there, an override is not a setting that fails, it is a
    /// setting that does not exist.
    public private(set) var overrides: [String: Set<String>]

    private struct Ref: Sendable {
        let sourceID: String
        let sourceName: String
        let entry: ExclusionEntry
    }

    private var subdomainIndex: [String: [Ref]] = [:]
    private var exactIndex: [String: [Ref]] = [:]
    private var wildcards: [Ref] = []

    public init(sources: [ExclusionSource], overrides: [String: Set<String>] = [:]) {
        self.sources = sources
        self.overrides = overrides
        rebuild()
    }

    private mutating func rebuild() {
        subdomainIndex.removeAll()
        exactIndex.removeAll()
        wildcards.removeAll()

        for source in sources {
            let disabled = source.lock == .hard ? [] : (overrides[source.id] ?? [])
            for entry in source.entries where !disabled.contains(entry.pattern) {
                let ref = Ref(sourceID: source.id, sourceName: source.name, entry: entry)
                switch entry.scope {
                case .domainAndSubdomains: subdomainIndex[entry.pattern, default: []].append(ref)
                case .exact:               exactIndex[entry.pattern, default: []].append(ref)
                case .wildcard:            wildcards.append(ref)
                }
            }
        }
    }

    public mutating func setOverrides(_ patterns: Set<String>, forSource id: String) {
        overrides[id] = patterns
        rebuild()
    }

    /// Distinct hosts covered, counting a domain named by several sources once.
    public var distinctPatternCount: Int {
        Set(subdomainIndex.keys).union(exactIndex.keys).count + wildcards.count
    }

    // MARK: Matching

    /// The first reason not to decrypt `host`, or `nil` if there is none.
    ///
    /// `bundleID` narrows entries carrying `$app=`. When it is `nil` — the connection
    /// could not be attributed to an application — those entries still apply. Excluding
    /// a host that did not need it costs one unfiltered page; decrypting one the list
    /// said to leave alone is the failure this whole mechanism exists to prevent.
    public func match(host: String, bundleID: String? = nil) -> Match? {
        guard let host = IDNA.normalize(host: host) else { return nil }

        if let refs = exactIndex[host], let ref = refs.first(where: { applies($0, bundleID) }) {
            return Match(sourceID: ref.sourceID, sourceName: ref.sourceName, entry: ref.entry)
        }

        var suffix = Substring(host)
        while true {
            if let refs = subdomainIndex[String(suffix)],
               let ref = refs.first(where: { applies($0, bundleID) }) {
                return Match(sourceID: ref.sourceID, sourceName: ref.sourceName, entry: ref.entry)
            }
            guard let dot = suffix.firstIndex(of: ".") else { break }
            suffix = suffix[suffix.index(after: dot)...]
        }

        for ref in wildcards where applies(ref, bundleID) && ref.entry.matches(host: host) {
            return Match(sourceID: ref.sourceID, sourceName: ref.sourceName, entry: ref.entry)
        }
        return nil
    }

    public func isExcluded(host: String, bundleID: String? = nil) -> Bool {
        match(host: host, bundleID: bundleID) != nil
    }

    /// Every source covering `host`, for the question the interface has to answer:
    /// *is my bank protected?* — covered or not, by which list, exactly or with
    /// subdomains, under which `$app=` restriction.
    ///
    /// Unlike ``match(host:bundleID:)`` this ignores application restrictions, because
    /// the user asking is not asking on behalf of one application.
    public func allMatches(host: String) -> [Match] {
        guard let host = IDNA.normalize(host: host) else { return [] }
        var found: [Match] = []

        for ref in exactIndex[host] ?? [] {
            found.append(Match(sourceID: ref.sourceID, sourceName: ref.sourceName, entry: ref.entry))
        }
        var suffix = Substring(host)
        while true {
            for ref in subdomainIndex[String(suffix)] ?? [] {
                found.append(Match(sourceID: ref.sourceID, sourceName: ref.sourceName, entry: ref.entry))
            }
            guard let dot = suffix.firstIndex(of: ".") else { break }
            suffix = suffix[suffix.index(after: dot)...]
        }
        for ref in wildcards where ref.entry.matches(host: host) {
            found.append(Match(sourceID: ref.sourceID, sourceName: ref.sourceName, entry: ref.entry))
        }
        return found
    }

    private func applies(_ ref: Ref, _ bundleID: String?) -> Bool {
        guard !ref.entry.apps.isEmpty else { return true }
        guard let bundleID else { return true }
        return ref.entry.apps.contains(bundleID)
    }
}
