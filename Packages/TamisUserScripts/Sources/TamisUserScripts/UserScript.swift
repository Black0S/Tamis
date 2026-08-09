import Foundation

/// A user script, parsed from its Tampermonkey-style metadata block.
///
/// Tamis runs these from the proxy rather than from inside a browser, which changes two
/// things in the script's favour. They apply in every browser at once, including the
/// ones that no longer accept extensions. And they are injected ahead of the page's own
/// scripts, so `@run-at document-start` genuinely means before everything.
public struct UserScript: Sendable, Equatable, Identifiable {

    public enum RunAt: String, Sendable, Equatable {
        case documentStart = "document-start"
        case documentEnd = "document-end"
        case documentIdle = "document-idle"
        case documentBody = "document-body"

        /// Injection happens once, at the top of the document. Later timings are
        /// reproduced by wrapping the body in the matching event, which is why the
        /// value has to survive parsing rather than being flattened away.
        public var needsWrapping: Bool { self != .documentStart }
    }

    public var id: String { name + "\u{1}" + (namespace ?? "") }

    public let name: String
    public let namespace: String?
    public let version: String?
    public let description: String?
    public let matches: [MatchPattern]
    public let includes: [IncludeRule]
    public let excludes: [IncludeRule]
    public let runAt: RunAt
    public let grants: [String]
    public let requires: [URL]
    public let downloadURL: URL?
    /// Applications the user restricted this script to, empty meaning all of them.
    ///
    /// Read from an optional `@app` key when present, but normally set in the app and
    /// stored alongside rather than in the file: a script updated from its source would
    /// otherwise lose the restriction on every update.
    public let apps: [String]
    /// The script body, without the metadata block.
    public let body: String

    /// Whether anything at all scopes this script.
    ///
    /// A script with neither `@match` nor `@include` would run on every page ever
    /// loaded. Greasemonkey defaulted to that; refusing is safer, and the parser
    /// rejects such a script rather than silently making it global.
    public var isScoped: Bool { !matches.isEmpty || !includes.isEmpty }
}

// MARK: - Parsing

extension UserScript {

    public enum ParseError: Error, Sendable, Equatable {
        case noMetadataBlock
        case noName
        case unscoped
    }

    /// Parses a `.user.js` file.
    public static func parse(_ source: String) throws -> UserScript {
        guard let block = metadataBlock(in: source) else { throw ParseError.noMetadataBlock }

        var values: [String: [String]] = [:]
        for line in block.lines {
            // `// @key value` — the value may contain spaces and is taken whole.
            guard let range = line.range(of: "@") else { continue }
            let rest = line[range.upperBound...]
            let key = String(rest.prefix { !$0.isWhitespace }).lowercased()
            guard !key.isEmpty else { continue }
            let value = String(rest.dropFirst(key.count)).trimmingCharacters(in: .whitespaces)
            values[key, default: []].append(value)
        }

        guard let name = values["name"]?.first, !name.isEmpty else { throw ParseError.noName }

        let matches = (values["match"] ?? []).compactMap(MatchPattern.parse)
        let includes = (values["include"] ?? []).compactMap(IncludeRule.parse)
        let excludes = ((values["exclude"] ?? []) + (values["exclude-match"] ?? []))
            .compactMap(IncludeRule.parse)

        let script = UserScript(
            name: name,
            namespace: values["namespace"]?.first,
            version: values["version"]?.first,
            description: values["description"]?.first,
            matches: matches,
            includes: includes,
            excludes: excludes,
            runAt: values["run-at"]?.first.flatMap(RunAt.init(rawValue:)) ?? .documentIdle,
            grants: values["grant"] ?? [],
            requires: (values["require"] ?? []).compactMap { URL(string: $0) },
            downloadURL: (values["downloadurl"] ?? values["updateurl"])?.first
                .flatMap { URL(string: $0) },
            apps: values["app"] ?? [],
            body: String(source[block.bodyStart...])
        )

        guard script.isScoped else { throw ParseError.unscoped }
        return script
    }

    /// Locates `// ==UserScript== … // ==/UserScript==`.
    static func metadataBlock(in source: String) -> (lines: [Substring], bodyStart: String.Index)? {
        guard let open = source.range(of: "==UserScript=="),
              let close = source.range(of: "==/UserScript==", range: open.upperBound..<source.endIndex)
        else { return nil }

        let block = source[open.upperBound..<close.lowerBound]
        let lines = block.split(separator: "\n", omittingEmptySubsequences: true)

        // The body starts after the closing marker's line.
        var start = close.upperBound
        while start < source.endIndex, source[start] != "\n" { start = source.index(after: start) }
        if start < source.endIndex { start = source.index(after: start) }
        return (lines, start)
    }
}

// MARK: - Matching

extension UserScript {

    /// Whether this script should run on `url`.
    ///
    /// Exclusions are checked first and win outright: an `@exclude` exists because the
    /// script broke that page, so a script matching both must not run.
    public func matches(url: URL) -> Bool {
        let text = url.absoluteString
        if excludes.contains(where: { $0.matches(url: text) }) { return false }
        if matches.contains(where: { $0.matches(url: url) }) { return true }
        return includes.contains { $0.matches(url: text) }
    }

    /// Whether this script applies to a request from `bundleID`.
    ///
    /// Unknown application means no: running arbitrary JavaScript in something we could
    /// not identify is worse than not running it, and differs deliberately from how a
    /// missed attribution is treated for blocking.
    public func applies(toApp bundleID: String?) -> Bool {
        guard !apps.isEmpty else { return true }
        guard let bundleID else { return false }
        return apps.contains(bundleID)
    }
}
