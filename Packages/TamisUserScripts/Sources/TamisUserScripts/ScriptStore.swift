import CryptoKit
import Foundation

/// Scripts and styles on disk, as real files in real folders.
///
/// The tree the user builds in the interface *is* the tree in
/// `~/Library/Application Support/Tamis/Scripts/`. That is not a convenience: it means
/// a script can be opened in VS Code, a folder can be versioned with git, the whole
/// library is backed up by copying one directory, and it can be reorganised from the
/// Finder without Tamis being involved.
///
/// Which is also why the manifest is indexed by relative path and reconciled on every
/// load. Anything else would treat a file moved in the Finder as a file deleted and a
/// different one created, losing its settings — and the user would have no idea why.
public actor ScriptStore {

    public enum Kind: String, Sendable, Codable, CaseIterable {
        case script, style

        public var fileExtension: String {
            switch self {
            case .script: "user.js"
            case .style:  "user.css"
            }
        }

        static func of(path: String) -> Kind? {
            if path.hasSuffix(".user.js") { return .script }
            if path.hasSuffix(".user.css") || path.hasSuffix(".css") { return .style }
            if path.hasSuffix(".js") { return .script }
            return nil
        }
    }

    /// What the manifest records about one file. Everything here is a decision the user
    /// made, never something read out of the file itself.
    public struct Settings: Sendable, Codable, Equatable {
        public var isEnabled = false
        /// Bundle identifiers this may run in. Empty means every filtered application.
        ///
        /// Set in the interface, never taken from the file: an update to the script
        /// would overwrite a restriction written in its header, and the user would end
        /// up with a script running somewhere they had excluded.
        public var apps: Set<String> = []
        public var sourceURL: URL?
        /// SHA-256 of the text as it arrived. What makes local modification detectable
        /// rather than guessed at.
        public var originalHash: String?
        /// Silent updates from a third-party URL are opt-in, per script.
        public var updatesAutomatically = false
        public var installedAt: Date?
        public var updatedAt: Date?
    }

    public struct Entry: Sendable, Identifiable, Equatable {
        /// Relative to the root, with `/` separators: `YouTube/no-shorts.user.js`.
        public let path: String
        public let kind: Kind
        /// From the file's own metadata when it has a name, otherwise the filename.
        public let name: String
        public var settings: Settings
        public var isLocallyModified: Bool

        public var id: String { path }
        public var folder: String {
            let parts = path.split(separator: "/")
            return parts.count > 1 ? parts.dropLast().joined(separator: "/") : ""
        }
    }

    public struct Folder: Sendable, Identifiable, Equatable {
        public let path: String
        public var isEnabled: Bool
        public var id: String { path }
        public var name: String { String(path.split(separator: "/").last ?? "") }
    }

    public enum Failure: Error, Sendable, Equatable {
        case notFound(String)
        case alreadyExists(String)
        case invalidName(String)
        case notJavaScript(String)
    }

    /// Immutable and safe to read from anywhere — the interface needs it to offer
    /// "reveal in the Finder", which is half the reason the tree is on disk.
    public nonisolated let root: URL
    /// Originals, for a free revert. A dot-directory so the Finder does not show it
    /// next to the files the user is meant to organise.
    private var originalsRoot: URL { root.appending(path: ".originals") }
    private var manifestURL: URL { root.appending(path: "manifest.json") }

    private var settings: [String: Settings] = [:]
    private var folderSettings: [String: Bool] = [:]
    public private(set) var entries: [Entry] = []
    public private(set) var folders: [Folder] = []

    public init(root: URL) {
        self.root = root
    }

    public static func defaultRoot() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true
        )
        return support.appending(path: "Tamis/Scripts", directoryHint: .isDirectory)
    }

    // MARK: Loading

    /// Reads the manifest, walks the tree, and makes the two agree.
    ///
    /// A file the user dropped in from the Finder appears with default settings. A file
    /// they deleted disappears, and its settings go with it — keeping them would mean a
    /// script silently re-enabling itself if the same name ever came back.
    public func reload() throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        loadManifest()

        var found: [Entry] = []
        var foundFolders: Set<String> = []

        let fileManager = FileManager.default
        guard let walker = fileManager.enumerator(
            at: root, includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else { return }

        for case let url as URL in walker {
            let relative = relativePath(of: url)
            guard !relative.isEmpty else { continue }

            let isDirectory = (try? url.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory
                ?? false
            if isDirectory {
                foundFolders.insert(relative)
                continue
            }
            guard let kind = Kind.of(path: relative) else { continue }

            let text = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            let stored = settings[relative] ?? Settings()
            found.append(Entry(
                path: relative,
                kind: kind,
                name: Self.name(of: text, kind: kind, fallback: url.lastPathComponent),
                settings: stored,
                isLocallyModified: stored.originalHash.map { $0 != Self.hash(text) } ?? false
            ))
        }

        entries = found.sorted { $0.path < $1.path }
        folders = foundFolders.sorted().map { Folder(path: $0, isEnabled: folderSettings[$0] ?? true) }

        // Drop settings whose file is gone, and folder switches for folders that are.
        let livePaths = Set(entries.map(\.path))
        settings = settings.filter { livePaths.contains($0.key) }
        folderSettings = folderSettings.filter { foundFolders.contains($0.key) }
        try saveManifest()
    }

    // MARK: Enablement

    /// Whether this actually runs: its own switch, and every folder above it.
    ///
    /// A folder switch cascades. Scope by application does not inherit — the moment a
    /// child can override a parent, "why is this script not running?" stops having an
    /// answer anyone can work out.
    public func isEffectivelyEnabled(_ path: String) -> Bool {
        guard settings[path]?.isEnabled == true else { return false }
        var prefix: [Substring] = []
        for component in path.split(separator: "/").dropLast() {
            prefix.append(component)
            if folderSettings[prefix.joined(separator: "/")] == false { return false }
        }
        return true
    }

    public func setEnabled(_ isEnabled: Bool, at path: String) throws {
        guard settings[path] != nil || entries.contains(where: { $0.path == path })
        else { throw Failure.notFound(path) }
        var updated = settings[path] ?? Settings()
        updated.isEnabled = isEnabled
        settings[path] = updated
        try saveManifest()
        try refreshEntries()
    }

    public func setFolderEnabled(_ isEnabled: Bool, at path: String) throws {
        folderSettings[path] = isEnabled
        try saveManifest()
        folders = folders.map { $0.path == path ? Folder(path: $0.path, isEnabled: isEnabled) : $0 }
    }

    public func setApps(_ apps: Set<String>, at path: String) throws {
        var updated = settings[path] ?? Settings()
        updated.apps = apps
        settings[path] = updated
        try saveManifest()
        try refreshEntries()
    }

    public func setUpdatesAutomatically(_ value: Bool, at path: String) throws {
        var updated = settings[path] ?? Settings()
        updated.updatesAutomatically = value
        settings[path] = updated
        try saveManifest()
        try refreshEntries()
    }

    /// Everything that should run, already parsed, for the injection channel.
    public func enabledScripts() -> [(path: String, text: String, apps: Set<String>)] {
        entries.compactMap { entry in
            guard entry.kind == .script, isEffectivelyEnabled(entry.path),
                  let text = try? text(at: entry.path)
            else { return nil }
            return (entry.path, text, entry.settings.apps)
        }
    }

    public func enabledStyles() -> [(path: String, text: String, apps: Set<String>)] {
        entries.compactMap { entry in
            guard entry.kind == .style, isEffectivelyEnabled(entry.path),
                  let text = try? text(at: entry.path)
            else { return nil }
            return (entry.path, text, entry.settings.apps)
        }
    }

    // MARK: Files

    public func text(at path: String) throws -> String {
        let url = url(for: path)
        guard FileManager.default.fileExists(atPath: url.path(percentEncoded: false))
        else { throw Failure.notFound(path) }
        return try String(contentsOf: url, encoding: .utf8)
    }

    public func originalText(at path: String) -> String? {
        try? String(contentsOf: originalsRoot.appending(path: path), encoding: .utf8)
    }

    /// Writes an edit. Validation is the caller's; see ``ScriptValidator``.
    public func write(_ text: String, at path: String) throws {
        let url = url(for: path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try Data(text.utf8).write(to: url, options: .atomic)
        try refreshEntries()
    }

    /// Free, because the original is still there.
    public func revertToOriginal(at path: String) throws {
        guard let original = originalText(at: path) else { throw Failure.notFound(path) }
        try write(original, at: path)
    }

    public func createFolder(_ path: String) throws {
        guard !path.isEmpty, !path.hasPrefix("/"), !path.contains("..")
        else { throw Failure.invalidName(path) }
        try FileManager.default.createDirectory(at: url(for: path), withIntermediateDirectories: true)
        folderSettings[path] = true
        try saveManifest()
        try reload()
    }

    public func delete(_ path: String) throws {
        try? FileManager.default.removeItem(at: url(for: path))
        try? FileManager.default.removeItem(at: originalsRoot.appending(path: path))
        settings[path] = nil
        folderSettings[path] = nil
        try saveManifest()
        try reload()
    }

    /// Moving keeps the settings, because the file is the same file.
    public func move(from: String, to: String) throws {
        let destination = url(for: to)
        guard !FileManager.default.fileExists(atPath: destination.path(percentEncoded: false))
        else { throw Failure.alreadyExists(to) }

        try FileManager.default.createDirectory(
            at: destination.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try FileManager.default.moveItem(at: url(for: from), to: destination)

        if let original = originalText(at: from) {
            try? FileManager.default.removeItem(at: originalsRoot.appending(path: from))
            try storeOriginal(original, at: to)
        }
        settings[to] = settings[from]
        settings[from] = nil
        try saveManifest()
        try reload()
    }

    // MARK: Installing

    /// Installs a script or style, keeping the text as it arrived so a later edit is
    /// detectable and a revert costs nothing.
    @discardableResult
    public func install(
        _ text: String,
        named name: String,
        kind: Kind,
        in folder: String = "",
        sourceURL: URL? = nil,
        now: Date = .now
    ) throws -> String {
        let filename = Self.filename(from: name, kind: kind)
        let path = folder.isEmpty ? filename : folder + "/" + filename
        guard !FileManager.default.fileExists(atPath: url(for: path).path(percentEncoded: false))
        else { throw Failure.alreadyExists(path) }

        try write(text, at: path)
        try storeOriginal(text, at: path)

        // Installed switched off. A script arriving from a URL and running before
        // anyone has read its @match is the one thing this screen must not do.
        settings[path] = Settings(
            isEnabled: false,
            sourceURL: sourceURL,
            originalHash: Self.hash(text),
            installedAt: now
        )
        try saveManifest()
        try reload()
        return path
    }

    /// The proposed text and what it would change, applied by nobody yet.
    public func pendingUpdate(at path: String, newText: String) throws -> (current: String, proposed: String) {
        (try text(at: path), newText)
    }

    public func applyUpdate(_ text: String, at path: String, now: Date = .now) throws {
        try write(text, at: path)
        try storeOriginal(text, at: path)
        var updated = settings[path] ?? Settings()
        updated.originalHash = Self.hash(text)
        updated.updatedAt = now
        settings[path] = updated
        try saveManifest()
        try refreshEntries()
    }

    // MARK: Internals

    private func url(for path: String) -> URL {
        path.split(separator: "/").reduce(root) { $0.appending(path: String($1)) }
    }

    private func relativePath(of url: URL) -> String {
        let base = root.standardizedFileURL.path(percentEncoded: false)
        let full = url.standardizedFileURL.path(percentEncoded: false)
        guard full.hasPrefix(base) else { return "" }
        return String(full.dropFirst(base.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private func storeOriginal(_ text: String, at path: String) throws {
        let url = originalsRoot.appending(path: path)
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true
        )
        try Data(text.utf8).write(to: url, options: .atomic)
    }

    private func refreshEntries() throws {
        entries = try entries.map { entry in
            var entry = entry
            entry.settings = settings[entry.path] ?? Settings()
            let text = try? text(at: entry.path)
            entry.isLocallyModified = entry.settings.originalHash.flatMap { hash in
                text.map { hash != Self.hash($0) }
            } ?? false
            return entry
        }
    }

    private struct Manifest: Codable {
        var files: [String: Settings] = [:]
        var folders: [String: Bool] = [:]
    }

    private func loadManifest() {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let data = try? Data(contentsOf: manifestURL),
              let manifest = try? decoder.decode(Manifest.self, from: data)
        else { return }
        settings = manifest.files
        folderSettings = manifest.folders
    }

    private func saveManifest() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let manifest = Manifest(files: settings, folders: folderSettings)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try encoder.encode(manifest).write(to: manifestURL, options: .atomic)
    }

    static func hash(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// The name the file carries, when it carries one.
    ///
    /// Public because an install has to name the file before it exists, and the name
    /// worth using is the one the author wrote rather than whatever the URL ends with.
    public static func name(of text: String, kind: Kind, fallback: String) -> String {
        let key = kind == .script ? "@name" : "@name"
        for line in text.split(separator: "\n").prefix(60) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.contains(key) else { continue }
            let parts = trimmed.split(separator: " ", omittingEmptySubsequences: true)
            guard let index = parts.firstIndex(of: Substring(key)), index + 1 < parts.count
            else { continue }
            return parts[(index + 1)...].joined(separator: " ")
        }
        return fallback
    }

    /// A filename that is safe on disk and still recognisable in the Finder.
    static func filename(from name: String, kind: Kind) -> String {
        var cleaned = name
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.isEmpty { cleaned = "sans-titre" }
        if cleaned.hasSuffix("." + kind.fileExtension) { return cleaned }
        return cleaned + "." + kind.fileExtension
    }
}
