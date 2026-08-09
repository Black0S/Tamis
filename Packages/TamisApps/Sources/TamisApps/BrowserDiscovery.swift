import AppKit
import Foundation

/// Finds the browsers on this Mac by asking macOS, not by guessing.
///
/// `NSWorkspace.urlsForApplications(toOpen:)` returns everything registered to handle
/// HTTP, which is every browser installed — including ones released after Tamis was
/// written. There is no list to maintain and nothing to keep up to date.
public enum BrowserDiscovery {

    public static func installed() -> [Browser] {
        let https = URL(string: "https://example.com")!
        let urls = NSWorkspace.shared.urlsForApplications(toOpen: https)
        return characterise(urls)
    }

    /// The default browser, which is worth naming because it is where most traffic goes.
    public static func defaultBrowser() -> Browser? {
        let https = URL(string: "https://example.com")!
        guard let url = NSWorkspace.shared.urlForApplication(toOpen: https) else { return nil }
        return characterise([url]).first
    }

    /// Split out so it can be run against fabricated bundles in a test, where
    /// `NSWorkspace` would only ever return what happens to be installed.
    public static func characterise(_ urls: [URL]) -> [Browser] {
        var seen: Set<String> = []
        var browsers: [Browser] = []

        for url in urls {
            guard let bundle = Bundle(url: url),
                  let bundleID = bundle.bundleIdentifier,
                  seen.insert(bundleID).inserted
            else { continue }

            browsers.append(Browser(
                bundleID: bundleID,
                name: displayName(of: bundle, url: url),
                url: url,
                engine: engine(of: url)
            ))
        }
        return browsers.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    static func displayName(of bundle: Bundle, url: URL) -> String {
        let info = bundle.infoDictionary ?? [:]
        return (info["CFBundleDisplayName"] as? String)
            ?? (info["CFBundleName"] as? String)
            ?? url.deletingPathExtension().lastPathComponent
    }

    /// Structure, not name.
    ///
    /// Checked in order of how specific the signature is: Gecko's `omni.ja` and
    /// Chromium's `Versions/` directory are unmistakable, while a WebKit link is what
    /// is left once neither of those is present.
    public static func engine(of bundleURL: URL) -> Browser.Engine {
        let contents = bundleURL.appending(path: "Contents")
        let fileManager = FileManager.default

        func exists(_ url: URL) -> Bool {
            fileManager.fileExists(atPath: url.path(percentEncoded: false))
        }

        if exists(contents.appending(path: "Resources/browser/omni.ja")) { return .gecko }

        let frameworks = contents.appending(path: "Frameworks")
        if exists(frameworks) {
            let versioned = (try? fileManager.contentsOfDirectory(
                at: frameworks, includingPropertiesForKeys: nil
            )) ?? []
            for framework in versioned
            where exists(framework.appending(path: "Versions")) && framework.pathExtension == "framework" {
                return .chromium
            }
        }

        // Safari itself, and anything that links WebKit without carrying its own engine.
        if exists(contents.appending(path: "MacOS/Safari")) { return .webKit }
        if exists(frameworks.appending(path: "WebKit.framework")) { return .webKit }
        return .unknown
    }
}
