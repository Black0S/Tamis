import Foundation
import Testing
@testable import TamisApps

/// Bundles are fabricated on disk rather than looked for on this Mac: the point is that
/// characterisation reads structure, and a test that only ever sees what happens to be
/// installed proves nothing about a browser released next year.
@Suite("Browser characterisation")
struct BrowserCharacterisationTests {

    private func makeBundle(
        _ name: String, bundleID: String, layout: [String]
    ) throws -> (root: URL, app: URL) {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-apps-\(UUID().uuidString)")
        let app = root.appending(path: "\(name).app")
        let contents = app.appending(path: "Contents")
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)

        let plist: [String: Any] = [
            "CFBundleIdentifier": bundleID,
            "CFBundleName": name,
            "CFBundlePackageType": "APPL",
        ]
        try (plist as NSDictionary).write(to: contents.appending(path: "Info.plist"))

        for path in layout {
            let url = contents.appending(path: path)
            if path.hasSuffix("/") {
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
            } else {
                try FileManager.default.createDirectory(
                    at: url.deletingLastPathComponent(), withIntermediateDirectories: true
                )
                try Data().write(to: url)
            }
        }
        return (root, app)
    }

    @Test("Chromium is recognised by its versioned framework")
    func chromium() throws {
        let (root, app) = try makeBundle("Fork", bundleID: "com.example.fork", layout: [
            "Frameworks/Fork Framework.framework/Versions/",
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(BrowserDiscovery.engine(of: app) == .chromium)
    }

    @Test("Gecko is recognised by omni.ja")
    func gecko() throws {
        let (root, app) = try makeBundle("Autre", bundleID: "com.example.autre", layout: [
            "Resources/browser/omni.ja",
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(BrowserDiscovery.engine(of: app) == .gecko)
    }

    @Test("WebKit is what is left")
    func webKit() throws {
        let (root, app) = try makeBundle("Léger", bundleID: "com.example.leger", layout: [
            "Frameworks/WebKit.framework/",
        ])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(BrowserDiscovery.engine(of: app) == .webKit)
    }

    @Test("A bundle with no engine signature is not guessed at")
    func unknown() throws {
        let (root, app) = try makeBundle("Vide", bundleID: "com.example.vide", layout: [])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(BrowserDiscovery.engine(of: app) == .unknown)
    }

    /// The whole reason for reading structure: a fork nobody has heard of is
    /// characterised correctly without anyone adding its name anywhere.
    @Test("An unheard-of fork is characterised anyway")
    func unheardOfFork() throws {
        let (root, app) = try makeBundle("Navigateur 2029", bundleID: "com.example.2029", layout: [
            "Frameworks/Something Framework.framework/Versions/",
        ])
        defer { try? FileManager.default.removeItem(at: root) }

        let browsers = BrowserDiscovery.characterise([app])
        #expect(browsers.count == 1)
        #expect(browsers[0].engine == .chromium)
        #expect(browsers[0].name == "Navigateur 2029")
        #expect(AppPolicy.recommended(for: browsers[0]).treatment == .filter)
    }

    @Test("The same bundle listed twice appears once")
    func deduplicates() throws {
        let (root, app) = try makeBundle("Double", bundleID: "com.example.double", layout: [])
        defer { try? FileManager.default.removeItem(at: root) }
        #expect(BrowserDiscovery.characterise([app, app]).count == 1)
    }
}

@Suite("Application policy")
struct AppPolicyTests {

    private func browser(_ bundleID: String, _ name: String = "Test") -> Browser {
        Browser(bundleID: bundleID, name: name, url: URL(fileURLWithPath: "/"), engine: .chromium)
    }

    /// Not a default. A refusal.
    @Test("Tor and Mullvad are locked out and cannot be switched on", arguments: [
        "org.torproject.torbrowser", "net.mullvad.mullvadbrowser",
    ])
    func lockedOut(bundleID: String) {
        let policy = AppPolicy.recommended(for: browser(bundleID))
        #expect(policy.treatment == .passthrough)
        #expect(policy.isLocked)

        var set = AppPolicySet(policies: [policy])
        let changed = set.set(.filter, for: bundleID)
        #expect(changed == false)
        #expect(set.treatment(for: bundleID) == .passthrough)
    }

    @Test("A browser that already blocks is left alone, with the reason said")
    func builtInBlocking() {
        let policy = AppPolicy.recommended(for: browser("com.brave.Browser", "Brave"))
        #expect(policy.treatment == .passthrough)
        #expect(!policy.isLocked)
        #expect(policy.rationale.text.contains("Brave"))
    }

    /// Safari and Chrome are the case the whole project exists for.
    @Test("Browsers that lost their extension are filtered, and it says why", arguments: [
        ("com.apple.Safari", "uBlock Origin n'existe plus"),
        ("com.google.Chrome", "Manifest V3"),
        ("com.microsoft.edgemac", "Manifest V3"),
    ])
    func weakened(bundleID: String, fragment: String) {
        let policy = AppPolicy.recommended(for: browser(bundleID))
        #expect(policy.treatment == .filter)
        #expect(policy.rationale.text.contains(fragment))
    }

    @Test("Firefox is left alone, because uBO is better there than we are")
    func firefox() {
        let policy = AppPolicy.recommended(for: browser("org.mozilla.firefox", "Firefox"))
        #expect(policy.treatment == .passthrough)
        #expect(policy.rationale.text.contains("uBlock Origin"))
    }

    @Test("An unknown browser is filtered rather than ignored")
    func unknownDefaultsToFilter() {
        let policy = AppPolicy.recommended(for: browser("com.example.inconnu"))
        #expect(policy.treatment == .filter)
        #expect(policy.rationale == .unknownDefault)
    }

    /// A pinned client does not degrade when intercepted; it fails to connect.
    @Test("Pinned applications come pre-excluded", arguments: [
        "org.whispersystems.signal-desktop", "com.getdropbox.dropbox", "com.docker.docker",
    ])
    func pinned(bundleID: String) throws {
        let policy = try #require(AppPolicy.recommended(forApplication: bundleID, name: "X"))
        #expect(policy.treatment == .passthrough)
        #expect(policy.rationale.text.contains("ne fonctionne pas"))
    }

    @Test("An unremarkable application gets no pre-filled policy")
    func notPinned() {
        #expect(AppPolicy.recommended(forApplication: "com.example.texte", name: "X") == nil)
    }

    /// Two different risks, so two different fallbacks. Missing a block costs an
    /// advert; running arbitrary JavaScript in an unidentified application does not.
    @Test("Filtering fails open on an unattributed connection, scripts fail closed")
    func unattributed() {
        let set = AppPolicySet()
        #expect(set.treatment(for: nil) == .filter)
        #expect(set.runsScripts(for: nil) == false)
    }

    @Test("Scripts do not run in an application that is not filtered")
    func scriptsFollowTreatment() {
        var set = AppPolicySet(policies: [
            AppPolicy(bundleID: "com.example.a", treatment: .filter, rationale: .unknownDefault),
            AppPolicy(bundleID: "com.example.b", treatment: .passthrough, rationale: .unknownDefault),
        ])
        #expect(set.runsScripts(for: "com.example.a"))
        #expect(set.runsScripts(for: "com.example.b") == false)

        let changed = set.set(.passthrough, for: "com.example.a")
        #expect(changed)
        #expect(set.runsScripts(for: "com.example.a") == false)
    }

    @Test("Anything not filtered is handed to the proxy as never-intercept")
    func neverIntercepted() {
        let set = AppPolicySet(policies: [
            AppPolicy(bundleID: "a", treatment: .filter, rationale: .unknownDefault),
            AppPolicy(bundleID: "b", treatment: .passthrough, rationale: .unknownDefault),
            AppPolicy(bundleID: "c", treatment: .block, rationale: .unknownDefault),
        ])
        #expect(set.neverIntercepted == ["b", "c"])
    }
}
