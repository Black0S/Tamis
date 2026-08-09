import Foundation

/// A browser installed on this Mac.
public struct Browser: Sendable, Equatable, Identifiable {

    /// Recognised from the bundle's structure, never from its name.
    ///
    /// A fork ships under whatever name its author chose, and new ones appear
    /// constantly. What does not change is the layout the engine imposes, so a browser
    /// released tomorrow is characterised correctly today.
    public enum Engine: String, Sendable, Equatable {
        case chromium, gecko, webKit, unknown

        public var title: String {
            switch self {
            case .chromium: "Chromium"
            case .gecko:    "Gecko"
            case .webKit:   "WebKit"
            case .unknown:  "moteur inconnu"
            }
        }
    }

    public let bundleID: String
    public let name: String
    public let url: URL
    public let engine: Engine
    public var id: String { bundleID }

    public init(bundleID: String, name: String, url: URL, engine: Engine) {
        self.bundleID = bundleID
        self.name = name
        self.url = url
        self.engine = engine
    }

    /// Whether the browser blocks on its own.
    ///
    /// The one thing that cannot be derived from the bundle: it is a fact about what
    /// the software does, not how it is built. So it is a list, and a short one.
    public var hasBuiltInBlocking: Bool {
        BrowserKnowledge.builtInBlocking.contains(bundleID)
    }

    /// Never intercepted, and the user cannot change it.
    ///
    /// Intercepting Tor Browser destroys the thing it exists for, and its uniform TLS
    /// signature — which is what stops its users being told apart — disappears the
    /// moment Tamis re-encrypts on its behalf. This is not a default; it is a refusal.
    public var isLockedOut: Bool {
        BrowserKnowledge.lockedOut.contains(bundleID)
    }
}

/// The parts that cannot be deduced, kept together and kept small.
public enum BrowserKnowledge {

    /// Browsers that already block. Filtering them again is not wrong, only redundant —
    /// so the recommendation is to leave them alone, with the reason said out loud.
    public static let builtInBlocking: Set<String> = [
        "com.brave.Browser",
        "com.vivaldi.Vivaldi",
        "com.operasoftware.Opera",
        "com.operasoftware.OperaGX",
        "com.kagi.kagimacOS",              // Orion
        "com.duckduckgo.macos.browser",
        "net.imput.helium",
    ]

    public static let lockedOut: Set<String> = [
        "org.torproject.torbrowser",
        "net.mullvad.mullvadbrowser",
    ]

    /// Applications that pin their certificates, or otherwise break when intercepted.
    ///
    /// Pre-filled because without them this software is unusable, not because it is
    /// convenient: a pinned client does not degrade, it fails to connect at all.
    public static let pinnedApplications: [String: String] = [
        "org.whispersystems.signal-desktop": "Signal épingle ses certificats.",
        "com.getdropbox.dropbox":            "Dropbox épingle ses certificats.",
        "com.docker.docker":                 "Docker casse si son trafic est déchiffré.",
        "com.apple.appstore":                "L'App Store épingle ses certificats.",
        "com.apple.CommerceKit":             "Les achats et mises à jour épinglent leurs certificats.",
        "com.apple.softwareupdated":         "Les mises à jour système épinglent leurs certificats.",
    ]
}
