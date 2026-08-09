import Foundation

/// What Tamis does with one application's traffic.
public struct AppPolicy: Sendable, Equatable, Codable {

    public enum Treatment: String, Sendable, Equatable, Codable, CaseIterable {
        /// Decrypt and filter.
        case filter
        /// Relay blind. The application talks to the origin directly, and Tamis learns
        /// nothing about the contents.
        case passthrough
        /// Refuse the connection outright.
        case block

        public var title: String {
            switch self {
            case .filter:      "Filtrer"
            case .passthrough: "Laisser passer"
            case .block:       "Bloquer"
            }
        }
    }

    /// Why an application is treated the way it is, so the screen never shows a bare
    /// verdict. A recommendation nobody can check is a recommendation nobody should
    /// follow.
    public enum Rationale: Sendable, Equatable, Codable {
        /// Not negotiable. Tor and Mullvad.
        case lockedOut(String)
        /// Pre-filled: this software breaks when intercepted.
        case pinned(String)
        /// The browser blocks on its own already.
        case blocksOnItsOwn(String)
        /// The browser has lost its extension, so Tamis is what is left.
        case extensionsWeakened(String)
        /// Nothing known about it.
        case unknownDefault

        public var text: String {
            switch self {
            case .lockedOut(let reason),
                 .pinned(let reason),
                 .blocksOnItsOwn(let reason),
                 .extensionsWeakened(let reason):
                reason
            case .unknownDefault:
                "Aucune particularité connue. Le filtrage est le comportement par défaut."
            }
        }
    }

    public let bundleID: String
    public var treatment: Treatment
    /// `true` when the user cannot change this. Only ever set by ``recommended(for:)``.
    public let isLocked: Bool
    public let rationale: Rationale

    public init(bundleID: String, treatment: Treatment, isLocked: Bool = false, rationale: Rationale) {
        self.bundleID = bundleID
        self.treatment = treatment
        self.isLocked = isLocked
        self.rationale = rationale
    }

    /// Tamis's own suggestion for a browser, with the reason attached.
    ///
    /// The landscape is what justifies the answer, so it is quoted rather than summed
    /// up as a verdict: Safari has no uBlock Origin at all any more, Chrome and Edge
    /// have uBO Lite with a hard cap on rules, and Firefox still runs the full thing.
    public static func recommended(for browser: Browser) -> AppPolicy {
        if browser.isLockedOut {
            return AppPolicy(
                bundleID: browser.bundleID, treatment: .passthrough, isLocked: true,
                rationale: .lockedOut(
                    "Déchiffrer ce navigateur détruirait exactement ce pour quoi il existe, "
                    + "et sa signature TLS uniforme — qui empêche d'identifier ses utilisateurs "
                    + "— disparaîtrait. Non modifiable."
                )
            )
        }
        if browser.hasBuiltInBlocking {
            return AppPolicy(
                bundleID: browser.bundleID, treatment: .passthrough,
                rationale: .blocksOnItsOwn(
                    "\(browser.name) bloque déjà par lui-même. Filtrer en plus n'est pas "
                    + "faux, seulement redondant."
                )
            )
        }
        if let reason = knownWeakness[browser.bundleID] {
            return AppPolicy(
                bundleID: browser.bundleID, treatment: .filter,
                rationale: .extensionsWeakened(reason)
            )
        }
        if let reason = knownStrength[browser.bundleID] {
            return AppPolicy(
                bundleID: browser.bundleID, treatment: .passthrough,
                rationale: .blocksOnItsOwn(reason)
            )
        }
        // An unknown browser is filtered. Doing nothing to something unrecognised would
        // mean a new fork silently arriving unprotected.
        return AppPolicy(
            bundleID: browser.bundleID, treatment: .filter, rationale: .unknownDefault
        )
    }

    public static func recommended(forApplication bundleID: String, name: String) -> AppPolicy? {
        guard let reason = BrowserKnowledge.pinnedApplications[bundleID] else { return nil }
        return AppPolicy(
            bundleID: bundleID, treatment: .passthrough,
            rationale: .pinned(reason + " Sans cette exclusion, l'application ne fonctionne pas.")
        )
    }

    static let knownWeakness: [String: String] = [
        "com.apple.Safari":
            "uBlock Origin n'existe plus pour Safari : le support a été abandonné. "
            + "Tamis est ce qui reste.",
        "com.google.Chrome":
            "Manifest V3 : uBlock Origin est réduit à uBO Lite, avec un plafond dur sur "
            + "le nombre de règles.",
        "com.microsoft.edgemac":
            "Manifest V3 : uBlock Origin est réduit à uBO Lite, avec un plafond dur sur "
            + "le nombre de règles.",
        "com.google.Chrome.canary":
            "Manifest V3 : uBlock Origin est réduit à uBO Lite.",
    ]

    static let knownStrength: [String: String] = [
        "org.mozilla.firefox":
            "Firefox fait encore tourner uBlock Origin complet, dont le filtrage "
            + "cosmétique est plus fin que ce qu'on peut injecter depuis l'extérieur "
            + "de la page.",
        "org.mozilla.firefoxdeveloperedition":
            "Firefox fait encore tourner uBlock Origin complet.",
        "app.zen-browser.zen":
            "Basé sur Firefox : uBlock Origin y tourne complet.",
        "org.mozilla.librewolf":
            "Basé sur Firefox : uBlock Origin y tourne complet.",
    ]
}

/// Every application's treatment, and the rule that decides an unattributed connection.
public struct AppPolicySet: Sendable, Equatable {

    /// What to do when the connection could not be attributed to an application.
    ///
    /// Deliberately not one rule for everything. Filtering is allowed to guess: missing
    /// a block costs an advert. Running a user script is not: executing arbitrary
    /// JavaScript inside an application nobody identified is worse than any advert, so
    /// scripts fail closed while filtering fails open.
    public var filtersWhenUnattributed = true
    public var runsScriptsWhenUnattributed = false

    public private(set) var policies: [String: AppPolicy]

    public init(policies: [AppPolicy] = []) {
        self.policies = Dictionary(policies.map { ($0.bundleID, $0) }, uniquingKeysWith: { a, _ in a })
    }

    public func treatment(for bundleID: String?) -> AppPolicy.Treatment {
        guard let bundleID else { return filtersWhenUnattributed ? .filter : .passthrough }
        return policies[bundleID]?.treatment ?? .filter
    }

    public func runsScripts(for bundleID: String?) -> Bool {
        guard let bundleID else { return runsScriptsWhenUnattributed }
        return treatment(for: bundleID) == .filter
    }

    /// Refused for a locked application, which is what "non modifiable" has to mean if
    /// it means anything.
    @discardableResult
    public mutating func set(_ treatment: AppPolicy.Treatment, for bundleID: String) -> Bool {
        guard var policy = policies[bundleID] else { return false }
        guard !policy.isLocked else { return false }
        policy.treatment = treatment
        policies[bundleID] = policy
        return true
    }

    public mutating func add(_ policy: AppPolicy) {
        policies[policy.bundleID] = policy
    }

    /// Bundle identifiers the proxy must never decrypt.
    public var neverIntercepted: Set<String> {
        Set(policies.values.filter { $0.treatment != .filter }.map(\.bundleID))
    }
}
