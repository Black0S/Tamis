import Foundation
import Security
import SystemConfiguration

/// One thing installing Tamis would change about this Mac.
///
/// Every change carries three things together: what it does, how to detect whether it
/// is already in place, and how to undo it. Keeping them in one value is the whole
/// point — the uninstall is *derived* from the install rather than written alongside
/// it. Two separate lists drift, and the one that drifts is the uninstall, which is how
/// software comes to leave things behind.
public struct SystemChange: Sendable, Identifiable {

    public enum Scope: Sendable, Equatable {
        /// Inside the user's own account. No password.
        case user
        /// Needs an administrator. Said plainly wherever it appears, because a password
        /// prompt with no warning is how people learn to type their password at
        /// anything that asks.
        case administrator
    }

    public let id: String
    public let title: String
    /// What it does, in the user's terms rather than the system's.
    public let effect: String
    /// The exact command that reverses it, so somebody can undo this without Tamis —
    /// including after deleting the application.
    public let undoCommand: String
    public let scope: Scope
    /// Files and directories it creates, for the uninstall to remove.
    public let paths: [URL]

    private let detect: @Sendable () -> Bool

    public init(
        id: String, title: String, effect: String, undoCommand: String,
        scope: Scope, paths: [URL] = [],
        detect: @escaping @Sendable () -> Bool
    ) {
        self.id = id
        self.title = title
        self.effect = effect
        self.undoCommand = undoCommand
        self.scope = scope
        self.paths = paths
        self.detect = detect
    }

    /// Whether this is currently in place. Read-only, always.
    public var isApplied: Bool { detect() }
}

/// Everything installing would change, and everything uninstalling would undo.
public enum Installation {

    public static let daemonLabel = "io.github.black0s.tamisd"
    public static let resolverLabel = "io.github.black0s.tamis-dnsd"
    public static let helperLabel = "io.github.black0s.tamis-pac"
    public static let authorityCommonNamePrefix = "Tamis Local CA"

    /// The auto-configuration URL macOS is pointed at.
    ///
    /// The path carries the name on purpose: it is what makes an undo able to tell a
    /// setting Tamis made from one that was already there.
    public static func pacURL(port: UInt16 = 7655) -> String {
        "http://127.0.0.1:\(port)/tamis.pac"
    }

    /// Where the privileged binaries live once installed.
    ///
    /// Not inside the application bundle, and that is not tidiness: launchd refuses to
    /// start a root daemon from a location the user can write to, and `/Applications`
    /// is one. Copying the binaries out is what makes the daemon start at all — and it
    /// has a second consequence the design depends on: the daemon becomes independent
    /// of the bundle, so deleting the application cannot leave the machine with its
    /// proxy setting pointing at nothing.
    public static let privilegedDirectory = URL(
        fileURLWithPath: "/Library/Application Support/Tamis"
    )

    public static var supportDirectory: URL {
        (try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: false
        ))?.appending(path: "Tamis") ?? URL(fileURLWithPath: "/tmp/Tamis")
    }

    /// The full plan, in the order it would be applied.
    ///
    /// Ordered so that a failure part-way leaves the machine in a state that still
    /// works: the authority and the daemons go in first and change nothing about how
    /// traffic flows, and the system proxy — the one change that redirects anything —
    /// goes last.
    public static func plan(proxyPort: UInt16 = 7654, pacPort: UInt16 = 7655) -> [SystemChange] {
        [
            SystemChange(
                id: "daemon",
                title: "Service privilégié",
                effect: "Installe un service qui détient la clé de l'autorité de "
                      + "certification et applique les réglages système. Il n'analyse "
                      + "aucun contenu réseau : c'est ce qui permet au reste de Tamis "
                      + "de ne jamais tourner en root.",
                undoCommand: "sudo launchctl bootout system/\(daemonLabel); "
                           + "sudo rm /Library/LaunchDaemons/\(daemonLabel).plist; "
                           + "sudo rm -rf '\(privilegedDirectory.path(percentEncoded: false))'",
                scope: .administrator,
                paths: [
                    URL(fileURLWithPath: "/Library/LaunchDaemons/\(daemonLabel).plist"),
                    privilegedDirectory,
                ],
                detect: {
                    FileManager.default.fileExists(
                        atPath: "/Library/LaunchDaemons/\(daemonLabel).plist"
                    )
                }
            ),

            SystemChange(
                id: "authority",
                title: "Autorité de certification",
                effect: "Ajoute une autorité racine au trousseau du système. C'est ce "
                      + "qui permet à Tamis de lire le HTTPS — et donc ce qu'il faut "
                      + "retirer pour qu'il ne le puisse plus. La clé privée ne quitte "
                      + "jamais le service privilégié.",
                undoCommand: "sudo security delete-certificate -c \"\(authorityCommonNamePrefix)\" "
                           + "/Library/Keychains/System.keychain",
                scope: .administrator,
                detect: { !installedAuthorityNames().isEmpty }
            ),

            SystemChange(
                id: "resolver",
                title: "Résolveur sur le port 53",
                effect: "Fait écouter Tamis sur le port DNS. launchd ouvre le port et "
                      + "le transmet déjà ouvert, donc le résolveur lui-même ne tourne "
                      + "jamais en root.",
                undoCommand: "sudo launchctl bootout system/\(resolverLabel); "
                           + "sudo rm /Library/LaunchDaemons/\(resolverLabel).plist",
                scope: .administrator,
                paths: [URL(fileURLWithPath: "/Library/LaunchDaemons/\(resolverLabel).plist")],
                detect: {
                    FileManager.default.fileExists(
                        atPath: "/Library/LaunchDaemons/\(resolverLabel).plist"
                    )
                }
            ),

            SystemChange(
                id: "pac-helper",
                title: "Serveur de configuration proxy",
                effect: "Sert le fichier PAC sur 127.0.0.1:\(pacPort). Il survit à "
                      + "l'application : si Tamis est fermé, il répond « tout en "
                      + "direct » plutôt que de laisser le système pointer vers un port "
                      + "mort.",
                undoCommand: "launchctl bootout gui/$(id -u)/\(helperLabel); "
                           + "rm ~/Library/LaunchAgents/\(helperLabel).plist",
                scope: .user,
                paths: [
                    FileManager.default.homeDirectoryForCurrentUser
                        .appending(path: "Library/LaunchAgents/\(helperLabel).plist"),
                    supportDirectory.appending(path: "proxy.pac"),
                ],
                detect: {
                    FileManager.default.fileExists(atPath:
                        FileManager.default.homeDirectoryForCurrentUser
                            .appending(path: "Library/LaunchAgents/\(helperLabel).plist")
                            .path(percentEncoded: false))
                }
            ),

            SystemChange(
                id: "system-proxy",
                title: "Réglage proxy du système",
                effect: "Indique à macOS d'utiliser la configuration automatique servie "
                      + "par Tamis, et de résoudre les noms via 127.0.0.1. Ce sont les "
                      + "seuls changements qui redirigent réellement du trafic, et c'est "
                      + "pour cela qu'ils sont appliqués en dernier.",
                // Scoped to what Tamis set. Turning auto-proxy off everywhere would
                // also undo a configuration somebody else made — including one the
                // user had before installing — and an uninstall that removes another
                // program's settings is worse than one that leaves something behind.
                undoCommand: "networksetup -listallnetworkservices | tail -n +2 | "
                           + "while read -r s; do "
                           + "case \"$(networksetup -getautoproxyurl \"$s\" | head -1)\" in "
                           + "*tamis*) sudo networksetup -setautoproxystate \"$s\" off; "
                           + "sudo networksetup -setdnsservers \"$s\" empty ;; "
                           + "esac; done",
                scope: .administrator,
                // Only ours counts as applied, for the same reason.
                detect: { currentAutoProxyURL()?.contains("tamis") == true }
            ),
        ]
    }

    /// What is currently in place. This is what an uninstall would remove, and what the
    /// preflight check reports as residue.
    public static func applied(proxyPort: UInt16 = 7654, pacPort: UInt16 = 7655) -> [SystemChange] {
        plan(proxyPort: proxyPort, pacPort: pacPort).filter(\.isApplied)
    }

    public static var isInstalled: Bool { !applied().isEmpty }

    // MARK: Detection

    /// Tamis authorities in the trust store, by common name.
    public static func installedAuthorityNames() -> [String] {
        Preflight.installedAuthorities().filter { $0.hasPrefix(authorityCommonNamePrefix) }
    }

    /// The auto-configuration URL currently set, if any.
    static func currentAutoProxyURL() -> String? {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any],
              proxies[kSCPropNetProxiesProxyAutoConfigEnable as String] as? Int == 1
        else { return nil }
        return proxies[kSCPropNetProxiesProxyAutoConfigURLString as String] as? String
    }

    /// Data Tamis wrote that belongs to the user rather than to the system.
    ///
    /// Listed separately because removing it is a different decision: uninstalling the
    /// software is not the same as discarding the scripts somebody wrote, and the two
    /// should not be one checkbox.
    public static func userData() -> [URL] {
        let support = supportDirectory
        return [
            support.appending(path: "Lists"),
            support.appending(path: "Scripts"),
            support.appending(path: "history.sqlite"),
            support.appending(path: "applications.json"),
        ].filter { FileManager.default.fileExists(atPath: $0.path(percentEncoded: false)) }
    }
}
