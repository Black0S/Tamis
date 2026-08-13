import Foundation

/// Applies the plan, or undoes it.
///
/// **Why a shell script and a single password prompt.** The tidy way to do privileged
/// work on macOS is a helper registered with `SMAppService`, which needs the application
/// to be signed with a Developer ID. Tamis deliberately has no Apple developer account —
/// that is the constraint the whole project is built under — so that route is closed.
/// What is left is asking for authorisation once, for a batch of commands the user can
/// read in full beforehand.
///
/// That is a worse mechanism than a signed helper and it is written down rather than
/// glossed: the user is trusting a script they were shown, not an entitlement the system
/// enforced. Showing the exact commands is what makes it a decision rather than a leap.
///
/// Nothing here runs unless ``isDryRun`` is false, and it is true by default.
public struct Installer: Sendable {

    public struct Outcome: Sendable, Equatable, Identifiable {
        public let id: String
        public let succeeded: Bool
        public let message: String
    }

    public enum Failure: Error, Sendable, Equatable {
        case authorisationRefused
        case commandFailed(String)
        case notWritable(String)
    }

    /// True by default. An installer that runs when nobody asked is not an installer.
    public var isDryRun: Bool
    /// Where the built application lives, which is what the jobs will point at.
    public let applicationURL: URL
    public let proxyPort: UInt16
    public let pacPort: UInt16

    public init(
        applicationURL: URL,
        proxyPort: UInt16 = 7654,
        pacPort: UInt16 = 7655,
        isDryRun: Bool = true
    ) {
        self.applicationURL = applicationURL
        self.proxyPort = proxyPort
        self.pacPort = pacPort
        self.isDryRun = isDryRun
    }

    /// Where the binaries are now.
    private var bundled: URL { applicationURL.appending(path: "Contents/MacOS") }
    /// Where the privileged ones will be, once installed. See
    /// ``Installation/privilegedDirectory``.
    private var installed: URL { Installation.privilegedDirectory }

    // MARK: Install

    /// The privileged half, as one script.
    ///
    /// Assembled rather than run so it can be displayed before it is authorised. Every
    /// line is a command the user could type; nothing is hidden behind an API call they
    /// cannot inspect.
    /// The authority is not passed in: it does not exist yet.
    ///
    /// `tamisd` creates it the first time launchd starts it, which happens inside this
    /// script. So the script starts the daemon, waits for the certificate to appear,
    /// and trusts that file. Handing in a path from the app would mean the app had
    /// generated the authority — which is exactly the arrangement the daemon exists to
    /// avoid.
    public func privilegedScript() -> String {
        // The jobs point at the installed copies, never at the bundle.
        let daemon = LaunchdJob.privilegedDaemon(executable: installed.appending(path: "tamisd"))
        let resolver = LaunchdJob.resolver(executable: installed.appending(path: "tamis-dnsd"))
        let directory = Installation.privilegedPath

        return """
        set -e

        # Les binaires privilégiés quittent le bundle : launchd refuse de lancer un
        # démon root depuis un emplacement que l'utilisateur peut modifier. Effet de
        # bord voulu — le service ne dépend plus de l'application, donc supprimer
        # Tamis ne laisse pas le Mac avec un réglage proxy pointant vers rien.
        mkdir -p '\(directory)'
        cp '\(bundled.appending(path: "tamisd").path(percentEncoded: false))' '\(directory)/tamisd'
        cp '\(bundled.appending(path: "tamis-dnsd").path(percentEncoded: false))' '\(directory)/tamis-dnsd'
        chown -R root:wheel '\(directory)'
        chmod 755 '\(directory)/tamisd' '\(directory)/tamis-dnsd'

        # Service privilégié : il crée l'autorité au premier démarrage et la garde.
        cp '\(stagedPlist(for: daemon).path(percentEncoded: false))' '\(daemon.plistURL.path(percentEncoded: false))'
        chown root:wheel '\(daemon.plistURL.path(percentEncoded: false))'
        chmod 644 '\(daemon.plistURL.path(percentEncoded: false))'
        launchctl bootstrap \(daemon.domain) '\(daemon.plistURL.path(percentEncoded: false))'

        # Le démon vient de créer l'autorité. On attend qu'elle soit sur le disque
        # plutôt que de supposer qu'un service lancé est un service prêt.
        CERT='\(directory)/Authority/ca.der'
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            [ -s "$CERT" ] && break
            sleep 0.5
        done
        [ -s "$CERT" ] || { echo "l'autorité n'a pas été créée" >&2; exit 1; }

        # Le certificat doit être lisible sans privilège : c'est l'utilisateur, pas
        # root, qui le présente à `security`. Reposé ici plutôt que laissé au démon
        # parce qu'un démon qui trouve une autorité existante ne la réécrit pas — donc
        # un Mac passé par une version antérieure garderait un dossier en 0700 et
        # l'étape de confiance échouerait sans que rien ne l'explique.
        chmod 755 '\(directory)/Authority'
        chmod 644 "$CERT"
        # `|| true` parce que `set -e` tuerait le script sur un test qui répond non.
        [ -f '\(directory)/Authority/ca.key' ] && chmod 600 '\(directory)/Authority/ca.key' || true

        # L'autorité n'est PAS marquée de confiance ici : voir ``trustCommand``.

        # Résolveur : launchd ouvre le port 53 et transmet le descripteur.
        cp '\(stagedPlist(for: resolver).path(percentEncoded: false))' '\(resolver.plistURL.path(percentEncoded: false))'
        chown root:wheel '\(resolver.plistURL.path(percentEncoded: false))'
        chmod 644 '\(resolver.plistURL.path(percentEncoded: false))'
        launchctl bootstrap \(resolver.domain) '\(resolver.plistURL.path(percentEncoded: false))'

        # Le résolveur doit RÉPONDRE avant qu'on lui confie le DNS de la machine.
        # « En dernier » ne suffit pas : un job qui refuse ses arguments sort en
        # erreur, launchd le relance en boucle, et pointer le DNS vers lui laisse le
        # Mac incapable de résoudre quoi que ce soit. C'est arrivé.
        RESOLVER_OK=no
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if dig +short +time=1 +tries=1 @127.0.0.1 example.com >/dev/null 2>&1; then
                RESOLVER_OK=yes; break
            fi
            sleep 0.5
        done
        if [ "$RESOLVER_OK" != yes ]; then
            launchctl bootout \(resolver.domain)/\(Installation.resolverLabel) 2>/dev/null || true
            rm -f '\(resolver.plistURL.path(percentEncoded: false))'
            echo "le résolveur ne répond pas — DNS laissé intact" >&2
            exit 1
        fi

        # Réglages réseau — les seuls changements qui redirigent du trafic, en dernier.
        networksetup -listallnetworkservices | tail -n +2 | while read -r service; do
            networksetup -setautoproxyurl "$service" '\(Installation.pacURL(port: pacPort))'
            networksetup -setdnsservers "$service" 127.0.0.1 ::1
        done
        """
    }

    /// Where the daemon writes the certificate the trust step reads.
    public var authorityCertificateURL: URL {
        installed.appending(path: "Authority/ca.der")
    }

    /// Marking the authority as trusted — the one step that cannot be batched.
    ///
    /// **Why this is separate, and why there is a second password prompt.** macOS
    /// guards the admin trust domain with the `com.apple.trust-settings.admin`
    /// authorisation right, whose rule is one-of `entitled` or `authenticate-admin`.
    /// The first needs a signed binary carrying an Apple entitlement, which a project
    /// with no developer account cannot have. The second needs to *authenticate*, and
    /// authenticating needs a dialog.
    ///
    /// `do shell script … with administrator privileges` runs as root in a session with
    /// no way to present one, so the right is refused before anyone is asked — the
    /// failure is `SecTrustSettingsSetTrustSettings: The authorization was denied since
    /// no user interaction was possible`. Being root is not the missing piece and no
    /// amount of privilege in that batch would supply it.
    ///
    /// So this runs from the user's own session instead, unprivileged, and lets macOS
    /// raise its own prompt. That prompt is better than the one it replaces: it names
    /// the certificate being trusted, where `osascript` could only say that `osascript`
    /// wanted to make changes.
    ///
    /// **And it targets the user's keychain, not the system's.** Moving the command out
    /// of the batch was necessary but not sufficient: `-d` writes to
    /// `/Library/Keychains/System.keychain`, which is `root:wheel`, so the unprivileged
    /// process that can finally authenticate cannot write the file —
    /// `SecCertificateAddToKeychain: Write permissions error`. Root could write it but
    /// could not authenticate; the user can authenticate but could not write it. Only
    /// the user domain closes both halves: `com.apple.trust-settings.user` asks for
    /// `authenticate-session-owner`, and the login keychain belongs to the person
    /// answering.
    ///
    /// The consequence is stated rather than hidden: the authority is trusted for this
    /// account only. Other accounts on the Mac do not get filtering — and do not get a
    /// root certificate installed behind their backs either, which is the better half
    /// of the trade.
    public func trustCommand() -> String {
        "security add-trusted-cert -r trustRoot -k '\(Installation.loginKeychainPath)' "
            + "-p ssl '\(authorityCertificateURL.path(percentEncoded: false))'"
    }

    /// Runs ``trustCommand`` and lets macOS do the asking.
    ///
    /// Deliberately not wrapped in `osascript`: wrapping it is what broke it.
    public func trustAuthority() throws {
        guard !isDryRun else { return }
        let path = authorityCertificateURL.path(percentEncoded: false)
        guard FileManager.default.isReadableFile(atPath: path) else {
            // The daemon writes it at 0644 in a 0755 directory precisely so this works
            // without privileges. If it is unreadable, say which file rather than let
            // `security` report a generic failure.
            throw Failure.notWritable("certificat illisible : \(path)")
        }
        _ = try run("/usr/bin/security", [
            "add-trusted-cert", "-r", "trustRoot",
            "-k", Installation.loginKeychainPath, "-p", "ssl", path,
        ])
    }

    /// Removes the trust again, from the same keychain that received it.
    ///
    /// Unprivileged for the same reason as ``trustAuthority``, and part of the user
    /// half of the uninstall rather than the privileged script — a `sudo` command
    /// aimed at the user's own keychain would look for it in the wrong place.
    public func untrustAuthority() -> Outcome {
        let id = "authority"
        guard !Installation.installedAuthorityNames().isEmpty else {
            return Outcome(id: id, succeeded: true, message: "absente du trousseau")
        }
        guard !isDryRun else {
            return Outcome(id: id, succeeded: true, message: "supprimerait l'autorité du trousseau")
        }
        do {
            _ = try run("/usr/bin/security", [
                "delete-certificate", "-c", Installation.authorityCommonNamePrefix,
                Installation.loginKeychainPath,
            ])
            return Outcome(id: id, succeeded: true, message: "autorité retirée du trousseau")
        } catch {
            return Outcome(id: id, succeeded: false, message: "\(error)")
        }
    }

    /// The unprivileged half: files inside the user's own account.
    ///
    /// Done in Swift rather than as shell, because there is no authorisation to batch
    /// and a failure here should say which file rather than which exit code.
    public func applyUserChanges(pacContents: String) throws -> [Outcome] {
        var outcomes: [Outcome] = []
        let support = Installation.supportDirectory
        let helper = LaunchdJob.pacHelper(
            executable: bundled.appending(path: "tamis-pac"), port: pacPort
        )

        outcomes.append(try write(
            id: "pac-file", data: Data(pacContents.utf8),
            to: support.appending(path: "proxy.pac")
        ))
        outcomes.append(try write(
            id: "pac-helper", data: try helper.plistData(), to: helper.plistURL
        ))

        if !isDryRun {
            _ = try? run("/bin/launchctl", [
                "bootstrap", helper.domain, helper.plistURL.path(percentEncoded: false),
            ])
        }
        return outcomes
    }

    /// Property lists are written to the support directory first, then copied into
    /// place by the privileged script.
    ///
    /// Writing them from the privileged script instead would mean generating their
    /// contents inside a shell heredoc, where a path containing a quote becomes a
    /// command. Staging keeps the generation in Swift.
    public func stagePlists() throws -> [Outcome] {
        let staging = Installation.supportDirectory.appending(path: "staging")
        var outcomes: [Outcome] = []
        for job in [
            LaunchdJob.privilegedDaemon(executable: installed.appending(path: "tamisd")),
            LaunchdJob.resolver(executable: installed.appending(path: "tamis-dnsd")),
        ] {
            outcomes.append(try write(
                id: "staged-\(job.label)", data: try job.plistData(),
                to: staging.appending(path: "\(job.label).plist")
            ))
        }
        return outcomes
    }

    func stagedPlist(for job: LaunchdJob) -> URL {
        Installation.supportDirectory
            .appending(path: "staging")
            .appending(path: "\(job.label).plist")
    }

    // MARK: Uninstall

    /// The privileged half of the removal, derived from the changes that are actually
    /// in place rather than from the full plan.
    ///
    /// Undoing something that was never done is how an uninstall script ends up
    /// disabling a setting somebody else made.
    public func uninstallScript() -> String {
        uninstallScript(for: Installation.applied(proxyPort: proxyPort, pacPort: pacPort))
    }

    /// The same thing, over a list handed in.
    ///
    /// Split out so the ordering can be tested without a machine that happens to have
    /// Tamis installed. The version above reads the real system, so on a clean Mac it
    /// returns an empty string and any test of its ordering passes by describing
    /// nothing — which is how an ordering bug survives a green suite.
    public func uninstallScript(for changes: [SystemChange]) -> String {
        // Reversed: the last change applied is the first undone. That puts the system
        // proxy back before the services it points at are dismantled, and removes the
        // privileged directory only after the resolver living in it has been booted
        // out.
        let privileged = changes.filter { $0.scope == .administrator }.reversed()
        guard !privileged.isEmpty else { return "" }

        // No `set -e` here, deliberately: a removal must keep going when one step finds
        // nothing to remove, or a half-uninstalled machine stays half-uninstalled.
        return privileged.map { "# \($0.title)\n\($0.undoCommand)" }.joined(separator: "\n\n")
    }

    public func removeUserFiles() throws -> [Outcome] {
        let applied = Installation.applied(proxyPort: proxyPort, pacPort: pacPort)
            .filter { $0.scope == .user }
        var outcomes: [Outcome] = []

        for change in applied {
            if !isDryRun {
                _ = try? run("/bin/launchctl", [
                    "bootout", "gui/\(getuid())/\(Installation.helperLabel)",
                ])
            }
            for path in change.paths {
                outcomes.append(remove(id: change.id, at: path))
            }
        }
        outcomes.append(contentsOf: (try? stagingOutcomes()) ?? [])
        // Neither privileged nor path-based, so neither loop above would reach it: the
        // authority lives in the user's keychain and comes out the same way.
        outcomes.append(untrustAuthority())
        return outcomes
    }

    private func stagingOutcomes() throws -> [Outcome] {
        let staging = Installation.supportDirectory.appending(path: "staging")
        guard FileManager.default.fileExists(atPath: staging.path(percentEncoded: false))
        else { return [] }
        return [remove(id: "staging", at: staging)]
    }

    /// The user's own data, removed only when asked for separately.
    public func removeUserData() -> [Outcome] {
        Installation.userData().map { remove(id: "data", at: $0) }
    }

    // MARK: Doing it

    private func write(id: String, data: Data, to url: URL) throws -> Outcome {
        guard !isDryRun else {
            return Outcome(id: id, succeeded: true,
                           message: "écrirait \(url.path(percentEncoded: false))")
        }
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            try data.write(to: url, options: .atomic)
            return Outcome(id: id, succeeded: true, message: url.path(percentEncoded: false))
        } catch {
            throw Failure.notWritable("\(url.path(percentEncoded: false)) : \(error)")
        }
    }

    private func remove(id: String, at url: URL) -> Outcome {
        let path = url.path(percentEncoded: false)
        guard FileManager.default.fileExists(atPath: path) else {
            return Outcome(id: id, succeeded: true, message: "absent : \(path)")
        }
        guard !isDryRun else {
            return Outcome(id: id, succeeded: true, message: "supprimerait \(path)")
        }
        do {
            try FileManager.default.removeItem(at: url)
            return Outcome(id: id, succeeded: true, message: "supprimé : \(path)")
        } catch {
            return Outcome(id: id, succeeded: false, message: "\(path) : \(error)")
        }
    }

    @discardableResult
    private func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        guard process.terminationStatus == 0 else { throw Failure.commandFailed(text) }
        return text
    }
}
