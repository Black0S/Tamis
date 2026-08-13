import Foundation
import Testing
@testable import TamisSystem

@Suite("Installer")
struct InstallerTests {

    private let application = URL(fileURLWithPath: "/Applications/Tamis.app")

    private func installer(dryRun: Bool = true) -> Installer {
        Installer(applicationURL: application, isDryRun: dryRun)
    }

    /// An installer that runs when nobody asked is not an installer.
    @Test("Nothing happens by default")
    func dryRunIsTheDefault() throws {
        #expect(Installer(applicationURL: application).isDryRun)

        let outcomes = try installer().stagePlists()
        #expect(!outcomes.contains { !$0.succeeded })
        #expect(outcomes.allSatisfy { $0.message.hasPrefix("écrirait") })

        // Asked as a difference rather than an absolute: this suite also runs on a Mac
        // where Tamis is genuinely installed, and a staging directory that was already
        // there is not evidence the dry run made one.
        let staging = Installation.supportDirectory.appending(path: "staging")
        let existedBefore = FileManager.default.fileExists(atPath: staging.path(percentEncoded: false))
        _ = try installer().stagePlists()
        let existsAfter = FileManager.default.fileExists(atPath: staging.path(percentEncoded: false))
        #expect(existedBefore == existsAfter, "un essai à blanc a créé des fichiers")
    }

    /// The user is trusting a script they were shown. It has to be readable, and it has
    /// to contain exactly what it claims.
    @Test("The privileged script names every command it will run")
    func scriptIsReadable() {
        let script = installer().privilegedScript()
        // `bootstrap` takes a domain and a path; `bootout` takes a service target.
        // Getting those the wrong way round produces a command that fails at install
        // time and nowhere earlier.
        for expected in [
            "launchctl bootstrap system '/Library/LaunchDaemons/\(Installation.resolverLabel).plist'",
            "networksetup -setautoproxyurl",
        ] {
            #expect(script.contains(expected), "le script ne contient pas « \(expected) »")
        }
    }

    /// Trusted for SSL and nothing else. A root marked good for everything could sign
    /// code, e-mail and timestamps, none of which Tamis has any business doing.
    @Test("The authority is trusted only for SSL")
    func authorityScope() {
        let command = installer().trustCommand()
        #expect(command.contains("-p ssl"))
        #expect(command.contains("-r trustRoot"))
    }

    /// Found by running the install for real. `com.apple.trust-settings.admin` is
    /// `k-of-n: 1` over `entitled` / `authenticate-admin`: the first needs an Apple
    /// entitlement this project cannot have, and the second needs to authenticate,
    /// which needs a dialog. `do shell script … with administrator privileges` runs as
    /// root in a session that can show none, so the right is refused before anyone is
    /// asked — `SecTrustSettingsSetTrustSettings: The authorization was denied since no
    /// user interaction was possible`. Root was never the missing piece.
    @Test("The trust step is not in the batch, because it cannot work there")
    func trustIsNotBatched() {
        #expect(!installer().privilegedScript().contains("security add-trusted-cert"),
                "la commande de confiance est revenue dans le lot osascript")
        #expect(installer().trustCommand().contains("security add-trusted-cert"))
        // Wrapping it is exactly what broke it.
        #expect(!installer().trustCommand().contains("osascript"))
    }

    /// The daemon writes it at 0644 in a 0755 directory so an unprivileged process can
    /// read it. The trust step is unprivileged; a root-only certificate is one it
    /// cannot hand to `security`.
    @Test("The trust step reads the certificate the daemon writes")
    func trustReadsTheDaemonsCertificate() {
        #expect(installer().trustCommand().contains(
            Installation.privilegedDirectory.appending(path: "Authority/ca.der")
                .path(percentEncoded: false)
        ))
    }

    /// Generating property list contents inside a shell heredoc would turn a path
    /// containing a quote into a command. They are written by Swift and copied.
    @Test("Property lists are staged, never written from the shell")
    func plistsAreStaged() {
        let script = installer().privilegedScript()
        #expect(script.contains("staging/\(Installation.resolverLabel).plist"))
        #expect(!script.contains("<?xml"), "un plist est construit dans le shell")
        #expect(!script.contains("cat >"), "un fichier est écrit depuis le shell")
    }

    /// The one change that redirects traffic goes last, so an interrupted install
    /// leaves a machine that still browses normally.
    @Test("The proxy setting is the last thing the script does")
    func proxyLast() throws {
        let script = installer().privilegedScript()
        let proxy = try #require(script.range(of: "networksetup -setautoproxyurl"))
        let resolver = try #require(script.range(of: Installation.resolverLabel))
        #expect(proxy.lowerBound > resolver.lowerBound)
    }

    /// Undoing something that was never done is how an uninstall comes to disable a
    /// setting somebody else made.
    @Test("The uninstall script only undoes what is in place")
    func uninstallIsDerived() {
        // Nothing is installed on a machine running the tests, so there is nothing to
        // undo — and the script must be empty rather than a list of hopeful commands.
        let script = installer().uninstallScript()
        if Installation.applied().isEmpty {
            #expect(script.isEmpty)
        } else {
            #expect(!script.isEmpty)
        }
    }

    /// A removal that stops at the first missing file leaves a half-uninstalled machine
    /// half-uninstalled.
    @Test("The uninstall script does not abort on a missing step")
    func uninstallKeepsGoing() {
        #expect(!installer().uninstallScript().contains("set -e"))
    }

    @Test("A dry-run uninstall removes nothing")
    func dryRunUninstall() throws {
        let removed = try installer().removeUserFiles()
        let outcomes = removed + installer().removeUserData()
        for outcome in outcomes {
            #expect(outcome.succeeded)
            #expect(outcome.message.hasPrefix("supprimerait") || outcome.message.hasPrefix("absent"))
        }
    }

    /// Written for real this time, into a directory the test owns, because a dry run
    /// that is never contrasted with a real one proves only that nothing happened.
    @Test("A real write produces the property list launchd expects")
    func realWrite() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-installer-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let job = LaunchdJob.resolver(executable: application.appending(path: "Contents/MacOS/x"))
        let url = root.appending(path: "\(job.label).plist")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try job.plistData().write(to: url)

        let parsed = try PropertyListSerialization.propertyList(
            from: try Data(contentsOf: url), options: [], format: nil
        ) as? [String: Any]
        #expect(parsed?["Label"] as? String == Installation.resolverLabel)
    }
}

/// The requirement that decides whether the daemon starts at all.
@Suite("Privileged binaries leave the bundle")
struct PrivilegedLocationTests {

    private let installer = Installer(
        applicationURL: URL(fileURLWithPath: "/Applications/Tamis.app")
    )

    /// launchd refuses to start a root daemon from a location the user can write to,
    /// and `/Applications` is one. A job pointing into the bundle fails at install
    /// time, with an error that says nothing about why.
    @Test("No launchd job points into the application bundle")
    func jobsPointOutsideTheBundle() throws {
        for job in [
            LaunchdJob.resolver(
                executable: Installation.privilegedDirectory.appending(path: "tamis-dnsd")),
        ] {
            let arguments = try PropertyListSerialization.propertyList(
                from: try job.plistData(), options: [], format: nil
            ) as? [String: Any]
            let path = try #require((arguments?["ProgramArguments"] as? [String])?.first)
            #expect(!path.contains(".app/"), "\(job.label) est lancé depuis le bundle")
            #expect(path.hasPrefix(Installation.privilegedPath))
        }
    }

    @Test("The script copies the binaries out and makes them root-owned")
    func scriptCopiesBinaries() {
        let script = installer.privilegedScript()
        let directory = Installation.privilegedPath
        #expect(script.contains("cp '/Applications/Tamis.app/Contents/MacOS/tamis-dnsd' '\(directory)/tamis-dnsd'"))
        #expect(script.contains("chown -R root:wheel '\(directory)'"))
        #expect(script.contains("chmod 755"))
    }

    /// The copies are outside the bundle, so deleting the application cannot remove
    /// them — which means the uninstall has to, or they stay for ever.
    /// Carried by the step that *creates* the directory, which is the daemon. It used
    /// to hang off the resolver, and a real failed install showed the cost: the script
    /// died at the trust step, so the resolver step never ran, so nothing owned the
    /// removal — and the rollback reported a clean Mac with root-owned binaries still
    /// in `/Library/Application Support/Tamis`.
    @Test("The step that creates the privileged directory is the step that removes it")
    func uninstallRemovesCopies() throws {
        let directory = Installation.privilegedPath
        let daemon = try #require(Installation.plan().first { $0.id == "daemon" })
        #expect(daemon.undoCommand.contains(directory))
        #expect(daemon.paths.contains(Installation.privilegedDirectory))

        // And nowhere else, or two steps race to delete the same tree.
        let others = Installation.plan().filter { $0.id != "daemon" }
        #expect(!others.contains { $0.undoCommand.contains("rm -rf '\(directory)'") })
    }

    /// The residue state this bug left behind: a privileged directory whose property
    /// list is gone. Reporting that as "not applied" is what makes it permanent.
    @Test("A privileged directory without its property list still counts as installed")
    func directoryAloneIsDetected() throws {
        let daemon = try #require(Installation.plan().first { $0.id == "daemon" })
        let directoryExists = FileManager.default.fileExists(
            atPath: Installation.privilegedPath
        )
        let plistExists = FileManager.default.fileExists(
            atPath: "/Library/LaunchDaemons/\(Installation.daemonLabel).plist"
        )
        #expect(daemon.isApplied == (directoryExists || plistExists))
    }

    /// Undo runs backwards, so the resolver is booted out before the directory holding
    /// its binary is deleted.
    /// Asked over the whole plan rather than over whatever this Mac happens to have
    /// installed. Read from the live system, this test returned early on a clean
    /// machine and proved nothing — the ordering bug it exists to catch would have
    /// sailed through a green suite.
    @Test("The uninstall reverses the order of the install")
    func uninstallIsReversed() throws {
        let plan = Installation.plan()
        let script = installer.uninstallScript(for: plan)
        let privileged = plan.filter { $0.scope == .administrator }

        let positions = privileged.compactMap { change -> (String.Index, String)? in
            script.range(of: change.undoCommand).map { ($0.lowerBound, change.id) }
        }
        #expect(positions.count == privileged.count, "une commande d'annulation manque")

        let scriptOrder = positions.sorted { $0.0 < $1.0 }.map { $0.1 }
        #expect(scriptOrder == Array(privileged.map(\.id).reversed()))
    }

    /// The consequence that ordering exists for: the resolver's binary lives inside
    /// the directory the daemon step deletes, so booting it out has to come first.
    @Test("The resolver is booted out before its binary is deleted")
    func resolverLeavesBeforeItsDirectory() throws {
        let script = installer.uninstallScript(for: Installation.plan())
        let bootout = try #require(script.range(of: "bootout system/\(Installation.resolverLabel)"))
        let removal = try #require(script.range(of: "rm -rf '\(Installation.privilegedPath)'"))
        #expect(bootout.lowerBound < removal.lowerBound)
    }

    /// Pointing DNS at Tamis is what makes the resolver cover the whole machine, and
    /// leaving it pointed there after uninstalling would leave a Mac that cannot
    /// resolve anything.
    @Test("DNS is set on install and cleared on uninstall")
    func dnsIsSetAndCleared() throws {
        let script = installer.privilegedScript()
        #expect(script.contains("networksetup -setdnsservers \"$service\" 127.0.0.1 ::1"))

        let proxy = try #require(Installation.plan().first { $0.id == "system-proxy" })
        #expect(proxy.undoCommand.contains("-setdnsservers"))
        #expect(proxy.undoCommand.contains("empty"))
    }
}

/// The step order the script depends on, found by walking the flow by hand and
/// discovering that the button labelled "Installer" advanced without installing.
@Suite("The script's own ordering")
struct ScriptOrderingTests {

    private let script = Installer(
        applicationURL: URL(fileURLWithPath: "/Applications/Tamis.app")
    ).privilegedScript()

    /// The authority does not exist when the script starts: `tamisd` creates it the
    /// first time launchd runs it, which happens inside this script. The trust step
    /// runs after the whole batch, so what matters here is that the batch does not
    /// finish before the certificate is on disk — otherwise the trust step would be
    /// handed a path to nothing.
    @Test("The batch does not finish before the certificate exists")
    func certificateExistsBeforeTheBatchEnds() throws {
        let bootstrap = try #require(script.range(of: "launchctl bootstrap system '/Library/LaunchDaemons/\(Installation.daemonLabel).plist'"))
        let wait = try #require(script.range(of: "Authority/ca.der"))
        #expect(bootstrap.lowerBound < wait.lowerBound)
    }

    /// A service that has been started is not a service that has finished starting.
    @Test("It waits for the certificate rather than assuming it")
    func waitsForCertificate() {
        #expect(script.contains("Authority/ca.der"))
        #expect(script.contains("sleep 0.5"))
        // And refuses to continue if it never appears, rather than trusting nothing
        // and reporting success.
        #expect(script.contains("l'autorité n'a pas été créée"))
    }

    /// Nothing hands the app a certificate path any more — that would mean the app had
    /// generated the authority, which is the arrangement the daemon exists to avoid.
    @Test("The app supplies no certificate")
    func appSuppliesNoCertificate() {
        #expect(!script.contains("ca.pem"))
    }
}
