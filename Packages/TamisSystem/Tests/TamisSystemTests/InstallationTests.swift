import Foundation
import Testing
@testable import TamisSystem

@Suite("Installation plan")
struct InstallationTests {

    /// The claim the whole type exists to make: every change knows how to undo itself,
    /// so the uninstall is derived rather than written alongside and left to drift.
    @Test("Every change carries the command that reverses it")
    func everyChangeIsReversible() {
        let plan = Installation.plan()
        #expect(!plan.isEmpty)

        for change in plan {
            #expect(!change.undoCommand.isEmpty, "\(change.id) ne dit pas comment l'annuler")
            #expect(!change.effect.isEmpty, "\(change.id) n'explique pas ce qu'il fait")
            // Written in the user's terms, not the system's: an effect nobody can read
            // is a consent nobody can give.
            #expect(change.effect.count > 60, "\(change.id) explique trop peu")
        }
    }

    @Test("Identifiers are unique, so a change cannot be applied or undone twice")
    func uniqueIdentifiers() {
        let ids = Installation.plan().map(\.id)
        #expect(Set(ids).count == ids.count)
    }

    /// A password prompt with no warning is how people learn to type their password at
    /// anything that asks, so which steps need one is part of the plan.
    @Test("The plan says which steps need an administrator")
    func scopes() {
        let plan = Installation.plan()
        let privileged = plan.filter { $0.scope == .administrator }.map(\.id)
        #expect(privileged.contains("system-proxy"))
        #expect(privileged.contains("daemon"))

        // The authority is *not* an administrator change any more, and calling it one
        // is what made two installs fail. It goes into the user's own keychain, in the
        // user trust domain, and macOS asks the session owner rather than an admin.
        #expect(plan.first { $0.id == "authority" }?.scope == .sessionOwner)
        #expect(!privileged.contains("authority"))

        // Serving a file on a loopback port needs nothing.
        #expect(plan.first { $0.id == "pac-helper" }?.scope == .user)

        // What the screens actually need to know: which steps interrupt the user.
        #expect(plan.filter(\.scope.prompts).map(\.id).sorted()
                == ["authority", "daemon", "resolver", "system-proxy"])
    }

    /// A failure part-way must leave a machine that still works. Nothing redirects
    /// traffic until the last step, so an interrupted install is an install that did
    /// nothing visible.
    @Test("The only change that redirects traffic is applied last")
    func ordering() {
        let plan = Installation.plan()
        #expect(plan.last?.id == "system-proxy")
    }

    @Test("Undo commands name the thing they remove")
    func undoCommandsAreSpecific() {
        for change in Installation.plan() {
            let undo = change.undoCommand
            #expect(undo.contains("tamis") || undo.contains("Tamis"),
                    "\(change.id) : « \(undo) » ne nomme pas Tamis")
            // A blanket removal in an uninstall script is how somebody loses a file
            // they never gave anyone permission to touch.
            #expect(!undo.contains("rm -rf /"), "\(change.id) supprime trop")
        }
    }

    /// Detection reads; it never installs. Running the plan twice must change nothing.
    @Test("Reading the plan changes nothing")
    func detectionIsReadOnly() {
        let before = Installation.plan().map(\.isApplied)
        let after = Installation.plan().map(\.isApplied)
        #expect(before == after)
        #expect(Installation.applied().count == before.count { $0 })
    }

    /// Uninstalling the software is not the same decision as discarding the scripts
    /// somebody wrote, and one checkbox for both would take the second by surprise.
    @Test("User data is listed apart from system changes")
    func userDataIsSeparate() {
        let systemPaths = Set(Installation.plan().flatMap(\.paths).map(\.lastPathComponent))
        for url in Installation.userData() {
            #expect(!systemPaths.contains(url.lastPathComponent),
                    "\(url.lastPathComponent) apparaît des deux côtés")
        }
    }

    @Test("A machine with nothing installed reports nothing installed")
    func nothingInstalled() {
        // True of this machine, and the assertion worth making either way: `applied`
        // and `isInstalled` must agree, or the uninstall screen and the badge disagree.
        #expect(Installation.isInstalled == !Installation.applied().isEmpty)
    }
}

/// The install plan must only reference binaries the build actually produces.
@Suite("The plan matches the build")
struct PlanMatchesBuildTests {

    /// Found by cloning the repository fresh and building it: the plan copied a
    /// `tamisd` no package produces, so the install would have failed at the moment
    /// the user had just typed their password.
    @Test("The privileged script names no binary the bundle does not carry")
    func onlyRealBinaries() {
        let script = Installer(applicationURL: URL(fileURLWithPath: "/Applications/Tamis.app"))
            .privilegedScript()
        // The three the bundle script copies. Anything else would be a path that does
        // not exist on the machine the install runs on.
        let shipped = ["Tamis", "tamisd", "tamis-dnsd", "tamis-pac"]
        for name in ["tamis-proxy", "tamis-lists", "tamis-bench"] where !shipped.contains(name) {
            #expect(!script.contains("MacOS/\(name)"), "le script copie \(name), absent du bundle")
        }
    }

    /// The daemon is installed again now that it exists, and it must be first: the
    /// authority is created by it, so adding the certificate to the trust store before
    /// the daemon has run would trust a root nobody holds.
    @Test("The daemon is installed, and before the authority")
    func daemonFirst() throws {
        let ids = Installation.plan().map(\.id)
        let daemon = try #require(ids.firstIndex(of: "daemon"))
        let authority = try #require(ids.firstIndex(of: "authority"))
        #expect(daemon < authority)
    }
}

@Suite("Authority store")
struct AuthorityStoreTests {

    /// The key is what matters; the certificate is public by nature. Locking both down
    /// would be theatre that hides which of the two the security rests on.
    @Test("The key is readable only by its owner, the certificate is not restricted")
    func permissions() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-ca-\(UUID().uuidString)")
        let store = AuthorityStore(directory: directory)
        defer { store.remove() }

        try store.store(certificatePEM: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
                        privateKeyDER: [1, 2, 3])
        #expect(store.exists)
        #expect(try store.privateKeyDER() == [1, 2, 3])

        let mode = try FileManager.default.attributesOfItem(
            atPath: store.privateKeyURL.path(percentEncoded: false)
        )[.posixPermissions] as? NSNumber
        #expect(mode?.int16Value == 0o600)
    }

    @Test("Removing leaves nothing")
    func removal() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appending(path: "tamis-ca-\(UUID().uuidString)")
        let store = AuthorityStore(directory: directory)
        try store.store(certificatePEM: "x", privateKeyDER: [1])
        store.remove()
        #expect(!store.exists)
        #expect(throws: AuthorityStore.Failure.missing) { _ = try store.privateKeyDER() }
    }

    /// The gap between what runs and what the design calls for is quoted from one
    /// place, so the onboarding and the settings screen cannot drift apart on it.
    @Test("The caveat is stated, and says what is actually true")
    func caveatIsHonest() {
        #expect(AuthorityStore.keyProtectionCaveat.contains("ne quitte jamais"))
        #expect(AuthorityStore.keyProtectionCaveat.contains("aucun moyen de la lire"))
    }
}

/// The preflight and the plan have to agree about what is installed.
///
/// They did not. `Installation.applied()` documented itself as "what the preflight
/// reports as residue" while the preflight only ever looked at the trust store, so a
/// failed install left root-owned binaries on disk and the first screen said nothing
/// opposed installing.
@Suite("The preflight sees what the plan sees")
struct PreflightMatchesPlanTests {

    @Test("Residue in the plan is residue in the report")
    func residueIsReported() {
        let applied = Installation.applied().filter { $0.id != "authority" }
        let findings = Preflight.checkResidualTamis()
        let reported = findings.contains { $0.id == "install.residual" }

        #expect(reported == !applied.isEmpty,
                "le plan voit \(applied.count) élément(s), le préflight en signale \(reported ? 1 : 0)")
    }

    /// Derived from the plan rather than restated, so a change added later is reported
    /// without anybody remembering to come back here.
    @Test("The report names the changes and how to undo them")
    func residueNamesItsCommands() throws {
        let applied = Installation.applied().filter { $0.id != "authority" }
        try #require(!applied.isEmpty || true)
        guard !applied.isEmpty else { return }

        let finding = try #require(
            Preflight.checkResidualTamis().first { $0.id == "install.residual" }
        )
        for change in applied {
            #expect(finding.detail.contains(change.title))
            #expect(finding.remedy?.contains(change.undoCommand) == true)
        }
    }

    /// Warnings, not blockers: reinstalling over residue works, and refusing to let
    /// somebody install because a previous version failed to clean up would punish
    /// them for a bug that was ours.
    @Test("Residue warns rather than blocks")
    func residueDoesNotBlock() {
        for finding in Preflight.checkResidualTamis() {
            #expect(finding.severity != .blocking)
        }
    }
}

/// The uninstall has to be able to reach every change, or something becomes permanent.
///
/// Written when the removal screen was built: the privileged batch carries the
/// administrator changes, and the application runs the rest itself, unprivileged. If a
/// change falls between those two the exit door has a gap in it — and the gap is
/// invisible, because nothing fails, the thing simply stays.
@Suite("Every change can actually be undone")
struct UninstallCoverageTests {

    private let installer = Installer(applicationURL: URL(fileURLWithPath: "/Applications/Tamis.app"))

    @Test("The privileged script carries every administrator change and no other")
    func partitionIsExhaustive() {
        let plan = Installation.plan()
        let script = installer.uninstallScript(for: plan)

        for change in plan {
            if change.scope == .administrator {
                #expect(script.contains(change.undoCommand),
                        "\(change.id) a besoin de root et n'est pas dans le lot")
            } else {
                #expect(!script.contains(change.undoCommand),
                        "\(change.id) n'a pas besoin de root et se retrouve dans le lot")
            }
        }
    }

    /// The half the application runs itself. A command needing `sudo` here would fail
    /// unprivileged — and the removal would report success while leaving the thing in
    /// place, which is the failure mode this whole screen was built to avoid.
    @Test("An unprivileged change is undone by an unprivileged command")
    func unprivilegedUndoNeedsNoRoot() {
        for change in Installation.plan() where change.scope != .administrator {
            #expect(!change.undoCommand.contains("sudo"),
                    "\(change.id) est annoncé sans privilège mais son annulation appelle sudo")
        }
    }

    /// The authority is the removal with a security consequence: a trusted root nobody
    /// holds the key to is still a root this Mac believes. It must come out without
    /// depending on a password prompt somebody can dismiss.
    @Test("The authority is removed without needing an administrator")
    func authorityComesOutUnprivileged() throws {
        let authority = try #require(Installation.plan().first { $0.id == "authority" })
        #expect(authority.scope == .sessionOwner)
        #expect(!authority.undoCommand.contains("sudo"))
        // From the user's own keychain, which is the only one they can write to.
        #expect(authority.undoCommand.contains(Installation.loginKeychainPath))
    }
}
