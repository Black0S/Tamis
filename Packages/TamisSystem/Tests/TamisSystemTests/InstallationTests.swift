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
        #expect(privileged.contains("authority"))
        #expect(privileged.contains("system-proxy"))
        // Serving a file on a loopback port needs nothing.
        #expect(plan.first { $0.id == "pac-helper" }?.scope == .user)
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
