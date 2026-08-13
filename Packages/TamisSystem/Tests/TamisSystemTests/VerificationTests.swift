import Foundation
import JavaScriptCore
import Testing
@testable import TamisSystem

/// The screen that proves rather than announces.
///
/// Its predecessor said the checks "will run at the first real installation" and never
/// ran any. That is worse than saying nothing: a promise of verification leaves somebody
/// more confident than silence would have, so an unkept one is a false reassurance with
/// extra steps.
@Suite("Verification")
struct VerificationTests {

    /// The property that decides whether this screen is worth having at all.
    ///
    /// Nothing is installed on a machine running the tests. Every check must therefore
    /// report failure — a check that goes green on an empty Mac is a check that would go
    /// green on a broken one, and the screen would be decoration.
    @Test("On a Mac with nothing installed, nothing reports success")
    func noVacuousGreen() async throws {
        try #require(Installation.applied().isEmpty,
                     "ce test n'a de sens que sur une machine sans Tamis installé")

        for check in await Verification.run() {
            #expect(!check.passed, "« \(check.title) » réussit alors que rien n'est installé")
        }
    }

    @Test("Five checks, each identified once")
    func fiveDistinctChecks() async {
        let checks = await Verification.run()
        #expect(checks.count == 5)
        #expect(Set(checks.map(\.id)).count == checks.count)
    }

    /// A failed check is read at the moment something is wrong, which is the moment
    /// somebody least wants to decode a status code.
    @Test("Every check says what it is and what a failure would mean")
    func everyCheckExplainsItself() async {
        for check in await Verification.run() {
            #expect(!check.title.isEmpty, "\(check.id) n'a pas de titre")
            #expect(check.matters.count > 60, "\(check.id) n'explique pas ce qui est en jeu")
            #expect(!check.detail.isEmpty, "\(check.id) ne dit pas ce qu'il a observé")
        }
    }

    /// The resolver check is the reason this screen exists in its current form: a
    /// resolver that never answers, while the system DNS points at it, takes the Mac
    /// offline until somebody edits network settings by hand.
    @Test("The resolver check reports on the loopback resolver, not on DNS in general")
    func resolverCheckIsAboutTamis() {
        let check = Verification.resolverAnswers()
        #expect(check.id == "resolver")
        // It must name the address it tried, or a failure says nothing actionable.
        #expect(check.detail.contains("127.0.0.1"))
    }

    /// Inverted on purpose: it passes when the file cannot be read. Everything else here
    /// confirms that something works; this one confirms that something is impossible,
    /// which is the only kind of security claim worth printing.
    @Test("The key check fails when the key is readable, not when it is missing a tick")
    func keyCheckIsInverted() throws {
        let check = Verification.signingKeyIsOutOfReach()
        let path = Installation.privilegedDirectory.appending(path: "Authority/ca.key")
            .path(percentEncoded: false)

        if FileManager.default.isReadableFile(atPath: path) {
            #expect(!check.passed, "la clé est lisible et le contrôle réussit quand même")
        } else if FileManager.default.fileExists(atPath: path) {
            #expect(check.passed)
        } else {
            // No installation: absent is not the same as protected, and the check must
            // not pretend otherwise.
            #expect(!check.passed)
            #expect(check.detail.contains("aucune clé"))
        }
    }

    /// The claim the exclusion list exists for, checked against the script macOS itself
    /// would evaluate rather than against the list Tamis holds in memory.
    ///
    /// The hosts are handed in rather than read from `BundledExclusions`, which lives in
    /// `TamisLists` — a package this one deliberately does not depend on. So this proves
    /// what `TamisSystem` owns: that a host given as an exclusion is answered `DIRECT`.
    /// Whether these particular banks are *in* the shipped list is `TamisLists`' claim,
    /// and it is tested there.
    @Test("A banking host is answered DIRECT by the generated script", arguments: [
        "www.bnpparibas", "www.credit-agricole.fr", "www.labanquepostale.fr",
    ])
    func banksGoDirect(host: String) throws {
        let script = ProxyAutoConfig.script(
            proxyPort: 7654,
            directHosts: ["bnpparibas", "credit-agricole.fr", "labanquepostale.fr"]
        )
        // Evaluated the way macOS evaluates it, not by searching the text for the
        // hostname: a host can appear in the script and still be routed to the proxy.
        let context = try #require(JSContext())
        context.evaluateScript(script)
        let verdict = context.objectForKeyedSubscript("FindProxyForURL")?
            .call(withArguments: ["https://\(host)/", host])?.toString() ?? "<nil>"

        #expect(verdict.uppercased().contains("DIRECT"),
                "\(host) irait au proxy : « \(verdict) »")
    }
}
