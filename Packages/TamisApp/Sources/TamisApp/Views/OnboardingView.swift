import SwiftUI
import TamisSystem

/// The first run. Nine screens, one password, nothing left behind if abandoned.
struct OnboardingView: View {
    @Environment(OnboardingModel.self) private var model
    var onFinish: () -> Void = {}

    var body: some View {
        VStack(spacing: 0) {
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .padding(28)
            Divider()
            footer
        }
        .frame(width: 640, height: 520)
    }

    @ViewBuilder
    private var content: some View {
        switch model.step {
        case .welcome:     welcome
        case .preflight:   preflight
        case .whatChanges: whatChanges
        case .authorise:   authorise
        case .installing:  installing
        case .browsers:    ApplicationsView()
        case .dns:         dns
        case .verify:      verify
        case .done:        done
        }
    }

    // MARK: 0 — the contract

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Tamis").font(.largeTitle).fontWeight(.medium)
            // The contract, not marketing: what it does, and at what cost.
            Text("""
            Tamis filtre la publicité et la télémétrie pour **tous vos navigateurs à la \
            fois**, et pour les applications qui n'en sont pas — depuis l'extérieur du \
            navigateur, sans extension.
            """)
            Text("""
            Pour lire le HTTPS, il doit installer une autorité de certification sur ce \
            Mac. C'est un vrai pouvoir : un programme pourra déchiffrer votre trafic. \
            Les écrans suivants disent exactement ce que cela change, ce que Tamis ne \
            fera pas, et comment tout annuler.
            """)
            Text("Rien n'est modifié avant que vous ne l'autorisiez.")
                .foregroundStyle(.secondary)
            Spacer()
        }
    }

    // MARK: 1 — before asking anything

    private var preflight: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("État de ce Mac").font(.title2)
            Text("Vérifié avant de vous demander quoi que ce soit : les réponses "
                 + "changent ce qu'il y a à demander.")
                .foregroundStyle(.secondary)

            if model.report.findings.isEmpty {
                Label("Rien ne s'oppose à l'installation.", systemImage: "checkmark.circle")
                    .foregroundStyle(.green)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(model.report.findings) { finding in
                            GroupBox {
                                VStack(alignment: .leading, spacing: 4) {
                                    Label(finding.title, systemImage: symbol(finding.severity))
                                        .foregroundStyle(colour(finding.severity))
                                        .fontWeight(.medium)
                                    Text(finding.detail).font(.callout)
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                    if let remedy = finding.remedy {
                                        Text("→ \(remedy)").font(.callout)
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(4)
                            }
                        }
                    }
                }
            }
            Spacer()
        }
    }

    // MARK: 2 — the one that matters

    private var whatChanges: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Ce que Tamis va faire").font(.title2)

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(model.changes) { change in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: symbol(change.scope))
                                .foregroundStyle(.secondary).font(.caption).frame(width: 14)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(change.title).fontWeight(.medium)
                                Text(change.effect).font(.callout).foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }

                    Divider().padding(.vertical, 6)

                    // The second half counts as much as the first. Software that states
                    // its limits is more credible than software that states only its
                    // powers.
                    Text("Ce que Tamis ne fait pas").fontWeight(.medium)
                    ForEach(model.limits, id: \.self) { limit in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text("·").foregroundStyle(.tertiary)
                            Text(limit).font(.callout).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }
        }
    }

    // MARK: 3 — the single password

    private var authorise: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Votre mot de passe").font(.title2)
            // It used to promise a single prompt. macOS guards the trust store with an
            // authorisation right that can only be satisfied by authenticating in a
            // session able to show a dialog, which the batch is not — so the count is
            // two, and saying "one" would be the kind of small lie that makes the rest
            // of these screens not worth reading.
            Text("""
            macOS va vous le demander **deux fois**, et les deux demandes sont \
            différentes.
            """)
            VStack(alignment: .leading, spacing: 6) {
                Label {
                    Text("**Les fichiers et les services** — un seul lot, via `osascript`.")
                } icon: { Text("1.").monospacedDigit().foregroundStyle(.secondary) }
                Label {
                    // One literal, not a concatenation: `Text` only parses markdown in
                    // a literal, and a joined string renders its asterisks verbatim.
                    Text("""
                    **L'autorité de certification** — macOS pose lui-même la question, \
                    et nomme le certificat qu'il va approuver.
                    """)
                } icon: { Text("2.").monospacedDigit().foregroundStyle(.secondary) }
            }
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)

            Text("Si vous annulez, rien n'aura changé.").foregroundStyle(.secondary)

            DisclosureGroup("Voir les commandes exactes") {
                ScrollView {
                    Text(model.installer.privilegedScript()
                         + "\n\n# Puis, séparément, sans osascript :\n"
                         + model.installer.trustCommand())
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
            }
            Spacer()
        }
    }

    // MARK: 4 — transactional

    private var installing: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Installation").font(.title2)
            if model.operations.isEmpty && !model.isWorking && model.failure == nil {
                // Reached without installing means something skipped the step. Saying
                // so beats an empty panel that reads as success.
                Label("Rien n'a été appliqué. Revenez à l'écran précédent et choisissez "
                      + "« Installer ».", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(model.operations) { operation in
                Label(
                    operation.description,
                    systemImage: operation.succeeded ? "checkmark.circle" : "xmark.circle"
                )
                .foregroundStyle(operation.succeeded ? .green : .red)
            }
            if model.isWorking { ProgressView().controlSize(.small) }
            if let failure = model.failure {
                // Undone in reverse rather than left half-done: a half-installed Mac is
                // worse than an uninstalled one, because its owner cannot tell which
                // half.
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("L'installation a échoué et a été annulée",
                              systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                        Text(failure).font(.callout).foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)

                        // When the undo could not finish, the commands to finish it by
                        // hand are worth more than an apology.
                        if !model.residue.isEmpty {
                            Divider()
                            Text("Ceci subsiste sur le Mac. À retirer à la main :")
                                .font(.callout)
                            ForEach(model.residue) { change in
                                Text(change.undoCommand)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
                }
            }
            Spacer()
        }
    }

    // MARK: 6 — DNS

    private var dns: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Résolveur DNS").font(.title2)
            Text("""
            Les requêtes DNS partent chiffrées. Le résolveur est contacté par adresse \
            IP : Tamis ne résout jamais le nom de son propre résolveur, sinon la \
            première requête fuiterait en clair.
            """)
            .foregroundStyle(.secondary)
            DNSView()
            Spacer()
        }
    }

    // MARK: 7 — prove rather than announce

    private var verify: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Vérification").font(.title2)
            Text("""
            Cinq essais réels contre le banc local. Si quelque chose ne va pas, vous \
            l'apprenez ici — pas dans trois jours devant un site cassé.
            """)
            .foregroundStyle(.secondary)

            if model.isVerifying {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Essais en cours…").foregroundStyle(.secondary)
                }
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(model.checks) { check in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 4) {
                                Label(check.title,
                                      systemImage: check.passed
                                          ? "checkmark.circle" : "xmark.octagon")
                                    .foregroundStyle(check.passed ? .green : .red)
                                    .fontWeight(.medium)
                                Text(check.detail)
                                    .font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                                // Shown only when it failed: what it means is what
                                // somebody needs at the moment it goes wrong, and
                                // printing it beside every tick would train people to
                                // skip it.
                                if !check.passed {
                                    Text(check.matters).font(.callout)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(4)
                        }
                    }
                }
            }

            if model.verificationFailed {
                Label("Un essai a échoué. Le bouton « Réessayer » relance les cinq.",
                      systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                Button("Réessayer") { Task { await model.verify() } }
            }
        }
    }

    private var done: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Terminé").font(.title2)
            Text("Tamis vit dans la barre des menus. L'icône dit son état par sa forme, "
                 + "jamais par sa couleur.")
                .foregroundStyle(.secondary)
            Text("""
            Aucune liste de filtres n'est activée : le choix vous revient. Le catalogue \
            en propose 165, et « Sélection suggérée » en active onze en un clic.
            """)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack {
            Text("\(model.step.rawValue + 1) / \(OnboardingModel.Step.allCases.count)")
                .font(.caption).foregroundStyle(.tertiary).monospacedDigit()
            Spacer()
            if model.step != .done {
                Button("Annuler") {
                    Task { await model.cancel(); onFinish() }
                }
                .keyboardShortcut(.cancelAction)
            }
            if model.step.rawValue > 0 && model.step != .done {
                Button("Retour") { model.back() }
            }
            Button(nextTitle) {
                switch model.step {
                case .done:      onFinish()
                // The button that says "Installer" installs. It used to call the same
                // `advance()` as every other screen, which walked past the whole
                // installation without doing any of it — the flow completed and the
                // machine was untouched.
                case .authorise: Task { await model.installNow() }
                default:         model.advance()
                }
            }
            .buttonStyle(.borderedProminent)
            // Return moves forward and Escape backs out. Nine screens without a
            // keyboard is nine screens somebody has to reach for the mouse on.
            .keyboardShortcut(.defaultAction)
            .disabled(model.step == .preflight && !model.canProceedFromPreflight)
        }
        .padding(.horizontal, 20).padding(.vertical, 12)
    }

    private var nextTitle: String {
        switch model.step {
        case .authorise: "Installer"
        case .done:      "Ouvrir Tamis"
        default:         "Continuer"
        }
    }

    /// Three states, not two: a change can touch nothing outside the user's own account
    /// and still stop to ask them.
    private func symbol(_ scope: SystemChange.Scope) -> String {
        switch scope {
        case .administrator: "lock.fill"
        case .sessionOwner:  "person.badge.key.fill"
        case .user:          "person.fill"
        }
    }

    private func symbol(_ severity: Preflight.Finding.Severity) -> String {
        switch severity {
        case .blocking: "xmark.octagon"
        case .warning:  "exclamationmark.triangle"
        case .note:     "info.circle"
        }
    }

    private func colour(_ severity: Preflight.Finding.Severity) -> Color {
        switch severity {
        case .blocking: .red
        case .warning:  .orange
        case .note:     .secondary
        }
    }
}
