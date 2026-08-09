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
                            Image(systemName: change.scope == .administrator
                                  ? "lock.fill" : "person.fill")
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
            Text("""
            macOS va vous le demander **une seule fois**, pour appliquer les \
            modifications administrateur en un seul lot.
            """)
            Text("Si vous annulez, rien n'aura changé.").foregroundStyle(.secondary)

            DisclosureGroup("Voir les commandes exactes") {
                ScrollView {
                    Text(model.installer.privilegedScript(
                        authorityPEM: URL(fileURLWithPath: "…/ca.pem")
                    ))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 220)
            }
            Spacer()
        }
    }

    // MARK: 4 — transactional

    private var installing: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Installation").font(.title2)
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

            // The checks belong to the running installation, which does not exist until
            // the joint first install. Saying so beats a row of ticks that mean nothing.
            GroupBox {
                Label("Ces essais s'exécuteront lors de la première installation réelle.",
                      systemImage: "info.circle")
                    .foregroundStyle(.secondary)
                    .padding(4)
            }
            Spacer()
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
            }
            if model.step.rawValue > 0 && model.step != .done {
                Button("Retour") { model.back() }
            }
            Button(nextTitle) {
                if model.step == .done { onFinish() } else { model.advance() }
            }
            .buttonStyle(.borderedProminent)
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
