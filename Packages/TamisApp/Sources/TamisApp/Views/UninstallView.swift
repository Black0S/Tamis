import SwiftUI
import TamisSystem

/// The way out, made as reachable as the way in.
///
/// Shaped like the first-run flow on purpose: what is in place, what each removal does,
/// the exact commands, then one confirmation. Somebody who installed Tamis by reading
/// four screens should not have to leave by copying commands out of a text field.
struct UninstallView: View {
    @State private var model = UninstallModel()
    @State private var isConfirming = false
    var onFinished: () -> Void = {}

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if model.finished {
                    outcome
                } else if model.isInstalled {
                    plan
                } else {
                    nothingInstalled
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
        }
        .onAppear { model.refresh() }
    }

    // MARK: Nothing to do

    private var nothingInstalled: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label("Tamis n'est pas installé sur ce Mac", systemImage: "checkmark.circle")
                    .font(.headline).foregroundStyle(.green)
                Text("Aucun service, aucune autorité dans le trousseau, aucun réglage "
                     + "réseau. Il n'y a rien à retirer.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !model.userData.isEmpty {
                    Divider()
                    Text("Vos listes et vos scripts sont conservés — ils ne dépendent "
                         + "pas de l'installation.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }

    // MARK: What will be removed

    private var plan: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Désinstaller Tamis").font(.title2)

            // The authority first, in words: it is the one removal with a security
            // consequence, and the one nobody should have to infer from a list.
            GroupBox {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Ce qui compte le plus", systemImage: "lock.open")
                        .font(.headline)
                    Text("""
                    L'autorité de certification est retirée de votre trousseau. Après \
                    cela, plus aucun programme de ce Mac ne peut déchiffrer votre \
                    HTTPS avec elle — c'est le pouvoir que l'installation avait \
                    accordé, et c'est celui qui vous est rendu.
                    """)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }

            Text("Ce qui va être retiré").fontWeight(.medium)
            ForEach(model.applied) { change in
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

            Divider()

            // Two decisions, kept apart. Uninstalling the software is not the same as
            // discarding the lists and scripts somebody chose.
            Toggle(isOn: $model.alsoRemoveUserData) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Supprimer aussi mes données")
                    Text(model.userData.isEmpty
                         ? "Aucune donnée enregistrée."
                         : model.userData.map(\.lastPathComponent).joined(separator: ", "))
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .disabled(model.userData.isEmpty)

            DisclosureGroup("Voir les commandes exactes") {
                ScrollView {
                    Text(model.script)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
            }

            HStack {
                Button("Désinstaller Tamis", role: .destructive) { isConfirming = true }
                    .buttonStyle(.borderedProminent)
                    .disabled(model.isWorking)
                if model.isWorking { ProgressView().controlSize(.small) }
            }
            .confirmationDialog(
                "Retirer Tamis de ce Mac ?",
                isPresented: $isConfirming, titleVisibility: .visible
            ) {
                Button("Désinstaller", role: .destructive) { Task { await model.uninstall() } }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text(model.alsoRemoveUserData
                     ? "Vos listes, scripts et historique seront également supprimés. "
                       + "Cette partie n'est pas récupérable."
                     : "Vos listes, scripts et historique sont conservés.")
            }

            if !model.applied.filter({ $0.scope == .administrator }).isEmpty {
                Text("macOS demandera votre mot de passe une fois, pour les éléments "
                     + "système. L'autorité, elle, est dans votre trousseau et se "
                     + "retire sans privilège.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: What actually happened

    private var outcome: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Désinstallation").font(.title2)

            ForEach(model.steps) { step in
                Label(step.description,
                      systemImage: step.succeeded ? "checkmark.circle" : "xmark.circle")
                    .foregroundStyle(step.succeeded ? .green : .red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let failure = model.failure {
                GroupBox {
                    Text(failure).font(.callout).foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(4)
                }
            }

            // Read from the machine, not from the log above. A removal that reports
            // its own success without looking is what this screen exists to not be.
            if model.residue.isEmpty {
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("Ce Mac est revenu à son état d'avant Tamis",
                              systemImage: "checkmark.seal")
                            .font(.headline).foregroundStyle(.green)
                        Text("Vérifié en relisant la machine : aucun service, aucune "
                             + "autorité, aucun réglage réseau. Vous pouvez maintenant "
                             + "jeter l'application.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            } else {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Ceci subsiste", systemImage: "exclamationmark.triangle")
                            .font(.headline).foregroundStyle(.orange)
                        ForEach(model.residue) { change in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(change.title).fontWeight(.medium)
                                Text(change.undoCommand)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Text("Scripts/tamis-rescue.sh retire tout cela sans l'application.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            }

            Button("Terminer", action: onFinished).buttonStyle(.borderedProminent)
        }
    }
}
