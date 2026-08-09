import SwiftUI
import TamisApps

/// Which applications Tamis touches, and why it suggests what it suggests.
struct ApplicationsView: View {
    @Environment(ApplicationsModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                scanScope
                ForEach(model.rows) { BrowserCard(row: $0) }
                pinnedSection
                Spacer(minLength: 0)
            }
            .padding(20)
        }
        .navigationTitle("Applications")
        .onAppear { model.reload() }
    }

    /// Written on the screen, not only in the README. Software that reads browser
    /// profiles owes the user a precise statement of what it opens.
    private var scanScope: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Label("Ce que Tamis lit", systemImage: "eye")
                    .font(.headline)
                Text("""
                Le registre des applications de macOS, et la structure des bundles pour \
                reconnaître le moteur. **Jamais** l'historique, les cookies, les mots de \
                passe ni les favoris.
                """)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            .padding(4)
        }
    }

    private var pinnedSection: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label("Applications jamais déchiffrées", systemImage: "lock")
                    .font(.headline)
                Text("""
                Ces logiciels épinglent leurs certificats : déchiffrés, ils ne se \
                connectent pas du tout. L'exclusion n'est pas un confort.
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                ForEach(model.pinned, id: \.bundleID) { entry in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(entry.bundleID)
                            .font(.system(.callout, design: .monospaced))
                        Spacer()
                        Text(entry.reason).font(.caption).foregroundStyle(.tertiary)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }
}

struct BrowserCard: View {
    @Environment(ApplicationsModel.self) private var model
    let row: ApplicationsModel.Row

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(row.browser.name).font(.headline)
                            if row.isDefaultBrowser {
                                Text("par défaut").font(.caption2)
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(.secondary.opacity(0.15), in: .capsule)
                            }
                            if row.policy.isLocked {
                                Image(systemName: "lock.fill")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Text("\(row.browser.bundleID) · \(row.browser.engine.title)")
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                    Spacer()

                    Picker("Traitement", selection: .init(
                        get: { row.policy.treatment },
                        set: { model.setTreatment($0, for: row.id) }
                    )) {
                        ForEach(AppPolicy.Treatment.allCases, id: \.self) { treatment in
                            Text(treatment.title).tag(treatment)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 280)
                    // A locked browser shows its state and refuses to change it. Hiding
                    // the control would leave the user wondering where it went.
                    .disabled(row.policy.isLocked)
                }

                // Never a bare verdict: the landscape is what justifies the suggestion,
                // and a recommendation nobody can check is one nobody should follow.
                Text(row.policy.rationale.text)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(6)
        }
    }
}
