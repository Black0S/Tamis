import AppKit
import SwiftUI
import TamisLists
import TamisSystem

/// Settings, and the two screens the design owes the user.
///
/// The HTTPS exclusions and the internal allowlist are not preferences: they are the
/// two places where Tamis decides something on its own and the user has to be able to
/// check it. Until now they were only readable from a terminal, which is the same as
/// not being readable.
struct SettingsView: View {
    enum Tab: String, CaseIterable, Identifiable {
        case general, exclusions, allowlist, about
        var id: String { rawValue }

        var title: String {
            switch self {
            case .general:    "Général"
            case .exclusions: "Jamais déchiffré"
            case .allowlist:  "Domaines système"
            case .about:      "À propos"
            }
        }

        var symbol: String {
            switch self {
            case .general:    "gearshape"
            case .exclusions: "lock.shield"
            case .allowlist:  "checkmark.shield"
            case .about:      "info.circle"
            }
        }
    }

    @State private var tab: Tab = .general

    var body: some View {
        VStack(spacing: 0) {
            Picker("Section", selection: $tab) {
                ForEach(Tab.allCases) { Label($0.title, systemImage: $0.symbol).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 20).padding(.vertical, 12)

            Divider()

            switch tab {
            case .general:    GeneralSettings()
            case .exclusions: ExclusionsSettings()
            case .allowlist:  AllowlistSettings()
            case .about:      AboutSettings()
            }
        }
        .navigationTitle("Réglages")
    }
}

// MARK: - General

struct GeneralSettings: View {
    @Environment(FilterListsModel.self) private var lists
    @Environment(ScriptsModel.self) private var scripts
    @Environment(HistoryModel.self) private var history

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Où Tamis range ses données").font(.headline)
                        Text("""
                        Tout tient dans ces dossiers. Les copier suffit à faire une \
                        sauvegarde, et à emporter la configuration sur une autre machine.
                        """)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                        LocationRow("Listes de filtres", lists.manager.storeRoot)
                        LocationRow("Scripts et styles", scripts.store.root)
                        LocationRow("Journal des décisions", history.store.url)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
                Spacer(minLength: 0)
            }
            .padding(20)
        }
    }
}

private struct LocationRow: View {
    let label: String
    let url: URL

    init(_ label: String, _ url: URL) {
        self.label = label
        self.url = url
    }

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text(label).font(.callout)
                Text(url.path(percentEncoded: false))
                    .font(.caption).foregroundStyle(.tertiary)
                    .lineLimit(1).truncationMode(.head).textSelection(.enabled)
            }
            Spacer()
            Button("Révéler") { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                .buttonStyle(.link)
        }
    }
}

// MARK: - Exclusions

/// The promise the whole design rests on, made checkable.
///
/// The question is not "how many domains are excluded" but "is *mine*" — so the search
/// answers by naming the list, the scope and any application restriction, rather than
/// with a yes.
struct ExclusionsSettings: View {
    @State private var query = ""
    private let set = BundledExclusions.makeSet()
    private var sources: [ExclusionSource] { BundledExclusions.sources }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Un hôte est-il protégé ?").font(.headline)
                        TextField("Saisissez un nom d'hôte", text: $query)
                            .textFieldStyle(.roundedBorder)

                        if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                            let matches = set.allMatches(host: query)
                            if matches.isEmpty {
                                Label("Cet hôte serait déchiffré.",
                                      systemImage: "exclamationmark.triangle")
                                    .foregroundStyle(.orange)
                            } else {
                                ForEach(Array(matches.enumerated()), id: \.offset) { _, match in
                                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                                        Image(systemName: "lock.fill")
                                            .foregroundStyle(.secondary).font(.caption)
                                        VStack(alignment: .leading, spacing: 1) {
                                            Text(match.sourceName).font(.callout)
                                            Text(scopeText(match))
                                                .font(.caption).foregroundStyle(.tertiary)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Sources").font(.headline)
                        Text("""
                        Chaque source garde son origine, sa licence et son compteur. \
                        Elles ne sont jamais fusionnées : autrement, on ne saurait plus \
                        chez qui signaler un domaine manquant.
                        """)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                        ForEach(sources) { source in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Image(systemName: source.lock == .hard ? "lock.fill" : "lock.open")
                                    .foregroundStyle(source.lock == .hard ? .primary : .secondary)
                                    .font(.caption).frame(width: 14)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text("\(source.provider) · \(source.name)").font(.callout)
                                    Text(lockText(source.lock)).font(.caption)
                                        .foregroundStyle(.tertiary)
                                }
                                Spacer()
                                Text("\(source.entries.count.formatted()) hôtes")
                                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                                Text(source.licence).font(.caption2).foregroundStyle(.tertiary)
                            }
                        }

                        Divider()
                        HStack {
                            Text("Hôtes distincts").font(.callout)
                            Spacer()
                            Text(set.distinctPatternCount.formatted())
                                .font(.callout).monospacedDigit()
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
                Spacer(minLength: 0)
            }
            .padding(20)
        }
    }

    private func scopeText(_ match: ExclusionSet.Match) -> String {
        let scope = switch match.entry.scope {
        case .exact:               "cet hôte exactement"
        case .domainAndSubdomains: "ce domaine et ses sous-domaines"
        case .wildcard:            "par motif"
        }
        guard !match.entry.apps.isEmpty else { return "\(match.entry.pattern) — \(scope)" }
        return "\(match.entry.pattern) — \(scope), pour "
             + match.entry.apps.sorted().joined(separator: ", ")
    }

    private func lockText(_ lock: ExclusionSource.Lock) -> String {
        switch lock {
        case .hard:               "Verrouillée — aucune entrée ne peut être désactivée."
        case .entriesOverridable: "Correctifs de compatibilité — une entrée peut être surchargée."
        case .editable:           "La vôtre."
        }
    }
}

// MARK: - Internal allowlist

/// Read-only, and the reason it exists at all.
///
/// A hard-coded, invisible allowlist inside software that intercepts every connection
/// has the exact shape of a back door. The answer is not to promise it is short; it is
/// to show it, with each entry's justification.
struct AllowlistSettings: View {
    private let allowlist = InternalAllowlist.shared

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Jamais bloqués, sans exception").font(.headline)
                        Text("""
                        Une liste de blocage peut contenir le domaine d'où les listes se \
                        téléchargent. Ces \(allowlist.entries.count) hôtes passent avant \
                        tout le reste — listes, règles personnelles, exclusions — et \
                        c'est la seule règle du système sans exception.
                        """)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                ForEach([InternalAllowlist.Entry.Purpose.encryptedDNS,
                         .filterListSource, .appUpdate], id: \.rawValue) { purpose in
                    let entries = allowlist.entries(for: purpose)
                    if !entries.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("\(purpose.title) — \(entries.count)").font(.headline)
                                ForEach(entries) { entry in
                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(entry.host)
                                            .font(.system(.callout, design: .monospaced))
                                            .textSelection(.enabled)
                                        Text(entry.justification)
                                            .font(.caption).foregroundStyle(.tertiary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(6)
                        }
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(20)
        }
    }
}

// MARK: - About

struct AboutSettings: View {
    @State private var update: UpdateCheck.Outcome?
    @State private var isChecking = false

    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Tamis").font(.headline)
                        Text("Bloqueur de publicité et de télémétrie pour macOS, "
                             + "entièrement en Swift. GPLv3.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("Version \(version)").foregroundStyle(.secondary)
                        Link("github.com/Black0S/Tamis",
                             destination: URL(string: "https://github.com/Black0S/Tamis")!)

                        Divider().padding(.vertical, 2)

                        // Checked on request, never in the background: a program that
                        // phones home on a timer is a program that phones home.
                        HStack(spacing: 10) {
                            Button("Vérifier les mises à jour") {
                                isChecking = true
                                Task {
                                    update = await UpdateCheck().run()
                                    isChecking = false
                                }
                            }
                            .disabled(isChecking)
                            if isChecking { ProgressView().controlSize(.small) }
                        }

                        switch update {
                        case .none:
                            EmptyView()
                        case .upToDate(let current):
                            Label("Version \(current) — à jour", systemImage: "checkmark.circle")
                                .foregroundStyle(.secondary)
                        case .unavailable(let reason):
                            Label("Vérification impossible : \(reason)",
                                  systemImage: "wifi.exclamationmark")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        case .available(let release):
                            VStack(alignment: .leading, spacing: 4) {
                                Label("\(release.name) est disponible", systemImage: "arrow.down.circle")
                                // Nothing is downloaded here, and the reason is said
                                // rather than left as an absence.
                                Text("""
                                Tamis n'installe pas ses propres mises à jour : sans \
                                Developer ID il n'y a aucune signature à vérifier, et \
                                un logiciel qui se place au milieu de TLS ne devrait \
                                pas être celui qui exécute un binaire téléchargé sur la \
                                foi d'un certificat.
                                """)
                                .font(.callout).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                                Link("Voir la version publiée", destination: release.url)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                // Written here and not only in the README, because the person who needs
                // it is the one deciding whether to trust the application.
                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Ce que Tamis ne fait pas").font(.headline)
                        Bullet("N'envoie rien nulle part. Aucune télémétrie, pas même "
                               + "un rapport de plantage.")
                        Bullet("Ne déchiffre ni les banques ni les gestionnaires de mots "
                               + "de passe. Les listes sont embarquées et verrouillées.")
                        Bullet(AuthorityStore.keyProtectionCaveat)
                        Bullet("N'intercepte ni Tor Browser ni Mullvad Browser.")
                        Bullet("N'affiche aucun chiffre qu'il ne peut pas mesurer — il "
                               + "n'y a pas de « données économisées » : une requête "
                               + "bloquée n'est jamais téléchargée, donc sa taille est "
                               + "inconnue.")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Ce qui n'est pas chiffré").font(.headline)
                        Text("""
                        Le journal des décisions est un fichier en 0600, non chiffré par \
                        Tamis. FileVault est ce qui le protège réellement, et le vrai \
                        levier reste la rétention courte et le bouton « Effacer \
                        l'historique ». Ajouter une dépendance de chiffrement pour une \
                        base déjà chiffrée par le disque serait du théâtre — c'est écrit \
                        ici plutôt que passé sous silence.
                        """)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Ce qui n'est pas encore fait").font(.headline)
                        Text("""
                        Tamis ne s'installe pas encore : le proxy système n'est pas \
                        configuré, le port 53 n'est pas pris, et l'autorité n'est pas \
                        dans le trousseau. Rien de ce que vous voyez ici ne filtre votre \
                        trafic pour l'instant.
                        """)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
                Spacer(minLength: 0)
            }
            .padding(20)
        }
    }
}

private struct Bullet: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("•").foregroundStyle(.tertiary)
            Text(text).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
