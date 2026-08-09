import SwiftUI
import TamisDNS

/// The resolver: which upstream, whether it is running, and what it has decided.
struct DNSView: View {
    @Environment(ResolverModel.self) private var resolver
    @Environment(EngineModel.self) private var engines

    var body: some View {
        @Bindable var resolver = resolver

        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                status
                providerPicker
                if resolver.state.isRunning { counters; howToTest }
                if !resolver.recent.isEmpty { decisions }
                Spacer(minLength: 0)
            }
            .padding(20)
        }
        .navigationTitle("DNS")
    }

    // MARK: Status

    private var status: some View {
        GroupBox {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Résolveur local").font(.headline)
                    switch resolver.state {
                    case .stopped:
                        Text("Arrêté. Le Mac utilise son résolveur habituel.")
                            .foregroundStyle(.secondary)
                    case .running(let port):
                        Text("En écoute sur 127.0.0.1:\(String(port))")
                            .foregroundStyle(.secondary).monospacedDigit()
                    case .failed(let reason):
                        Label(reason, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }
                Spacer()
                Button(resolver.state.isRunning ? "Arrêter" : "Démarrer") {
                    Task {
                        if resolver.state.isRunning {
                            await resolver.stop()
                        } else {
                            await resolver.start(blocklist: engines.state.compiled?.dns ?? .init(lines: []))
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(engines.state.isBuilding)
            }
            .padding(4)
        }
    }

    /// Said plainly rather than left implicit: this is not the installed state, and a
    /// user who thinks their machine is filtered when it is not is worse off than one
    /// who knows it is not.
    private var howToTest: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label("Rien n'est modifié sur le Mac", systemImage: "info.circle")
                    .font(.headline)
                Text("""
                Le résolveur écoute sur un port local. Les réglages réseau du Mac ne sont \
                pas touchés, donc le système ne l'utilise pas encore. Pour l'essayer :
                """)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                if let port = resolver.state.port {
                    Text("dig @127.0.0.1 -p \(String(port)) ads.doubleclick.net")
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.4), in: .rect(cornerRadius: 6))
                }
            }
            .padding(6)
        }
    }

    // MARK: Provider

    private var providerPicker: some View {
        @Bindable var resolver = resolver

        return GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Picker("Résolveur chiffré", selection: $resolver.provider) {
                    ForEach(DoHProvider.presets, id: \.name) { provider in
                        Text(provider.name).tag(provider)
                    }
                }
                .onChange(of: resolver.provider) {
                    guard resolver.state.isRunning else { return }
                    Task {
                        await resolver.restart(
                            blocklist: engines.state.compiled?.dns ?? .init(lines: [])
                        )
                    }
                }

                // The invariant behind the whole layer, stated where it is chosen.
                Text("""
                Les requêtes partent chiffrées vers \(resolver.provider.hostname), \
                contactée par adresse IP — Tamis ne résout jamais le nom de son propre \
                résolveur, sinon la première requête fuiterait en clair.
                """)
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
            .padding(4)
        }
    }

    // MARK: Counters

    private var counters: some View {
        HStack(spacing: 12) {
            Counter("requêtes", resolver.statistics.queries)
            Counter("bloquées", resolver.statistics.blocked)
            Counter("cache", resolver.statistics.cacheHits)
            Counter("transmises", resolver.statistics.forwarded)
            // Reported next to the rest rather than hidden: a resolver failing upstream
            // still answers, and the answers are worse.
            Counter("échecs amont", resolver.statistics.upstreamFailures)
        }
    }

    private var decisions: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 0) {
                Text("Dernières décisions").font(.headline).padding(.bottom, 6)
                ForEach(resolver.recent.prefix(15)) { decision in
                    HStack {
                        Image(systemName: decision.isBlocked ? "hand.raised" : "arrow.right")
                            .foregroundStyle(decision.isBlocked ? .orange : .secondary)
                            .frame(width: 16)
                        Text(decision.name).font(.callout)
                        Spacer()
                        if case .block(let reason) = decision.outcome {
                            switch reason {
                            case .blocklist(let matched):
                                Text(matched).font(.caption).foregroundStyle(.tertiary)
                            case .firefoxCanary:
                                Text("canari Firefox").font(.caption).foregroundStyle(.tertiary)
                            }
                        }
                        Text(decision.date, style: .time)
                            .font(.caption).foregroundStyle(.tertiary).monospacedDigit()
                    }
                    .padding(.vertical, 2)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(6)
        }
    }
}

private struct Counter: View {
    let label: String
    let value: Int

    init(_ label: String, _ value: Int) {
        self.label = label
        self.value = value
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 2) {
                Text(value.formatted()).font(.title3).fontWeight(.medium).monospacedDigit()
                Text(label).font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(2)
        }
    }
}
