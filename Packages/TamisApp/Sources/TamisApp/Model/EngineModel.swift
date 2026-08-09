import Foundation
import Observation
import TamisDNS
import TamisFilterEngine
import TamisLists

/// Turns the lists on disk into the three things that actually decide.
///
/// Compiling half a million rules takes seconds, so it happens off the main actor and
/// the interface says so while it runs. Until it finishes there is no engine, and the
/// difference between *not built yet* and *built and empty* is one the screens have to
/// be able to state — a filter count of zero means nothing on its own.
@MainActor
@Observable
final class EngineModel {

    struct Compiled: Sendable {
        let network: FilterEngine
        let cosmetic: CosmeticEngine
        let dns: DomainBlocklist
        let listCount: Int
        let builtAt: Date
        let duration: TimeInterval

        var networkRules: Int { network.stats.networkRules }
        var cosmeticRules: Int { cosmetic.stats.rules }
        var blockedDomains: Int { dns.count }
        /// Rules the engine understood but does not enforce as a block. Reported rather
        /// than folded into the total: coverage claims are only worth something when
        /// what is missing is counted too.
        var notEnforced: Int {
            network.stats.rulesWithUnsupportedModifiers + network.stats.rulesThatChangeRatherThanBlock
        }
    }

    enum State: Sendable {
        /// Nothing compiled yet, and nothing tried.
        case idle
        case building
        case ready(Compiled)

        var compiled: Compiled? { if case .ready(let c) = self { c } else { nil } }
        var isBuilding: Bool { if case .building = self { true } else { false } }
    }

    private(set) var state: State = .idle
    private let manager: ListManager
    private var buildTask: Task<Void, Never>?

    init(manager: ListManager) {
        self.manager = manager
    }

    /// Rebuilds from whatever is enabled now.
    ///
    /// A rebuild already under way is cancelled: toggling three lists in a row should
    /// compile once, at the end, not three times over each other.
    func rebuild() {
        buildTask?.cancel()
        buildTask = Task { [manager] in
            let adblock = await manager.enabledTexts(format: .adblock)
            let hosts = await manager.enabledTexts(format: .hosts)
            guard !adblock.isEmpty || !hosts.isEmpty else {
                state = .idle
                return
            }
            state = .building

            let compiled = await Self.compile(adblock: adblock.map(\.text), hosts: hosts.map(\.text))
            guard !Task.isCancelled else { return }
            state = .ready(compiled)
        }
    }

    /// Off the main actor, and off any actor at all: this is pure computation over
    /// values, and it should not hold a lock on anything while it runs for seconds.
    private nonisolated static func compile(
        adblock: [String], hosts: [String]
    ) async -> Compiled {
        await Task.detached(priority: .userInitiated) {
            let started = Date()
            let adblockLines = adblock.flatMap { $0.split(separator: "\n").map(String.init) }
            // The resolver reads both formats: a hosts file directly, and an Adblock
            // list for the `||domain^` rules it can honour. Rules carrying anything DNS
            // cannot evaluate are dropped by the blocklist itself, not here.
            let dnsLines = hosts.flatMap { $0.split(separator: "\n").map(String.init) } + adblockLines

            return Compiled(
                network: FilterEngine(lines: adblockLines),
                cosmetic: CosmeticEngine(rules: adblockLines),
                dns: DomainBlocklist(lines: dnsLines),
                listCount: adblock.count + hosts.count,
                builtAt: Date(),
                duration: Date().timeIntervalSince(started)
            )
        }.value
    }
}
