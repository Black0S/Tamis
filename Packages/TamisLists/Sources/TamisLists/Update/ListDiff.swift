import Foundation

/// What changed between two versions of a list, split by direction rather than by size.
///
/// The measured cadence of the exclusion lists is 30 commits in twelve months, median
/// one line, largest change of the year 44 lines. Reviewing every update is therefore
/// affordable — three to five decisions a year, all of them meaningful.
public struct ListDiff: Sendable, Equatable {
    public let added: [String]
    public let removed: [String]

    public var isEmpty: Bool { added.isEmpty && removed.isEmpty }
    /// Nothing lost: nothing to decide.
    public var isRoutine: Bool { removed.isEmpty }

    public init(added: [String], removed: [String]) {
        self.added = added
        self.removed = removed
    }

    public init(from old: [String], to new: [String]) {
        let before = Set(old)
        let after = Set(new)
        self.added = after.subtracting(before).sorted()
        self.removed = before.subtracting(after).sorted()
    }
}

/// What to do with an update once it has been checked and diffed.
public enum UpdateOutcome: Sendable, Equatable {

    /// Additions only. Applied, written to the journal, nothing interrupted.
    case routine(ListDiff)

    /// Something was removed.
    ///
    /// The additions in this diff are **already applied**; only the removals wait.
    /// Holding an addition back until the user returns would leave a bank unprotected
    /// for as long as they are away — the delay would run in the wrong direction. A
    /// removal is the other way round: waiting keeps more protection, not less.
    case awaitingValidation(applied: ListDiff, pendingRemovals: [String])

    /// A guardrail fired. Nothing applied at all.
    case anomaly(UpdateGuard.Rejection)

    public var needsAttention: Bool {
        switch self {
        case .routine:                                  false
        case .awaitingValidation, .anomaly:             true
        }
    }
}

extension UpdateOutcome {

    /// Decides what an update means, given a verdict and a diff.
    ///
    /// Blocklists never reach `awaitingValidation`: EasyList moves by thousands of
    /// lines a day, so asking the user to approve each removal would be asking them to
    /// approve the list working. They apply, and the journal records it.
    public static func decide(
        policy: UpdateGuard.Policy,
        rejection: UpdateGuard.Rejection?,
        diff: ListDiff
    ) -> UpdateOutcome {
        if let rejection { return .anomaly(rejection) }
        guard policy == .exclusions, !diff.removed.isEmpty else { return .routine(diff) }
        return .awaitingValidation(
            applied: ListDiff(added: diff.added, removed: []),
            pendingRemovals: diff.removed
        )
    }
}
