import Foundation

/// The checks a downloaded list has to clear before it replaces the one in use.
///
/// Ordered by how often they catch something. A truncated download is the common
/// failure by a wide margin, and it is also the one that looks most like a successful
/// update — a file that is half a bank list still parses.
public enum UpdateGuard {

    /// How strictly to judge a shrinking list.
    public enum Policy: Sendable, Equatable {
        /// Exclusions: every check, including the two about size. Losing entries here
        /// means losing protection, and the lists move by a line or two a month, so a
        /// large drop is a signal rather than an inconvenience.
        case exclusions
        /// Blocklists: transport, syntax and emptiness only. EasyList changes thousands
        /// of lines several times a day, and a shorter blocklist blocks less — an
        /// annoyance, never a danger. Guarding it would produce constant false alarms
        /// about a list working normally.
        case blocklist
    }

    public enum Rejection: Sendable, Equatable {
        case httpStatus(Int)
        /// Content-Length promised one size and the body was another. This is the
        /// frequent one.
        case truncated(expected: Int, received: Int)
        case unparsable(reason: String)
        case empty
        /// Both conditions of the amplitude rule met at once. See ``amplitude``.
        case amplitude(current: Int, proposed: Int)

        public var summary: String {
            switch self {
            case .httpStatus(let code):
                "Le serveur a répondu \(code)."
            case .truncated(let expected, let received):
                "Téléchargement incomplet : \(received) octets reçus sur \(expected) annoncés."
            case .unparsable(let reason):
                "Le fichier n'a pas pu être lu : \(reason)"
            case .empty:
                "Le fichier ne contient aucune entrée."
            case .amplitude(let current, let proposed):
                "La liste passerait de \(current) à \(proposed) entrées."
            }
        }
    }

    /// A list may lose entries freely until it loses both a quarter of itself and more
    /// than 25 entries.
    ///
    /// Relative alone is too nervous on a small file: `mac.txt` holds 19 entries, so
    /// dropping four would trip an 80 % threshold on a change worth no alarm. Absolute
    /// alone is too lax on a large one: 25 lost lines out of 4 000 is noise. Requiring
    /// both means the rule only fires on something genuinely wrong.
    static let relativeFloor = 0.80
    static let absoluteFloor = 25

    public static func amplitude(current: Int, proposed: Int) -> Rejection? {
        guard current > 0 else { return nil }
        let lost = current - proposed
        guard lost > absoluteFloor else { return nil }
        guard Double(proposed) < Double(current) * relativeFloor else { return nil }
        return .amplitude(current: current, proposed: proposed)
    }

    /// Everything that can be judged from the response itself.
    public static func checkTransport(
        statusCode: Int,
        contentLength: Int?,
        receivedBytes: Int
    ) -> Rejection? {
        guard statusCode == 200 else { return .httpStatus(statusCode) }
        if let contentLength, contentLength != receivedBytes {
            return .truncated(expected: contentLength, received: receivedBytes)
        }
        return nil
    }

    /// The full verdict, once the payload has been parsed and counted.
    ///
    /// `currentCount` and `proposedCount` are **totals across every file of the set**,
    /// not one file's. Upstream reorganises now and then — moving 200 domains from
    /// `banks.txt` to `sensitive.txt` costs nothing and changes no protection, and a
    /// per-file check would reject both halves of it.
    public static func check(
        policy: Policy,
        statusCode: Int = 200,
        contentLength: Int? = nil,
        receivedBytes: Int? = nil,
        parseError: String? = nil,
        proposedCount: Int,
        currentCount: Int
    ) -> Rejection? {
        if let receivedBytes,
           let rejection = checkTransport(
               statusCode: statusCode, contentLength: contentLength, receivedBytes: receivedBytes
           ) {
            return rejection
        }
        if let parseError { return .unparsable(reason: parseError) }
        guard proposedCount > 0 else { return .empty }
        guard policy == .exclusions else { return nil }
        return amplitude(current: currentCount, proposed: proposedCount)
    }
}
