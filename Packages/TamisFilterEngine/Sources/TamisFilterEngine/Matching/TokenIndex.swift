import Foundation

/// Buckets rules by their index token so a request only evaluates plausible candidates.
///
/// Without it, every request would be tested against every rule — hundreds of
/// thousands of pattern scans per request. With it, a typical URL yields a few dozen
/// candidates.
///
/// Each rule lives in exactly one bucket, so a lookup cannot return the same rule
/// twice except on a hash collision — which costs one wasted evaluation, never a wrong
/// answer, because candidates are always matched in full afterwards.
struct TokenIndex: Sendable {
    private var buckets: [UInt64: [Int32]] = [:]
    /// Rules with no usable token. Evaluated on every request, so keeping this small
    /// is what keeps the engine fast.
    private var catchAll: [Int32] = []

    var catchAllCount: Int { catchAll.count }
    var bucketCount: Int { buckets.count }

    mutating func insert(ruleIndex: Int, token: String?) {
        let i = Int32(ruleIndex)
        guard let token else {
            catchAll.append(i)
            return
        }
        buckets[Tokenizer.hash(token), default: []].append(i)
    }

    /// Visits candidate rule indices for a URL, in no particular order.
    ///
    /// Deliberately a callback rather than a returned array: building one would copy
    /// the whole catch-all bucket on every request, which measured as the dominant
    /// cost of matching against EasyList. `stop` lets the caller abandon the scan as
    /// soon as an `$important` rule settles the question.
    func forEachCandidate(forURL bytes: [UInt8], _ body: (Int32) -> Bool) {
        for i in catchAll where !body(i) { return }
        for token in Tokenizer.tokens(ofURL: bytes) {
            guard let bucket = buckets[token] else { continue }
            for i in bucket where !body(i) { return }
        }
    }
}
