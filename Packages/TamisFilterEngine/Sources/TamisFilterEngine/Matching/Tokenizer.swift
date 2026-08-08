import Foundation

/// Turns URLs and patterns into the keys used by ``TokenIndex``.
///
/// The whole point of the index is to avoid testing 300 000 rules against every
/// request. It only works if the key a rule is filed under is guaranteed to be
/// produced when tokenizing a URL that rule matches — otherwise rules go missing
/// silently, which is the worst possible failure mode for a blocker.
///
/// The invariant that makes it sound:
///
/// > A pattern's index token must be **right-bounded** — immediately followed in the
/// > pattern by a non-token byte, or by the end anchor. Any URL matching the pattern
/// > therefore has that token ending exactly where a word ends, so the token is a
/// > **suffix** of one of the URL's words.
///
/// Hence ``tokens(ofURL:)`` emits every suffix of every word, not just whole words.
/// A pattern with no right-bounded word (`||double`, `*`) has no usable key and is
/// filed in the always-checked bucket instead.
enum Tokenizer {

    /// Shortest run worth indexing. Below this, a token matches almost everything and
    /// its bucket degenerates into a second catch-all.
    static let minTokenLength = 3

    /// Longest word from which suffixes are generated. Guards against pathological
    /// URLs — a 4 KB base64 blob in a query string would otherwise emit thousands of
    /// keys for a single request.
    static let maxWordLength = 48

    /// Words that appear in so many URLs that filing a rule under them would build a
    /// bucket almost as large as the catch-all — with the extra cost of hashing to
    /// reach it. A rule whose best candidate is one of these looks for another.
    static let uselessTokens: Set<String> = [
        "http", "https", "www", "com", "net", "org", "html", "htm", "php",
        "index", "static", "assets", "content", "images", "image", "media",
    ]

    /// Every suffix of length >= ``minTokenLength`` of every alphanumeric word.
    static func tokens(ofURL bytes: [UInt8]) -> [UInt64] {
        var result: [UInt64] = []
        result.reserveCapacity(32)

        var i = 0
        let n = bytes.count
        while i < n {
            guard Bytes.isTokenByte(bytes[i]) else { i += 1; continue }
            let start = i
            while i < n, Bytes.isTokenByte(bytes[i]) { i += 1 }
            let end = i

            let clamped = max(start, end - maxWordLength)
            var s = clamped
            while end - s >= minTokenLength {
                result.append(hash(bytes[s..<end]))
                s += 1
            }
        }
        return result
    }

    /// FNV-1a over a byte range. Tokens are compared by hash only; a collision costs
    /// one extra rule evaluation, never a wrong answer, because the candidate rule is
    /// still matched in full afterwards.
    static func hash(_ bytes: ArraySlice<UInt8>) -> UInt64 {
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        for b in bytes {
            h ^= UInt64(b)
            h &*= 0x0000_0100_0000_01B3
        }
        return h
    }

    static func hash(_ string: String) -> UInt64 {
        let bytes = Array(string.utf8)
        return hash(bytes[...])
    }
}
