import Foundation

/// A compiled Adblock Plus URL pattern.
///
/// Deliberately avoids regular expressions for the common case. Well over 95% of real
/// rules are a literal substring with optional anchors, and a direct byte scan beats a
/// regex engine by an order of magnitude on that shape. Only explicit `/…/` rules fall
/// back to `NSRegularExpression`.
///
/// Syntax handled:
/// - `||host` — anchored at the start of the hostname or at any subdomain boundary
/// - `|…`     — anchored at the start of the URL
/// - `…|`     — anchored at the end of the URL
/// - `*`      — any sequence, including empty
/// - `^`      — one separator character, or the end of the URL
/// - `/re/`   — raw regular expression
public struct URLPattern: Sendable {
    /// Literal runs, in order, separated by `*` in the source pattern.
    let segments: [[UInt8]]
    let anchorStart: Bool
    let anchorEnd: Bool
    let anchorHost: Bool
    let regex: NSRegularExpression?

    /// The longest alphanumeric run in the pattern, used to bucket the rule in the
    /// token index. `nil` for patterns with no usable literal (`*`, most regexes),
    /// which then land in the always-checked bucket.
    public let indexToken: String?

    // MARK: Compilation

    public init(_ raw: String) throws {
        if raw.count >= 2, raw.hasPrefix("/"), raw.hasSuffix("/") {
            let body = String(raw.dropFirst().dropLast())
            guard let re = try? NSRegularExpression(pattern: body, options: [.caseInsensitive]) else {
                throw FilterParseError.invalidRegex(body)
            }
            self.segments = []
            self.anchorStart = false
            self.anchorEnd = false
            self.anchorHost = false
            self.regex = re
            self.indexToken = Self.tokenForRegex(body)
            return
        }

        var body = Substring(raw)
        var host = false, start = false, end = false

        if body.hasPrefix("||") {
            host = true
            body = body.dropFirst(2)
        } else if body.hasPrefix("|") {
            start = true
            body = body.dropFirst()
        }
        if body.hasSuffix("|"), !body.hasSuffix("\\|") {
            end = true
            body = body.dropLast()
        }

        // Empty segments come from `**` or leading/trailing `*`; dropping them is
        // safe because `*` already means "any gap, possibly empty".
        let parts = body
            .split(separator: "*", omittingEmptySubsequences: false)
            .map { Array($0.utf8) }
            .filter { !$0.isEmpty }

        self.segments = parts
        self.anchorStart = start
        self.anchorEnd = end
        self.anchorHost = host
        self.regex = nil
        self.indexToken = Self.selectIndexToken(segments: parts, anchorEnd: end)
    }

    /// Longest **right-bounded** alphanumeric run across the segments.
    ///
    /// A run only qualifies if a non-token byte follows it inside the same segment, or
    /// it ends the pattern and the pattern is end-anchored. That guarantee is what
    /// makes the token index sound: see ``Tokenizer`` for why.
    ///
    /// A run touching a `*` boundary is never right-bounded — the wildcard can absorb
    /// further alphanumerics, so the word in the URL may be longer than the run.
    ///
    /// Runs shorter than ``Tokenizer/minTokenLength`` are rejected: their buckets would
    /// be so large as to be a second catch-all.
    static func selectIndexToken(segments: [[UInt8]], anchorEnd: Bool) -> String? {
        var best: ArraySlice<UInt8>?

        for (i, seg) in segments.enumerated() {
            let isLastSegment = (i == segments.count - 1)
            var j = 0
            while j < seg.count {
                guard Bytes.isTokenByte(seg[j]) else { j += 1; continue }
                let start = j
                while j < seg.count, Bytes.isTokenByte(seg[j]) { j += 1 }
                let end = j

                let rightBounded = (end < seg.count) || (isLastSegment && anchorEnd)
                guard rightBounded, end - start >= Tokenizer.minTokenLength else { continue }
                guard end - start > (best?.count ?? 0) else { continue }

                let candidate = seg[start..<end]
                let text = String(decoding: candidate, as: UTF8.self)
                guard !Tokenizer.uselessTokens.contains(text) else { continue }
                best = candidate
            }
        }

        guard let best else { return nil }
        return String(decoding: best, as: UTF8.self)
    }

    /// Index token for a `/…/` rule, when one can be proven to be mandatory.
    ///
    /// ABP treats *any* filter delimited by slashes as a regular expression, so real
    /// lists are full of "regexes" like `/ads/banners/` that contain no metacharacters
    /// at all. Leaving those unindexed would push a large number of rules into the
    /// always-checked bucket for no reason.
    ///
    /// Only characters that cannot make a literal run optional are tolerated: `.`, `^`
    /// and `$` constrain a match without ever removing a required character, whereas
    /// `?`, `*`, `+`, alternation, groups and classes all can — those give up.
    static func tokenForRegex(_ body: String) -> String? {
        let disqualifying: Set<Character> = ["\\", "?", "*", "+", "|", "(", ")", "[", "]", "{", "}"]
        guard !body.contains(where: { disqualifying.contains($0) }) else { return nil }
        // The end of a regex is not an anchor, so the trailing run is never bounded.
        return selectIndexToken(segments: [Array(body.utf8)], anchorEnd: false)
    }

    // MARK: Matching

    /// Whether this pattern matches `url`.
    ///
    /// - Parameters:
    ///   - url: the full URL as lowercased UTF-8 bytes.
    ///   - hostStart: index of the first byte of the hostname, used by `||` anchoring.
    ///   - hostEnd: index one past the last byte of the hostname.
    public func matches(url: [UInt8], urlString: String, hostStart: Int, hostEnd: Int) -> Bool {
        if let regex {
            // `urlString` is supplied by the caller rather than rebuilt from `url`:
            // decoding the bytes here allocated a String per regex rule per request,
            // which dominated the whole matching cost.
            let range = NSRange(urlString.startIndex..., in: urlString)
            return regex.firstMatch(in: urlString, options: [], range: range) != nil
        }

        // A pattern reduced to nothing (`*`, `||`) matches everything.
        guard let first = segments.first else { return true }

        if anchorHost {
            for candidate in Bytes.domainAnchorPositions(url: url, hostStart: hostStart, hostEnd: hostEnd) {
                if matchFrom(candidate, url: url, firstSegment: first) { return true }
            }
            return false
        }

        if anchorStart {
            return matchFrom(0, url: url, firstSegment: first)
        }

        var searchFrom = 0
        while let found = Bytes.find(first, in: url, from: searchFrom) {
            if matchFrom(found.start, url: url, firstSegment: first) { return true }
            searchFrom = found.start + 1
            if searchFrom > url.count { break }
        }
        return false
    }

    /// Anchors the first segment at `position`, then places the remaining segments in
    /// order. `*` between segments permits any gap, so a greedy left-to-right search
    /// is sufficient — there is no backtracking case that a literal ABP pattern can
    /// express and this misses.
    private func matchFrom(_ position: Int, url: [UInt8], firstSegment: [UInt8]) -> Bool {
        guard let firstEnd = Bytes.match(firstSegment, in: url, at: position) else { return false }

        var cursor = firstEnd
        for segment in segments.dropFirst() {
            guard let found = Bytes.find(segment, in: url, from: cursor) else { return false }
            cursor = found.end
        }

        if anchorEnd { return cursor == url.count }
        return true
    }
}

// MARK: - Byte helpers

enum Bytes {
    /// `[a-z0-9]` — the alphabet used to build index tokens.
    @inline(__always)
    static func isTokenByte(_ b: UInt8) -> Bool {
        (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39)
    }

    /// A separator in ABP terms: anything outside `[A-Za-z0-9_\-.%]`.
    @inline(__always)
    static func isSeparator(_ b: UInt8) -> Bool {
        if b >= 0x61 && b <= 0x7A { return false }  // a-z
        if b >= 0x41 && b <= 0x5A { return false }  // A-Z
        if b >= 0x30 && b <= 0x39 { return false }  // 0-9
        switch b {
        case 0x5F, 0x2D, 0x2E, 0x25: return false   // _ - . %
        default: return true
        }
    }

    /// Matches `segment` at exactly `position`, returning the index one past the match.
    ///
    /// `^` in the segment consumes one separator byte, or matches the end of the URL
    /// without consuming anything.
    static func match(_ segment: [UInt8], in url: [UInt8], at position: Int) -> Int? {
        var u = position
        for byte in segment {
            if byte == UInt8(ascii: "^") {
                if u == url.count { return u }        // `^` also means end-of-URL
                guard isSeparator(url[u]) else { return nil }
                u += 1
            } else {
                guard u < url.count, url[u] == byte else { return nil }
                u += 1
            }
        }
        return u
    }

    /// First occurrence of `segment` at or after `from`.
    static func find(_ segment: [UInt8], in url: [UInt8], from: Int) -> (start: Int, end: Int)? {
        guard from <= url.count else { return nil }
        var start = from
        while start <= url.count {
            if let end = match(segment, in: url, at: start) { return (start, end) }
            start += 1
        }
        return nil
    }

    /// Positions where `||` anchoring may begin: the start of the hostname, and every
    /// position just after a dot inside it.
    ///
    /// This is what makes `||example.com` match `sub.example.com` while rejecting
    /// `notexample.com`.
    static func domainAnchorPositions(url: [UInt8], hostStart: Int, hostEnd: Int) -> [Int] {
        guard hostStart < hostEnd, hostEnd <= url.count else { return [] }
        var positions = [hostStart]
        var i = hostStart
        while i < hostEnd {
            if url[i] == UInt8(ascii: "."), i + 1 < hostEnd {
                positions.append(i + 1)
            }
            i += 1
        }
        return positions
    }
}

// MARK: - Errors

public enum FilterParseError: Error, Sendable, Equatable {
    case invalidRegex(String)
    case emptyPattern
    case unknownModifier(String)
    case malformedRule(String)
}
