import Foundation
import NIOCore

/// Finds where to insert markup in an HTML stream, holding as little as possible.
///
/// Buffering the whole document would be simpler and would also delay the first byte
/// until the last one arrived — on a slow page that is the difference between a site
/// that renders progressively and one that appears frozen. So only the bytes up to the
/// insertion point are held; everything after flows straight through.
///
/// The search is deliberately not a parser. A tolerant scan for a handful of markers is
/// enough to place a `<style>` tag, and every HTML parser ever written has been a
/// source of security bugs when fed hostile input — which is all this ever sees.
public struct HTMLInjector {

    public enum State: Sendable, Equatable {
        /// Still looking; keep buffering.
        case searching
        /// Found: emit `prefix`, then the payload, then `suffix` and everything after.
        case found(insertAt: Int)
        /// No insertion point within the budget; give up and pass the body through
        /// untouched rather than risk corrupting it.
        case abandoned
    }

    /// Markers tried in order of preference. Immediately after `<head …>` is best: the
    /// styles apply before anything the document itself loads, so an advert slot never
    /// flashes visible.
    ///
    /// `</head>` is the fallback for documents whose head is generated late, and
    /// `<html …>` for the fragments and error pages that have no head at all.
    static let openHead: [UInt8] = Array("<head".utf8)
    static let closeHead: [UInt8] = Array("</head".utf8)
    static let openHTML: [UInt8] = Array("<html".utf8)
    static let openBody: [UInt8] = Array("<body".utf8)

    /// How much longer to wait for `<head>` after `<html>` has been seen.
    ///
    /// Committing to `<html>` the moment it appears would settle for the worse
    /// insertion point while the better one is a chunk away — in a stream the two
    /// arrive separately. A document that has a head puts it immediately after `<html>`
    /// modulo whitespace and comments, so a few kilobytes is a generous wait.
    public static let headGraceWindow = 4096

    private var buffer: [UInt8] = []
    private var consumed = 0
    private let budget: Int
    /// Where `<html …>` ended, and how much had been read at that moment.
    private var htmlFallback: (insertAt: Int, seenAt: Int)?

    public init(budget: Int = ResponseEligibility.maximumBufferedBytes) {
        self.budget = budget
    }

    public var bufferedBytes: [UInt8] { buffer }

    /// Feeds the next chunk and reports whether the insertion point is now known.
    public mutating func consume(_ bytes: [UInt8]) -> State {
        buffer.append(contentsOf: bytes)
        consumed += bytes.count

        // The preferred marker settles it immediately.
        if let index = Self.preferredInsertionPoint(in: buffer) {
            return .found(insertAt: index)
        }

        if htmlFallback == nil,
           let start = Self.find(Self.openHTML, in: buffer),
           let end = Self.endOfTag(from: start, in: buffer) {
            htmlFallback = (end, consumed)
        }
        if let fallback = htmlFallback, consumed - fallback.seenAt >= Self.headGraceWindow {
            return .found(insertAt: fallback.insertAt)
        }

        if consumed >= budget {
            // Out of budget with a usable fallback is still better than giving up.
            if let fallback = htmlFallback { return .found(insertAt: fallback.insertAt) }
            return .abandoned
        }
        return .searching
    }

    /// The last chunk arrived without a marker being found; place the payload at the
    /// very start rather than dropping it. A document with no `<head>` and no `<html>`
    /// is still a document a stylesheet can affect.
    public mutating func finish() -> State {
        if let index = Self.preferredInsertionPoint(in: buffer) { return .found(insertAt: index) }
        if let fallback = htmlFallback { return .found(insertAt: fallback.insertAt) }
        return buffer.isEmpty ? .abandoned : .found(insertAt: 0)
    }

    /// Index just past a marker good enough to stop searching for.
    ///
    /// `<html>` is deliberately absent: it is a fallback, applied only once the grace
    /// window has passed, because a better point may still be arriving.
    static func preferredInsertionPoint(in bytes: [UInt8]) -> Int? {
        if let range = find(openHead, in: bytes), let end = endOfTag(from: range, in: bytes) {
            return end
        }
        // `</head>` and `<body>` both prove the head is over; inserting just before
        // them is still ahead of the document's own body content.
        if let range = find(closeHead, in: bytes) { return range }
        if let range = find(openBody, in: bytes) { return range }
        return nil
    }

    /// Any usable marker, ignoring the streaming preference. For callers holding a
    /// complete document.
    static func insertionPoint(in bytes: [UInt8]) -> Int? {
        if let index = preferredInsertionPoint(in: bytes) { return index }
        if let range = find(openHTML, in: bytes), let end = endOfTag(from: range, in: bytes) {
            return end
        }
        return nil
    }

    /// Walks past the `>` that closes a tag beginning at `start`.
    ///
    /// Returns `nil` when the tag is still incomplete, so a marker split across two
    /// chunks is picked up on the next one instead of being inserted into halfway.
    static func endOfTag(from start: Int, in bytes: [UInt8]) -> Int? {
        var index = start
        while index < bytes.count {
            if bytes[index] == UInt8(ascii: ">") { return index + 1 }
            index += 1
        }
        return nil
    }

    /// Case-insensitive search over ASCII, since tag names may be written either way.
    static func find(_ needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count else { return nil }
        let limit = haystack.count - needle.count
        var index = 0
        while index <= limit {
            var matched = true
            for offset in needle.indices where lowercased(haystack[index + offset]) != needle[offset] {
                matched = false
                break
            }
            if matched { return index }
            index += 1
        }
        return nil
    }

    @inline(__always)
    static func lowercased(_ byte: UInt8) -> UInt8 {
        (byte >= 0x41 && byte <= 0x5A) ? byte + 32 : byte
    }
}

// MARK: - Payload

public enum InjectionPayload {

    /// Builds the markup inserted into the document.
    ///
    /// The nonce is repeated on both tags because the rewritten CSP authorises exactly
    /// that value — a tag without it is dropped by the browser as surely as if nothing
    /// had been injected at all.
    public static func markup(css: String, script: String?, nonce: String) -> String {
        var markup = ""
        if !css.isEmpty {
            markup += "<style nonce=\"\(nonce)\">\(css)</style>"
        }
        if let script, !script.isEmpty {
            markup += "<script nonce=\"\(nonce)\">\(script)</script>"
        }
        return markup
    }
}
