import Foundation

/// Collects the class and id names a document actually contains.
///
/// This is what makes generic cosmetic filtering affordable from a proxy. Real lists
/// carry over thirteen thousand generic rules — 216 KB of stylesheet if inlined into
/// every page — but a page can only be affected by the handful whose selector names
/// something the markup carries. Since the whole document is already in hand for
/// injection, the narrowing costs one pass over bytes we have already read.
///
/// A browser extension does this by inspecting the live DOM. A proxy can only see the
/// markup as delivered, so elements created later by script are missed. That is a real
/// limit, not an oversight: catching them would mean shipping the full rule set into
/// the page, which is the cost being avoided.
public enum DocumentTokens {

    /// Beyond this the page is not one whose tokens are worth collecting, and an
    /// unbounded set on a hostile document is a memory amplifier.
    public static let maximumTokens = 20_000

    /// Every `class` and `id` value in the markup, split into individual names.
    ///
    /// A tolerant scan, not a parser: it looks for the two attribute names and reads
    /// what follows. Mistaking a mention inside text for an attribute costs one useless
    /// lookup, while a real HTML parser fed hostile input costs rather more.
    public static func scan(_ bytes: [UInt8]) -> Set<String> {
        var tokens = Set<String>()
        let classAttribute = Array("class".utf8)
        let idAttribute = Array("id".utf8)

        var index = 0
        let count = bytes.count
        while index < count, tokens.count < maximumTokens {
            guard bytes[index] == UInt8(ascii: "=") else {
                index += 1
                continue
            }
            // Walk back over whitespace to the attribute name that precedes `=`.
            var nameEnd = index
            while nameEnd > 0, isSpace(bytes[nameEnd - 1]) { nameEnd -= 1 }
            var nameStart = nameEnd
            while nameStart > 0, isNameByte(bytes[nameStart - 1]) { nameStart -= 1 }
            guard nameStart < nameEnd else {
                index += 1
                continue
            }

            let name = bytes[nameStart..<nameEnd].map(lowercased)
            guard name == classAttribute || name == idAttribute else {
                index += 1
                continue
            }

            var valueStart = index + 1
            while valueStart < count, isSpace(bytes[valueStart]) { valueStart += 1 }
            guard valueStart < count else { break }

            let quote = bytes[valueStart]
            var valueEnd: Int
            if quote == UInt8(ascii: "\"") || quote == UInt8(ascii: "'") {
                valueStart += 1
                valueEnd = valueStart
                while valueEnd < count, bytes[valueEnd] != quote { valueEnd += 1 }
            } else {
                valueEnd = valueStart
                while valueEnd < count, !isSpace(bytes[valueEnd]),
                      bytes[valueEnd] != UInt8(ascii: ">") { valueEnd += 1 }
            }

            var tokenStart = valueStart
            var cursor = valueStart
            while cursor <= valueEnd {
                if cursor == valueEnd || isSpace(bytes[cursor]) {
                    if cursor > tokenStart {
                        tokens.insert(String(decoding: bytes[tokenStart..<cursor], as: UTF8.self))
                        if tokens.count >= maximumTokens { return tokens }
                    }
                    tokenStart = cursor + 1
                }
                cursor += 1
            }
            index = valueEnd + 1
        }
        return tokens
    }

    @inline(__always)
    static func isSpace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D || byte == 0x0C
    }

    @inline(__always)
    static func isNameByte(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
            || (byte >= 0x30 && byte <= 0x39) || byte == 0x2D || byte == 0x5F
    }

    @inline(__always)
    static func lowercased(_ byte: UInt8) -> UInt8 {
        (byte >= 0x41 && byte <= 0x5A) ? byte + 32 : byte
    }
}
