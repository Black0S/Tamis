import Foundation
import NIOHTTP1

/// Makes room in a page's Content-Security-Policy for exactly the two tags Tamis adds.
///
/// This is the single most common way a filtering proxy fails silently. A site that
/// forbids inline styles and scripts causes the browser to drop the injected `<style>`
/// and `<script>` without a word — the page loads, the adverts are gone from the
/// network, and the holes they left stay open. Nothing in any log says why.
///
/// The obvious fix is to delete the header. That works, and it strips the page of a
/// protection its authors deliberately added; a tool installed to improve the user's
/// security has no business doing that. Instead a nonce is generated per response and
/// added to the directives that would otherwise block us. Everything else about the
/// policy — allowed origins, frame ancestors, upgrade rules — is left exactly as it
/// was, and the nonce only ever authorises the two tags carrying it.
public enum CSPRewriter {

    /// A fresh nonce per response. Reusing one across responses would let a page that
    /// observed it authorise its own inline scripts.
    public static func makeNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        return Data(bytes).base64EncodedString()
    }

    /// Directives that can block an injected `<style>` or `<script>`.
    static let scriptDirectives = ["script-src", "script-src-elem"]
    static let styleDirectives = ["style-src", "style-src-elem"]

    /// Rewrites every CSP header so `nonce` is accepted.
    public static func authorise(headers: inout HTTPHeaders, nonce: String) {
        // Report-only policies never block anything, so leaving them untouched keeps a
        // site's own violation reports honest about the page rather than about us.
        let names = ["Content-Security-Policy"]
        for name in names {
            let values = headers[name]
            guard !values.isEmpty else { continue }
            headers.remove(name: name)
            for value in values {
                headers.add(name: name, value: authorise(policy: value, nonce: nonce))
            }
        }
    }

    /// Adds the nonce to one policy string.
    public static func authorise(policy: String, nonce: String) -> String {
        let source = "'nonce-\(nonce)'"
        var directives: [(name: String, values: [String])] = []

        for piece in policy.split(separator: ";") {
            let tokens = piece.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let name = tokens.first?.lowercased() else { continue }
            directives.append((name, Array(tokens.dropFirst())))
        }
        guard !directives.isEmpty else { return policy }

        let present = Set(directives.map(\.name))
        var rewritten: [(name: String, values: [String])] = []

        for var directive in directives {
            if scriptDirectives.contains(directive.name) || styleDirectives.contains(directive.name) {
                // 'strict-dynamic' makes a nonce the *only* way in, so adding one is
                // both necessary and sufficient. Otherwise the nonce simply joins the
                // existing sources.
                if !directive.values.contains(source) { directive.values.append(source) }
            }
            rewritten.append(directive)
        }

        // With no explicit script-src or style-src, default-src governs them. Copying
        // it into a specific directive plus the nonce keeps the effective policy
        // identical for everything except our two tags — widening default-src itself
        // would loosen fetches, frames and connections too.
        if present.contains("default-src") {
            let defaults = directives.first { $0.name == "default-src" }?.values ?? []
            for family in [scriptDirectives, styleDirectives] {
                let specific = family[0]
                guard !present.contains(specific), !present.contains(family[1]) else { continue }
                rewritten.append((specific, defaults + [source]))
            }
        }

        return rewritten
            .map { $0.values.isEmpty ? $0.name : "\($0.name) \($0.values.joined(separator: " "))" }
            .joined(separator: "; ")
    }
}
