import Foundation
import Testing
import NIOHTTP1
@testable import TamisProxy

private func response(
    status: HTTPResponseStatus = .ok,
    headers: [(String, String)] = [("Content-Type", "text/html")]
) -> HTTPResponseHead {
    var fields = HTTPHeaders()
    for (name, value) in headers { fields.add(name: name, value: value) }
    return HTTPResponseHead(version: .http1_1, status: status, headers: fields)
}

@Suite("Response eligibility")
struct ResponseEligibilityTests {

    @Test("an HTML document is eligible")
    func htmlDocument() {
        let verdict = ResponseEligibility.verdict(
            for: response(headers: [("Content-Type", "text/html; charset=utf-8")]),
            requestType: "document"
        )
        #expect(verdict == .eligible)
    }

    /// A positive predicate means anything unforeseen lands on the safe side. These are
    /// the cases that would corrupt a response if rewritten.
    @Test("everything else is passed through untouched", arguments: [
        (HTTPResponseStatus.notFound, [("Content-Type", "text/html")], "document"),
        (.partialContent, [("Content-Type", "text/html")], "document"),
        (.ok, [("Content-Type", "application/json")], "empty"),
        (.ok, [("Content-Type", "image/png")], "image"),
        // HTML fetched by script is data, not a page: rewriting it corrupts whatever
        // parses it.
        (.ok, [("Content-Type", "text/html")], "empty"),
        // An encoding we cannot decode must not be guessed at.
        (.ok, [("Content-Type", "text/html"), ("Content-Encoding", "br")], "document"),
        (.ok, [("Content-Type", "text/html"), ("Content-Encoding", "zstd")], "document"),
    ])
    func notEligible(status: HTTPResponseStatus, headers: [(String, String)], dest: String) {
        let verdict = ResponseEligibility.verdict(
            for: response(status: status, headers: headers), requestType: dest
        )
        #expect(verdict != .eligible)
    }

    @Test("a range response is refused even when it claims 200")
    func contentRange() {
        let verdict = ResponseEligibility.verdict(
            for: response(headers: [("Content-Type", "text/html"), ("Content-Range", "bytes 0-99/500")]),
            requestType: "document"
        )
        #expect(verdict == .notEligible(reason: .partialContent))
    }

    @Test("a client that sends no Sec-Fetch-Dest is still served")
    func missingSecFetchDest() {
        let verdict = ResponseEligibility.verdict(for: response(), requestType: nil)
        #expect(verdict == .eligible)
    }

    /// Brotli and zstd are excluded on purpose: linking a C decompressor into a process
    /// whose whole input is hostile costs more than the bandwidth it saves.
    @Test("the request asks only for what we can decode")
    func acceptEncodingIsNarrowed() {
        var headers = HTTPHeaders()
        headers.add(name: "Accept-Encoding", value: "gzip, deflate, br, zstd")
        ResponseEligibility.rewriteAcceptEncoding(&headers)
        let value = headers.first(name: "Accept-Encoding")
        #expect(value == "gzip, deflate")
        #expect(headers["Accept-Encoding"].count == 1)
    }

    @Test("the declared charset is recovered")
    func charset() {
        let head = response(headers: [("Content-Type", "text/html; charset=ISO-8859-1")])
        #expect(ResponseEligibility.charset(of: head) == "iso-8859-1")
        #expect(ResponseEligibility.charset(of: response()) == nil)
    }
}

@Suite("CSP rewriting")
struct CSPRewriterTests {

    /// The single most common way a filtering proxy fails silently: the browser drops
    /// the injected tags without a word, and the holes left by blocked adverts stay
    /// open with nothing in any log to say why.
    @Test("a nonce is added to the directives that would block us")
    func nonceIsAdded() {
        let rewritten = CSPRewriter.authorise(
            policy: "default-src 'self'; script-src 'self'; style-src 'self'",
            nonce: "ABC123"
        )
        #expect(rewritten.contains("script-src 'self' 'nonce-ABC123'"))
        #expect(rewritten.contains("style-src 'self' 'nonce-ABC123'"))
    }

    /// Deleting the header would work, and would strip the page of a protection its
    /// authors deliberately added.
    @Test("the rest of the policy is left exactly as it was")
    func restOfPolicyUntouched() {
        let rewritten = CSPRewriter.authorise(
            policy: "default-src 'none'; img-src https:; frame-ancestors 'none'; script-src 'self'",
            nonce: "N"
        )
        #expect(rewritten.contains("img-src https:"))
        #expect(rewritten.contains("frame-ancestors 'none'"))
        #expect(rewritten.contains("default-src 'none'"))
    }

    /// Without an explicit script-src, default-src governs scripts. Widening
    /// default-src itself would loosen fetches, frames and connections too, so a
    /// specific directive is derived instead.
    @Test("default-src is specialised rather than widened")
    func defaultSrcIsSpecialised() {
        let rewritten = CSPRewriter.authorise(policy: "default-src 'self' https:", nonce: "N")
        #expect(rewritten.contains("default-src 'self' https:"))
        #expect(rewritten.contains("script-src 'self' https: 'nonce-N'"))
        #expect(rewritten.contains("style-src 'self' https: 'nonce-N'"))
        // default-src itself must not have gained the nonce.
        let defaultPart = rewritten.split(separator: ";")
            .first { $0.contains("default-src") }
            .map(String.init) ?? ""
        #expect(!defaultPart.contains("nonce"))
    }

    @Test("the -elem variants are honoured when present")
    func elemVariants() {
        let rewritten = CSPRewriter.authorise(
            policy: "script-src-elem 'self'; style-src-elem 'self'", nonce: "N"
        )
        #expect(rewritten.contains("script-src-elem 'self' 'nonce-N'"))
        #expect(rewritten.contains("style-src-elem 'self' 'nonce-N'"))
    }

    /// With 'strict-dynamic' a nonce is the only way in, so adding one is both
    /// necessary and sufficient.
    @Test("strict-dynamic policies accept the nonce")
    func strictDynamic() {
        let rewritten = CSPRewriter.authorise(
            policy: "script-src 'strict-dynamic' 'nonce-page'", nonce: "N"
        )
        #expect(rewritten.contains("'strict-dynamic'"))
        #expect(rewritten.contains("'nonce-page'"))
        #expect(rewritten.contains("'nonce-N'"))
    }

    @Test("report-only policies are left alone, so a site's own reports stay honest")
    func reportOnlyUntouched() {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Security-Policy-Report-Only", value: "script-src 'self'")
        CSPRewriter.authorise(headers: &headers, nonce: "N")
        #expect(headers.first(name: "Content-Security-Policy-Report-Only") == "script-src 'self'")
    }

    @Test("multiple policy headers are each rewritten")
    func multipleHeaders() {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Security-Policy", value: "script-src 'self'")
        headers.add(name: "Content-Security-Policy", value: "style-src 'self'")
        CSPRewriter.authorise(headers: &headers, nonce: "N")
        let values = headers["Content-Security-Policy"]
        #expect(values.count == 2)
        #expect(values.allSatisfy { $0.contains("'nonce-N'") })
    }

    /// Reusing a nonce would let a page that observed it authorise its own inline
    /// scripts on the next response.
    @Test("each response gets a fresh nonce")
    func nonceIsFresh() {
        let a = CSPRewriter.makeNonce()
        let b = CSPRewriter.makeNonce()
        #expect(a != b)
        #expect(a.count >= 16)
    }
}

@Suite("HTML injection point")
struct HTMLInjectorTests {

    private func point(in html: String) -> Int? {
        HTMLInjector.insertionPoint(in: Array(html.utf8))
    }

    /// Just after `<head>` is the best place: the styles apply before the document
    /// loads anything of its own, so an advert slot never flashes visible.
    @Test("insertion lands just after the opening head tag")
    func afterOpenHead() throws {
        let html = "<!doctype html><html><head><title>x</title></head><body>y</body></html>"
        let index = try #require(point(in: html))
        let prefix = String(decoding: Array(html.utf8)[0..<index], as: UTF8.self)
        #expect(prefix.hasSuffix("<head>"))
    }

    @Test("a head tag with attributes is handled")
    func headWithAttributes() throws {
        let html = "<html><head data-x=\"1\" lang=\"fr\"><title>x</title></head></html>"
        let index = try #require(point(in: html))
        #expect(String(decoding: Array(html.utf8)[0..<index], as: UTF8.self).hasSuffix(">"))
    }

    @Test("tag names are matched whatever their case")
    func caseInsensitive() throws {
        let html = "<HTML><HEAD><TITLE>x</TITLE></HEAD></HTML>"
        #expect(point(in: html) != nil)
    }

    @Test("a document with no head falls back to html, then body", arguments: [
        "<html><body>x</body></html>",
        "<body>x</body>",
        "<div>fragment</div><body>x</body>",
    ])
    func fallbacks(html: String) {
        #expect(point(in: html) != nil)
    }

    /// A marker split across two chunks must be picked up on the next one, not
    /// inserted into halfway.
    @Test("an incomplete tag is not treated as found")
    func incompleteTag() {
        var injector = HTMLInjector()
        #expect(injector.consume(Array("<!doctype html><ht".utf8)) == .searching)
        #expect(injector.consume(Array("ml><head".utf8)) == .searching)
        guard case .found = injector.consume(Array(">".utf8)) else {
            Issue.record("the completed tag was not recognised")
            return
        }
    }

    /// No real document places `</head>` two megabytes in. Holding more would let one
    /// response consume the memory of every other connection.
    @Test("the search gives up rather than buffering without bound")
    func budget() {
        var injector = HTMLInjector(budget: 1024)
        let filler = Array(String(repeating: "x", count: 2048).utf8)
        #expect(injector.consume(filler) == .abandoned)
    }

    @Test("a body that ends with no marker still receives the payload")
    func finishFallsBackToStart() {
        var injector = HTMLInjector()
        _ = injector.consume(Array("plain text, no tags".utf8))
        #expect(injector.finish() == .found(insertAt: 0))
    }

    @Test("an empty body is left alone")
    func emptyBody() {
        var injector = HTMLInjector()
        #expect(injector.finish() == .abandoned)
    }

    /// A tag without the nonce is dropped by the browser as surely as if nothing had
    /// been injected at all.
    @Test("both injected tags carry the nonce")
    func payloadCarriesNonce() {
        let markup = InjectionPayload.markup(css: ".ad { display: none }", script: "void 0", nonce: "N")
        #expect(markup.contains("<style nonce=\"N\">"))
        #expect(markup.contains("<script nonce=\"N\">"))
    }

    @Test("nothing to inject produces no markup")
    func emptyPayload() {
        #expect(InjectionPayload.markup(css: "", script: nil, nonce: "N").isEmpty)
    }
}
