import Testing
@testable import TamisFilterEngine

@Suite("Request type reconstruction")
struct RequestTypeTests {

    @Test("Sec-Fetch-Dest is authoritative", arguments: [
        ("document", RequestType.document),
        ("iframe", .subdocument),
        ("frame", .subdocument),
        ("script", .script),
        ("serviceworker", .script),
        ("style", .stylesheet),
        ("image", .image),
        ("font", .font),
        ("audio", .media),
        ("video", .media),
        ("object", .object),
        ("manifest", .other),
    ])
    func secFetchDest(dest: String, expected: RequestType) {
        #expect(RequestType.inferred(secFetchDest: dest) == expected)
    }

    @Test("`empty` is a real answer, not a missing one")
    func emptyDest() {
        // fetch() and XHR report `empty`; it must not fall through to the heuristics,
        // which would misclassify a JSON API call by its path extension.
        #expect(RequestType.inferred(secFetchDest: "empty", path: "/x.png") == .xmlHTTPRequest)
    }

    @Test("Accept is the first fallback when the header is absent")
    func acceptFallback() {
        #expect(RequestType.inferred(secFetchDest: nil, accept: "text/css,*/*;q=0.1") == .stylesheet)
        #expect(RequestType.inferred(secFetchDest: nil, accept: "image/avif,image/webp") == .image)
        #expect(RequestType.inferred(secFetchDest: nil, accept: "text/html") == .document)
        // `*/*` carries no information and must not decide anything.
        #expect(RequestType.inferred(secFetchDest: nil, accept: "*/*", path: "/a.js") == .script)
    }

    @Test("the path extension is the last resort", arguments: [
        ("/lib/app.js", RequestType.script),
        ("/img/logo.svg", .image),
        ("/f/i.woff2", .font),
        ("/app.js?v=1.2", .script),   // a query string is not an extension
        ("/api/v1/users", .other),
    ])
    func extensionFallback(path: String, expected: RequestType) {
        #expect(RequestType.inferred(secFetchDest: nil, path: path) == expected)
    }

    @Test("a bare rule does not apply to top-level navigation")
    func defaultTypeSet() {
        #expect(!RequestTypeSet.defaultForRules.contains(.document))
        #expect(RequestTypeSet.defaultForRules.contains(.script))
        #expect(RequestTypeSet.all.contains(.document))
    }
}

@Suite("Request parsing")
struct RequestParsingTests {

    private func host(_ url: String) -> String {
        let bytes = Array(url.utf8)
        let b = Request.hostBounds(in: bytes)
        return String(decoding: bytes[b.start..<b.end], as: UTF8.self)
    }

    @Test("the hostname is located without URLComponents", arguments: [
        ("https://example.com/path", "example.com"),
        ("http://sub.example.com:8080/x?y=1", "sub.example.com"),
        ("https://example.com", "example.com"),
        // Userinfo must be skipped, or `||host` anchoring could be fooled.
        ("https://evil.com@real.com/x", "real.com"),
    ])
    func hostBounds(url: String, expected: String) {
        #expect(host(url) == expected)
    }

    @Test("the registrable domain handles multi-label suffixes", arguments: [
        ("sub.example.com", "example.com"),
        ("example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("user.github.io", "user.github.io"),
        ("127.0.0.1", "127.0.0.1"),
    ])
    func registrableDomain(host: String, expected: String) {
        #expect(PublicSuffix.registrableDomain(of: host) == expected)
    }

    @Test("third-party is decided on the registrable domain")
    func thirdParty() {
        let firstParty = Request(
            url: "https://cdn.example.com/a.js",
            hostname: "cdn.example.com",
            sourceHostname: "www.example.com",
            type: .script
        )
        #expect(!firstParty.isThirdParty)

        let thirdParty = Request(
            url: "https://ads.doubleclick.net/x",
            hostname: "ads.doubleclick.net",
            sourceHostname: "www.example.com",
            type: .script
        )
        #expect(thirdParty.isThirdParty)

        // An unattributed request counts as first-party: a third-party rule must not
        // fire on a request we simply failed to attribute.
        let unknown = Request(
            url: "https://ads.doubleclick.net/x",
            hostname: "ads.doubleclick.net",
            type: .script
        )
        #expect(!unknown.isThirdParty)
    }
}
