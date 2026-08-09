import Foundation
import Testing
import NIOHTTP1
import TamisFilterEngine
@testable import TamisProxy

@Suite("Request reconstruction")
struct RequestReconstructionTests {

    private func head(
        _ uri: String,
        method: HTTPMethod = .GET,
        headers: [(String, String)] = []
    ) -> HTTPRequestHead {
        var fields = HTTPHeaders()
        for (name, value) in headers { fields.add(name: name, value: value) }
        return HTTPRequestHead(version: .http1_1, method: method, uri: uri, headers: fields)
    }

    /// Through a tunnel the request line carries only the path, so the URL has to be
    /// rebuilt from the CONNECT target — otherwise every rule anchored on a domain
    /// would silently fail to match.
    @Test("the URL is rebuilt from the CONNECT target")
    func urlIsRebuilt() {
        let request = HTTPFilteringHandler.makeRequest(
            head: head("/ads/banner.png?id=1"), host: "ads.example.com"
        )
        #expect(request.url == "https://ads.example.com/ads/banner.png?id=1")
        #expect(request.hostname == "ads.example.com")
    }

    @Test("the resource type comes from Sec-Fetch-Dest when the client sends it")
    func typeFromSecFetchDest() {
        let request = HTTPFilteringHandler.makeRequest(
            head: head("/x", headers: [("Sec-Fetch-Dest", "image")]), host: "example.com"
        )
        #expect(request.type == .image)
    }

    @Test("without Sec-Fetch-Dest the path extension decides")
    func typeFallsBack() {
        let request = HTTPFilteringHandler.makeRequest(head: head("/app.js"), host: "example.com")
        #expect(request.type == .script)
    }

    @Test("the document origin comes from Origin, then Referer", arguments: [
        ([("Origin", "https://news.example")], "news.example"),
        ([("Referer", "https://news.example/article")], "news.example"),
        // Origin wins when both are present.
        ([("Origin", "https://a.example"), ("Referer", "https://b.example/x")], "a.example"),
    ])
    func documentOrigin(headers: [(String, String)], expected: String) {
        let request = HTTPFilteringHandler.makeRequest(
            head: head("/x", headers: headers), host: "cdn.example"
        )
        #expect(request.sourceHostname == expected)
    }

    /// Without an origin the request is first-party, so a `$third-party` rule never
    /// fires on traffic we merely failed to attribute.
    @Test("an unattributable request counts as first-party")
    func noOriginIsFirstParty() {
        let request = HTTPFilteringHandler.makeRequest(head: head("/x"), host: "ads.example")
        #expect(request.sourceHostname == nil)
        #expect(!request.isThirdParty)
    }

    @Test("third-party is decided against the document origin")
    func thirdParty() {
        let request = HTTPFilteringHandler.makeRequest(
            head: head("/pixel.gif", headers: [("Referer", "https://news.example/a")]),
            host: "ads.doubleclick.net"
        )
        #expect(request.isThirdParty)
    }

    @Test("the method reaches the engine, for $method rules")
    func methodIsCarried() {
        let request = HTTPFilteringHandler.makeRequest(
            head: head("/api", method: .POST), host: "example.com"
        )
        #expect(request.method == "POST")
    }
}

@Suite("Filtering decisions")
struct FilteringDecisionTests {

    /// The end-to-end shape of a block, without the network: an engine, a request
    /// rebuilt exactly as the handler rebuilds it, and the verdict.
    @Test("an advert URL matches, a page asset does not")
    func engineSeesRealRequests() {
        let engine = FilterEngine(rules: """
        ||doubleclick.net^
        ||example.com/ads/
        """)

        let advert = HTTPFilteringHandler.makeRequest(
            head: HTTPRequestHead(version: .http1_1, method: .GET, uri: "/pixel.gif"),
            host: "ads.doubleclick.net"
        )
        #expect(engine.match(advert).action == .block)

        let asset = HTTPFilteringHandler.makeRequest(
            head: HTTPRequestHead(version: .http1_1, method: .GET, uri: "/assets/main.css"),
            host: "static.example.com"
        )
        #expect(engine.match(asset).action == .allow)
    }

    @Test("an exception rule scoped to a document origin is honoured")
    func exceptionsUseTheOrigin() {
        let engine = FilterEngine(rules: """
        ||tracker.example^
        @@||tracker.example^$domain=trusted.example
        """)

        func request(from origin: String) -> TamisFilterEngine.Request {
            var headers = HTTPHeaders()
            headers.add(name: "Referer", value: "https://\(origin)/page")
            return HTTPFilteringHandler.makeRequest(
                head: HTTPRequestHead(version: .http1_1, method: .GET, uri: "/t.js", headers: headers),
                host: "tracker.example"
            )
        }

        #expect(engine.match(request(from: "other.example")).action == .block)
        #expect(engine.match(request(from: "trusted.example")).action == .allow)
    }
}
