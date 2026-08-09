import Foundation
import NIOCore
import NIOHTTP1
import TamisFilterEngine

/// Decides each request inside an intercepted session, and forwards or refuses it.
///
/// This is where the filter engine finally meets real traffic. Everything before it
/// exists to get a parsed request to this point with the connection still intact.
final class HTTPFilteringHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let engine: FilterEngine
    private let host: String
    private let upstream: Channel
    private let events: EventSink
    private let requestContext: RequestContext
    /// Whether the peer channel should be closed when this one goes inactive.
    ///
    /// True over HTTP/1.1, where each side is a whole connection and the two lifetimes
    /// are the same. False over HTTP/2, where these are streams: closing the peer
    /// stream when this one finishes cancels a response that is still in flight, which
    /// is exactly what it did until this flag existed. Connection lifetimes are linked
    /// at the connection level instead.
    private let propagatesClose: Bool

    /// Set on `.head` and consulted on `.body`/`.end`: once a request is refused, its
    /// body must be swallowed rather than forwarded to an origin that will never see
    /// the head it belongs to.
    private var isBlocked = false

    init(
        engine: FilterEngine,
        host: String,
        upstream: Channel,
        events: EventSink,
        requestContext: RequestContext,
        propagatesClose: Bool
    ) {
        self.engine = engine
        self.host = host
        self.upstream = upstream
        self.events = events
        self.requestContext = requestContext
        self.propagatesClose = propagatesClose
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            let request = Self.makeRequest(head: head, host: host)
            let result = engine.match(request)

            if result.action == .block {
                isBlocked = true
                events.emit(.requestBlocked(url: request.url, rule: result.rule ?? ""))
                respondBlocked(context: context, keepAlive: head.isKeepAlive)
                return
            }

            isBlocked = false
            events.emit(.requestAllowed(url: request.url))

            // The response side cannot see this head, and eligibility depends on it.
            requestContext.secFetchDest = head.headers.first(name: "Sec-Fetch-Dest")

            // Ask only for encodings we can decode, so an eligible document never
            // arrives in a form that forces us to skip it.
            var forwarded = head
            ResponseEligibility.rewriteAcceptEncoding(&forwarded.headers)
            let headPromise = upstream.eventLoop.makePromise(of: Void.self)
            headPromise.futureResult.whenFailure { error in
                self.events.emit(.failed(host: self.host, message: "upstream head: \(error)"))
            }
            upstream.write(HTTPClientRequestPart.head(forwarded), promise: headPromise)

        case .body(let buffer):
            guard !isBlocked else { return }
            upstream.write(HTTPClientRequestPart.body(.byteBuffer(buffer)), promise: nil)

        case .end(let trailers):
            guard !isBlocked else {
                isBlocked = false
                return
            }
            let endPromise = upstream.eventLoop.makePromise(of: Void.self)
            endPromise.futureResult.whenFailure { error in
                self.events.emit(.failed(host: self.host, message: "upstream end: \(error)"))
            }
            upstream.writeAndFlush(HTTPClientRequestPart.end(trailers), promise: endPromise)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if propagatesClose { upstream.close(promise: nil) }
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        if propagatesClose { upstream.close(promise: nil) }
        context.close(promise: nil)
    }

    /// Turns a proxied request into what the engine expects.
    ///
    /// Through a tunnel the request line carries only the path, so the URL is rebuilt
    /// from the CONNECT target. The document origin comes from `Origin` or `Referer` —
    /// the only things a proxy can see — and without it a request counts as
    /// first-party, so a `$third-party` rule never fires on traffic we failed to
    /// attribute.
    static func makeRequest(head: HTTPRequestHead, host: String) -> TamisFilterEngine.Request {
        let url = "https://\(host)\(head.uri)"
        let type = RequestType.inferred(
            secFetchDest: head.headers.first(name: "Sec-Fetch-Dest"),
            accept: head.headers.first(name: "Accept"),
            path: head.uri
        )
        let source = head.headers.first(name: "Origin").flatMap(Self.hostname(ofURL:))
            ?? head.headers.first(name: "Referer").flatMap(Self.hostname(ofURL:))

        return TamisFilterEngine.Request(
            url: url,
            hostname: host,
            sourceHostname: source,
            type: type,
            method: head.method.rawValue
        )
    }

    static func hostname(ofURL text: String) -> String? {
        guard let components = URLComponents(string: text), let host = components.host else {
            return nil
        }
        return host.isEmpty ? nil : host
    }

    /// Answers a blocked request with a well-formed empty response.
    ///
    /// Never a connection reset: some sites treat a network error as a signal to retry
    /// forever or to break the page outright, and an ad blocker that makes a site look
    /// broken gets uninstalled. `204 No Content` is the least surprising thing a client
    /// can receive in place of a resource.
    private func respondBlocked(context: ChannelHandlerContext, keepAlive: Bool) {
        var headers = HTTPHeaders()
        headers.add(name: "Content-Length", value: "0")
        headers.add(name: "Connection", value: keepAlive ? "keep-alive" : "close")
        let head = HTTPResponseHead(version: .http1_1, status: .noContent, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            if !keepAlive { context.close(promise: nil) }
        }
    }
}
