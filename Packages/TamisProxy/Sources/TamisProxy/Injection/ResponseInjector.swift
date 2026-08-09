import Foundation
import NIOCore
import NIOHTTP1
import TamisFilterEngine

/// Carries what the response side needs to know about the request that caused it.
///
/// Requests are sequential on a connection, so one slot is enough. The response
/// handler cannot see the request head, and eligibility depends on it: HTML fetched by
/// script is data rather than a page, and only `Sec-Fetch-Dest` says which this was.
final class RequestContext: @unchecked Sendable {
    private let lock = NSLock()
    private var _secFetchDest: String?

    var secFetchDest: String? {
        get { lock.lock(); defer { lock.unlock() }; return _secFetchDest }
        set { lock.lock(); defer { lock.unlock() }; _secFetchDest = newValue }
    }
}

/// Rewrites eligible responses on their way back to the client.
///
/// The head is held rather than forwarded immediately. That costs time to first byte,
/// and the alternative is worse: the head announces the framing and the encoding, so
/// sending it before knowing whether the body could be decoded and injected would mean
/// either lying about the body or being unable to change one's mind. Documents are
/// small — the budget bounds the exposure at two megabytes — and everything not
/// eligible is forwarded untouched with no buffering at all.
final class ResponseInjectingHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPClientResponsePart
    typealias OutboundOut = HTTPClientRequestPart

    private enum Mode {
        /// Not eligible: forward every part as it arrives.
        case passthrough
        /// Eligible: hold the head and accumulate the body.
        case buffering(head: HTTPResponseHead, body: [UInt8])
    }

    private let client: Channel
    private let host: String
    private let cosmetic: CosmeticEngine?
    private let context: RequestContext
    private let events: EventSink
    /// See the note on ``HTTPFilteringHandler``: streams must not close their peer.
    private let propagatesClose: Bool
    private var mode: Mode = .passthrough

    init(
        client: Channel,
        host: String,
        cosmetic: CosmeticEngine?,
        context: RequestContext,
        events: EventSink,
        propagatesClose: Bool
    ) {
        self.client = client
        self.host = host
        self.cosmetic = cosmetic
        self.context = context
        self.events = events
        self.propagatesClose = propagatesClose
    }

    func channelRead(context ctx: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            guard cosmetic != nil,
                  ResponseEligibility.verdict(for: head, requestType: context.secFetchDest) == .eligible
            else {
                mode = .passthrough
                client.write(HTTPServerResponsePart.head(head), promise: nil)
                return
            }
            mode = .buffering(head: head, body: [])

        case .body(let buffer):
            switch mode {
            case .passthrough:
                client.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
            case .buffering(let head, var body):
                body.append(contentsOf: buffer.readableBytesView)
                if body.count > ResponseEligibility.maximumBufferedBytes {
                    // Past the budget the document is not one we can hold. Give up on
                    // rewriting and release what was collected, unchanged — the head
                    // was never sent, so nothing has been promised yet.
                    events.emit(.injectionAbandoned(host: host, reason: "body over budget"))
                    flushUnmodified(head: head, body: body)
                    mode = .passthrough
                    return
                }
                mode = .buffering(head: head, body: body)
            }

        case .end(let trailers):
            switch mode {
            case .passthrough:
                client.writeAndFlush(HTTPServerResponsePart.end(trailers), promise: nil)
            case .buffering(let head, let body):
                finish(head: head, body: body, trailers: trailers)
                mode = .passthrough
            }
        }
    }

    func channelInactive(context ctx: ChannelHandlerContext) {
        if propagatesClose { client.close(promise: nil) }
        ctx.fireChannelInactive()
    }

    // MARK: Rewriting

    private func finish(head: HTTPResponseHead, body: [UInt8], trailers: HTTPHeaders?) {
        let encoding = ContentDecoder.Encoding.parse(head.headers.first(name: "Content-Encoding"))
        guard let encoding, let cosmetic else {
            flushUnmodified(head: head, body: body, trailers: trailers)
            return
        }

        let decoded: [UInt8]
        do {
            decoded = try ContentDecoder.decode(body, encoding: encoding)
        } catch {
            // A body we cannot decode is a body we must not rewrite. Passing the
            // original through keeps the page working; guessing would corrupt it.
            events.emit(.injectionAbandoned(host: host, reason: "\(error)"))
            flushUnmodified(head: head, body: body, trailers: trailers)
            return
        }

        // The document is already in hand, so generic rules can be narrowed to the
        // classes and ids it actually carries — a few hundred bytes instead of 216 KB.
        let tokens = DocumentTokens.scan(decoded)
        let set = cosmetic.set(forHostname: host, documentTokens: tokens)
        let css = set.inlineCSS()
        // Procedural selectors are parsed here, not in the page: a malformed rule is
        // rejected before it can reach a browser, and the runtime stays an interpreter
        // rather than a parser.
        let procedural = set.proceduralSelectors.compactMap(ProceduralSelector.parse)
        let runtime = CosmeticRuntime.script(for: procedural)

        // Scriptlets answer scripts that fight back — an advert loader checking its own
        // object, a paywall reading a flag. Hiding elements does nothing against those.
        let parsedScriptlets = set.scriptlets.compactMap(Scriptlet.parse)
        let scriptletResult = ScriptletLibrary.script(for: parsedScriptlets)
        if let skipped = scriptletResult?.skipped, !skipped.isEmpty {
            // Running an approximation of a scriptlet is how a page breaks in a way
            // nobody can attribute, so unknown names are reported rather than guessed.
            events.emit(.scriptletsSkipped(host: host, names: skipped))
        }

        // Scriptlets run first: they exist to be in place before the page's own code.
        let script = [scriptletResult?.source, runtime]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: "\n")

        guard !css.isEmpty || !script.isEmpty else {
            // Nothing to apply to this site. Still emit the decoded body: the head is
            // about to lose its Content-Encoding either way.
            flushDecoded(head: head, body: decoded, trailers: trailers)
            return
        }

        let nonce = CSPRewriter.makeNonce()
        let markup = InjectionPayload.markup(
            css: css, script: script.isEmpty ? nil : script, nonce: nonce
        )

        var injector = HTMLInjector()
        var state = injector.consume(decoded)
        if case .searching = state { state = injector.finish() }

        guard case .found(let index) = state, index <= decoded.count else {
            events.emit(.injectionAbandoned(host: host, reason: "no insertion point"))
            flushDecoded(head: head, body: decoded, trailers: trailers)
            return
        }

        var rewritten = Array(decoded[0..<index])
        rewritten.append(contentsOf: Array(markup.utf8))
        rewritten.append(contentsOf: Array(decoded[index...]))

        var headers = head.headers
        CSPRewriter.authorise(headers: &headers, nonce: nonce)
        var newHead = head
        newHead.headers = headers
        events.emit(.injected(
            host: host,
            selectors: set.specificSelectors.count + set.genericSelectors.count + procedural.count,
            bytes: markup.utf8.count
        ))
        flushDecoded(head: newHead, body: rewritten, trailers: trailers)
    }

    /// Emits a body whose length and encoding have changed.
    ///
    /// Both `Content-Length` and `Content-Encoding` are removed rather than corrected:
    /// the length is now known, but stating it would be one more thing to keep in step
    /// with every future rewrite, and chunked framing costs nothing over loopback.
    private func flushDecoded(head: HTTPResponseHead, body: [UInt8], trailers: HTTPHeaders?) {
        var head = head
        head.headers.remove(name: "Content-Length")
        head.headers.remove(name: "Content-Encoding")
        client.write(HTTPServerResponsePart.head(head), promise: nil)
        writeBody(body)
        client.writeAndFlush(HTTPServerResponsePart.end(trailers), promise: nil)
    }

    private func flushUnmodified(head: HTTPResponseHead, body: [UInt8], trailers: HTTPHeaders? = nil) {
        client.write(HTTPServerResponsePart.head(head), promise: nil)
        writeBody(body)
        if let trailers {
            client.writeAndFlush(HTTPServerResponsePart.end(trailers), promise: nil)
        }
    }

    private func writeBody(_ body: [UInt8]) {
        guard !body.isEmpty else { return }
        var buffer = client.allocator.buffer(capacity: body.count)
        buffer.writeBytes(body)
        client.write(HTTPServerResponsePart.body(.byteBuffer(buffer)), promise: nil)
    }
}
