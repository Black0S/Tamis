import Foundation
import NIOCore
import NIOHTTP1
import NIOHTTP2
import NIOConcurrencyHelpers
import TamisFilterEngine
import TamisUserScripts

/// Pairs one client HTTP/2 stream with one upstream HTTP/2 stream.
///
/// The win HTTP/2 brings here is not raw speed, it is handshakes. Over HTTP/1.1 a
/// browser opens six connections per origin, so Tamis performs six TLS handshakes with
/// the browser and six more with the origin. Over HTTP/2 it opens one, multiplexes
/// everything through it, and Tamis does the same upstream — for a page with eighty
/// resources that is the difference between eighty handshakes and one.
///
/// Both sides are presented to the rest of the proxy as HTTP/1 messages by NIO's
/// framing codecs, so the filtering and injection handlers are the same objects used on
/// the HTTP/1.1 path. Nothing above this file knows which protocol carried a request.
enum HTTP2Bridge {

    /// Configures an intercepted connection where both sides speak HTTP/2.
    ///
    /// - Parameters:
    ///   - client: the browser-facing channel, TLS already established.
    ///   - upstream: the origin-facing channel, TLS already established.
    static func install(
        client: Channel,
        upstream: Channel,
        host: String,
        engine: FilterEngine,
        cosmetic: CosmeticEngine?,
        userScripts: [UserScript],
        userStyles: [UserStyle],
        styleVariables: [String: [String: String]],
        resolvedRequires: [URL: String],
        events: EventSink
    ) -> EventLoopFuture<Void> {
        // The inline multiplexer, not the legacy standalone one: the two coexist in
        // NIO and only the inline variant is wired into the handler that actually
        // carries the frames.
        upstream.eventLoop.submit { () -> NIOHTTP2Handler.StreamMultiplexer in
            try upstream.pipeline.syncOperations.configureHTTP2Pipeline(
                mode: .client,
                connectionConfiguration: .init(),
                streamConfiguration: .init(),
                // The origin never opens a stream towards us: server push is dead and
                // disabled. Anything arriving is refused rather than half-handled.
                inboundStreamInitializer: { stream in stream.close() }
            )
        }
        .flatMap { upstreamMultiplexer -> EventLoopFuture<Void> in
            client.eventLoop.submit {
                _ = try client.pipeline.syncOperations.configureHTTP2Pipeline(
                    mode: .server,
                    connectionConfiguration: .init(),
                    streamConfiguration: .init(),
                    inboundStreamInitializer: { clientStream in
                        Self.bridge(
                            clientStream: clientStream,
                            upstreamMultiplexer: upstreamMultiplexer,
                            host: host,
                            engine: engine,
                            cosmetic: cosmetic,
                            userScripts: userScripts, userStyles: userStyles,
                styleVariables: styleVariables, resolvedRequires: resolvedRequires,
                            events: events
                        )
                    }
                )
            }
        }
    }

    /// Wires a single inbound client stream to a freshly created upstream stream.
    private static func bridge(
        clientStream: Channel,
        upstreamMultiplexer: NIOHTTP2Handler.StreamMultiplexer,
        host: String,
        engine: FilterEngine,
        cosmetic: CosmeticEngine?,
        userScripts: [UserScript],
        userStyles: [UserStyle],
        styleVariables: [String: [String: String]],
        resolvedRequires: [URL: String],
        events: EventSink
    ) -> EventLoopFuture<Void> {
        let promise = clientStream.eventLoop.makePromise(of: Channel.self)
        let requestContext = RequestContext()

        upstreamMultiplexer.createStreamChannel(promise: promise) { upstreamStream in
            // A stream channel does not inherit the parent's autoRead, so without this
            // the response frames are delivered to a channel that never asks for them.
            upstreamStream.setOption(.autoRead, value: true).flatMap {
            upstreamStream.pipeline.addHandlers([
                HTTP2FramePayloadToHTTP1ClientCodec(httpProtocol: .https),
                ResponseInjectingHandler(
                    client: clientStream, host: host, cosmetic: cosmetic,
                    userScripts: userScripts, userStyles: userStyles,
                styleVariables: styleVariables, resolvedRequires: resolvedRequires,
                    context: requestContext, events: events, propagatesClose: false
                ),
            ])
            }
        }

        return promise.futureResult.flatMap { upstreamStream in
            clientStream.pipeline.addHandlers([
                HTTP2FramePayloadToHTTP1ServerCodec(),
                HTTPFilteringHandler(
                    engine: engine, host: host, upstream: upstreamStream,
                    events: events, requestContext: requestContext,
                    propagatesClose: false
                ),
            ])
        }
    }
}

/// The application protocol both sides of an intercepted connection will speak.
///
/// Chosen from what the *origin* offers, then advertised to the client — never the
/// other way round. Letting the client pick would mean a browser choosing HTTP/2 while
/// the origin only speaks HTTP/1.1, which needs one upstream connection per concurrent
/// stream and a pool to manage them. Mirroring the origin removes that case entirely,
/// and is the honest answer anyway: Tamis reports what the site actually supports.
enum NegotiatedProtocol: String, Sendable {
    case http2 = "h2"
    case http1 = "http/1.1"

    static func from(_ negotiated: String?) -> NegotiatedProtocol {
        negotiated == "h2" ? .http2 : .http1
    }

    var alpn: [String] { [rawValue] }
}
