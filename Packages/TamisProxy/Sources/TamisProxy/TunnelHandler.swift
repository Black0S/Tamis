import NIOCore

/// Relays bytes between two channels without looking at them.
///
/// Used for everything Tamis deliberately does not decrypt — bank sites, pinned apps,
/// excluded applications — and as the recovery path when interception turns out to be
/// impossible. In every one of those cases the client validates the origin's real
/// certificate itself, exactly as if Tamis were not there.
///
/// Back-pressure is honoured rather than ignored: a slow client must not let an upload
/// accumulate in memory. Reads are paused on the peer whenever its channel is not
/// writable, which is the difference between a proxy and a memory leak with a port.
final class RelayHandler: ChannelDuplexHandler {
    typealias InboundIn = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private var peer: Channel?

    init(peer: Channel?) {
        self.peer = peer
    }

    func setPeer(_ channel: Channel) {
        peer = channel
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard let peer, peer.isActive else {
            context.close(promise: nil)
            return
        }
        let buffer = unwrapInboundIn(data)
        peer.writeAndFlush(buffer).whenFailure { _ in
            context.close(promise: nil)
        }
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        // Stop pulling from the peer while we cannot write, or the buffer grows without
        // bound on any connection where one side is slower than the other.
        peer?.setOption(.autoRead, value: context.channel.isWritable).whenComplete { _ in }
    }

    func channelInactive(context: ChannelHandlerContext) {
        peer?.close(promise: nil)
        peer = nil
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        peer?.close(promise: nil)
        context.close(promise: nil)
    }
}
