import Foundation
import Darwin

public enum SocketError: Error, Sendable, Equatable {
    case createFailed(errno: Int32)
    case bindFailed(errno: Int32)
    case optionFailed(errno: Int32)
    case launchdUnavailable
    case noSocketsFromLaunchd(name: String)
}

/// A UDP socket the server listens on, from one of two sources.
///
/// This split is what lets the resolver bind port 53 **without ever running as root**.
/// launchd opens the privileged socket itself at load time and hands the descriptor to
/// a process running as an unprivileged user; the process never holds the privilege at
/// all, not even briefly.
///
/// The self-bound variant exists so the whole server can be exercised on a high port,
/// with no privileges and nothing installed.
public struct DNSSocket: Sendable {
    public let descriptor: Int32
    public let source: Source

    public enum Source: Sendable, Equatable {
        case launchd(name: String)
        case bound(host: String, port: UInt16)
    }

    // MARK: Self-bound

    /// Binds a UDP socket directly. Used for tests and for running the resolver on a
    /// high port during development.
    public static func bind(host: String = "127.0.0.1", port: UInt16) throws -> DNSSocket {
        let isIPv6 = host.contains(":")
        let family = isIPv6 ? AF_INET6 : AF_INET
        let fd = socket(family, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw SocketError.createFailed(errno: errno) }

        var reuse: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0
        else {
            Darwin.close(fd)
            throw SocketError.optionFailed(errno: errno)
        }

        var result: Int32 = -1
        if isIPv6 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            _ = host.withCString { inet_pton(AF_INET6, $0, &addr.sin6_addr) }
            result = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        } else {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            _ = host.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
            result = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        guard result == 0 else {
            let code = errno
            Darwin.close(fd)
            throw SocketError.bindFailed(errno: code)
        }

        return DNSSocket(descriptor: fd, source: .bound(host: host, port: port))
    }

    /// The port actually in use, which matters when `bind(port: 0)` asked the kernel
    /// to choose one.
    public func boundPort() -> UInt16? {
        var addr = sockaddr_storage()
        var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let ok = withUnsafeMutablePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }
        guard ok == 0 else { return nil }
        switch Int32(addr.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_port.bigEndian }
            }
        case AF_INET6:
            return withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_port.bigEndian }
            }
        default:
            return nil
        }
    }

    public func close() {
        Darwin.close(descriptor)
    }
}

// MARK: - launchd socket activation

/// Retrieves sockets launchd bound on our behalf.
///
/// `launch_activate_socket` is a C function in libSystem that Swift does not surface,
/// so it is resolved at run time. Looking it up rather than linking against a header
/// also means the package still builds and tests anywhere, and simply reports that
/// activation is unavailable when it is not running under launchd.
public enum SocketActivation {

    private typealias ActivateSocket = @convention(c) (
        UnsafePointer<CChar>, UnsafeMutablePointer<UnsafeMutablePointer<Int32>?>,
        UnsafeMutablePointer<size_t>
    ) -> Int32

    /// Descriptors launchd bound for the socket entry `name` in the job's plist.
    public static func sockets(named name: String) throws -> [Int32] {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "launch_activate_socket") else {
            throw SocketError.launchdUnavailable
        }
        let activate = unsafeBitCast(symbol, to: ActivateSocket.self)

        var descriptors: UnsafeMutablePointer<Int32>?
        var count: size_t = 0
        let status = name.withCString { activate($0, &descriptors, &count) }

        guard status == 0, let descriptors, count > 0 else {
            descriptors?.deallocate()
            throw SocketError.noSocketsFromLaunchd(name: name)
        }
        defer { free(descriptors) }
        return (0..<count).map { descriptors[$0] }
    }

    /// The first socket launchd bound for `name`, ready to serve.
    public static func socket(named name: String) throws -> DNSSocket {
        guard let fd = try sockets(named: name).first else {
            throw SocketError.noSocketsFromLaunchd(name: name)
        }
        return DNSSocket(descriptor: fd, source: .launchd(name: name))
    }
}
