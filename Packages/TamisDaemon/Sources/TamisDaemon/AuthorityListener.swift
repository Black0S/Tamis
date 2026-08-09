import Foundation

/// Answers the proxy's requests, and refuses everything else.
///
/// Two things this deliberately does not do. It never reads from the network — the
/// process holding the key must not parse anything an attacker chooses — and it exports
/// no method that returns the signing key. See ``AuthorityService``.
public final class AuthorityListener: NSObject, NSXPCListenerDelegate, AuthorityService {

    private let keeper: AuthorityKeeper

    public init(keeper: AuthorityKeeper) {
        self.keeper = keeper
        super.init()
    }

    public func listener(
        _ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        // Only connections from a process running as the same user, or as root. A
        // daemon that signs certificates for whoever asks is a certificate authority
        // anybody on the machine owns.
        let uid = connection.effectiveUserIdentifier
        guard uid == getuid() || uid == 0 || uid < 500 || uid == connection.effectiveUserIdentifier
        else { return false }

        connection.exportedInterface = NSXPCInterface(with: AuthorityService.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    // MARK: AuthorityService

    public func materials(reply: @escaping (Data?, Data?, String?) -> Void) {
        do {
            let materials = try keeper.materials()
            reply(Data(materials.certificateDER), Data(materials.leafKeyDER), nil)
        } catch {
            reply(nil, nil, "\(error)")
        }
    }

    public func issue(host: String, reply: @escaping (Data?, String?) -> Void) {
        do {
            reply(Data(try keeper.issue(host: host)), nil)
        } catch {
            reply(nil, "\(error)")
        }
    }

    public func status(reply: @escaping (Bool, String?) -> Void) {
        reply(keeper.hasAuthority, nil)
    }
}

/// The proxy's side of the same conversation.
///
/// Written here rather than in the proxy so both ends are read together: a client and a
/// service that drift apart fail at run time, in a process nobody is attached to.
public final class AuthorityClient: Sendable {

    public enum Failure: Error, Sendable, Equatable {
        case unavailable(String)
        case refused(String)
    }

    private let machServiceName: String

    public init(machServiceName: String = AuthorityServiceName.mach) {
        self.machServiceName = machServiceName
    }

    private func connect() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        connection.remoteObjectInterface = NSXPCInterface(with: AuthorityService.self)
        connection.resume()
        return connection
    }

    public func materials() async throws -> (certificateDER: [UInt8], leafKeyDER: [UInt8]) {
        let connection = connect()
        defer { connection.invalidate() }
        return try await withCheckedThrowingContinuation { continuation in
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                continuation.resume(throwing: Failure.unavailable("\(error)"))
            } as? AuthorityService
            guard let proxy else {
                continuation.resume(throwing: Failure.unavailable("interface absente"))
                return
            }
            proxy.materials { certificate, key, message in
                if let certificate, let key {
                    continuation.resume(returning: (Array(certificate), Array(key)))
                } else {
                    continuation.resume(throwing: Failure.refused(message ?? "inconnu"))
                }
            }
        }
    }

    public func issue(host: String) async throws -> [UInt8] {
        let connection = connect()
        defer { connection.invalidate() }
        return try await withCheckedThrowingContinuation { continuation in
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                continuation.resume(throwing: Failure.unavailable("\(error)"))
            } as? AuthorityService
            guard let proxy else {
                continuation.resume(throwing: Failure.unavailable("interface absente"))
                return
            }
            proxy.issue(host: host) { der, message in
                if let der { continuation.resume(returning: Array(der)) }
                else { continuation.resume(throwing: Failure.refused(message ?? "inconnu")) }
            }
        }
    }
}
