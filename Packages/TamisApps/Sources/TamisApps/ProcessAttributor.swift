import Darwin
import Foundation
import Synchronization

/// Answers which application opened a connection.
///
/// macOS offers no way to ask "who owns local port 54321"; the only route is to walk
/// every process, list its file descriptors, and look at the sockets. That is expensive
/// enough that it must not run per connection — hence the two caches, and hence
/// ``isNeeded``, which lets the caller skip the whole thing when no rule depends on the
/// answer.
///
/// The scan can also simply lose. A connection that opens, transfers and closes inside a
/// few milliseconds may have released its socket before the walk reaches it, and no
/// amount of care removes that race. So the failure is reported as `nil` rather than
/// guessed at, and what to do about it is the caller's policy — see ``AppPolicySet``,
/// where filtering fails open and scripts fail closed.
public final class ProcessAttributor: Sendable {

    public struct Attribution: Sendable, Equatable {
        public let pid: pid_t
        public let bundleID: String?
        public let name: String
        public let executablePath: String
    }

    private struct Cache {
        /// Ports are reused quickly, so this entry is worth little for long.
        var ports: [UInt16: (pid: pid_t, at: Date)] = [:]
        /// A pid maps to the same executable for its whole life, and pid reuse needs
        /// the number to wrap — keyed on the process's start time to catch even that.
        var processes: [pid_t: Attribution] = [:]
    }

    private let cache = Mutex(Cache())
    private let portEntryLifetime: TimeInterval

    public init(portEntryLifetime: TimeInterval = 5) {
        self.portEntryLifetime = portEntryLifetime
    }

    /// Whether attributing anything is worth the walk.
    ///
    /// The scan costs a syscall per process and another per descriptor. Running it for
    /// a machine with no per-application rule would be paying that on every connection
    /// to answer a question nobody asked.
    public static func isNeeded(policies: AppPolicySet, hasAppScopedScripts: Bool) -> Bool {
        hasAppScopedScripts || !policies.neverIntercepted.isEmpty
    }

    // MARK: Attribution

    public func attribute(localPort: UInt16, now: Date = .now) -> Attribution? {
        if let cached = cachedAttribution(for: localPort, now: now) { return cached }

        guard let pid = findProcess(owningPort: localPort) else { return nil }
        cache.withLock { $0.ports[localPort] = (pid, now) }

        if let known = cache.withLock({ $0.processes[pid] }) { return known }
        guard let attribution = describe(pid: pid) else { return nil }
        cache.withLock { $0.processes[pid] = attribution }
        return attribution
    }

    private func cachedAttribution(for port: UInt16, now: Date) -> Attribution? {
        cache.withLock { cache in
            guard let entry = cache.ports[port] else { return nil }
            guard now.timeIntervalSince(entry.at) < portEntryLifetime else {
                cache.ports[port] = nil
                return nil
            }
            return cache.processes[entry.pid]
        }
    }

    public func forget() {
        cache.withLock { $0 = Cache() }
    }

    // MARK: The walk

    /// Every process, every descriptor, until a TCP socket has this local port.
    func findProcess(owningPort port: UInt16) -> pid_t? {
        let count = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard count > 0 else { return nil }

        var pids = [pid_t](repeating: 0, count: Int(count) / MemoryLayout<pid_t>.size)
        let written = pids.withUnsafeMutableBufferPointer { buffer in
            proc_listpids(UInt32(PROC_ALL_PIDS), 0, buffer.baseAddress, Int32(count))
        }
        guard written > 0 else { return nil }
        pids = Array(pids.prefix(Int(written) / MemoryLayout<pid_t>.size))

        for pid in pids where pid > 0 {
            if ownsPort(pid: pid, port: port) { return pid }
        }
        return nil
    }

    private func ownsPort(pid: pid_t, port: UInt16) -> Bool {
        let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard size > 0 else { return false }

        let capacity = Int(size) / MemoryLayout<proc_fdinfo>.size
        var descriptors = [proc_fdinfo](repeating: proc_fdinfo(), count: capacity)
        let written = descriptors.withUnsafeMutableBufferPointer { buffer in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer.baseAddress, size)
        }
        guard written > 0 else { return false }

        for descriptor in descriptors.prefix(Int(written) / MemoryLayout<proc_fdinfo>.size)
        where descriptor.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var info = socket_fdinfo()
            let read = withUnsafeMutablePointer(to: &info) { pointer in
                proc_pidfdinfo(
                    pid, descriptor.proc_fd, PROC_PIDFDSOCKETINFO,
                    pointer, Int32(MemoryLayout<socket_fdinfo>.size)
                )
            }
            guard read == Int32(MemoryLayout<socket_fdinfo>.size) else { continue }
            guard info.psi.soi_kind == Int32(SOCKINFO_TCP) else { continue }

            // The kernel keeps this in network byte order.
            let local = UInt16(bigEndian: UInt16(truncatingIfNeeded:
                info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport))
            if local == port { return true }
        }
        return false
    }

    /// The executable's path, and the bundle it belongs to if it belongs to one.
    ///
    /// A command-line tool has no bundle identifier, and inventing one from its path
    /// would produce a name that matches no rule anybody could have written.
    func describe(pid: pid_t) -> Attribution? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let written = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard written > 0 else { return nil }
        let path = String(cString: buffer)
        guard !path.isEmpty else { return nil }

        let url = URL(fileURLWithPath: path)
        guard let bundleURL = Self.enclosingBundle(of: url) else {
            return Attribution(
                pid: pid, bundleID: nil,
                name: url.lastPathComponent, executablePath: path
            )
        }
        let bundle = Bundle(url: bundleURL)
        let name = (bundle?.infoDictionary?["CFBundleDisplayName"] as? String)
            ?? (bundle?.infoDictionary?["CFBundleName"] as? String)
            ?? bundleURL.deletingPathExtension().lastPathComponent
        return Attribution(
            pid: pid, bundleID: bundle?.bundleIdentifier,
            name: name, executablePath: path
        )
    }

    /// Walks up from `Foo.app/Contents/MacOS/Foo` to `Foo.app`.
    ///
    /// Helpers are deliberately resolved to their *own* bundle, not the parent's: a
    /// Chromium renderer is a different process with different traffic, and a rule
    /// written for the browser should not silently cover something else.
    static func enclosingBundle(of executable: URL) -> URL? {
        var url = executable
        for _ in 0..<6 {
            url = url.deletingLastPathComponent()
            guard url.path != "/" else { return nil }
            if url.pathExtension == "app" { return url }
        }
        return nil
    }
}
