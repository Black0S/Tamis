import Foundation
import JavaScriptCore
import Testing
@testable import TamisSystem

/// The script is executed, not read.
///
/// A PAC that looks right and answers wrongly is indistinguishable from a correct one
/// by inspection, and this is the file that decides whether a banking connection enters
/// the process. JavaScriptCore is a system framework, so running it costs nothing.
@Suite("Proxy auto-configuration")
struct ProxyAutoConfigTests {

    private struct Evaluator {
        let context: JSContext

        init(proxyPort: UInt16 = 7654, directHosts: [String] = []) throws {
            context = try #require(JSContext())
            context.evaluateScript(ProxyAutoConfig.script(
                proxyPort: proxyPort, directHosts: directHosts
            ))
            if let exception = context.exception {
                Issue.record("le script ne s'évalue pas : \(exception)")
            }
        }

        func result(for host: String, scheme: String = "https") -> String {
            let value = context.objectForKeyedSubscript("FindProxyForURL")?
                .call(withArguments: ["\(scheme)://\(host)/", host])
            return value?.toString() ?? "<nil>"
        }
    }

    @Test("Ordinary traffic goes to the proxy")
    func ordinary() throws {
        let pac = try Evaluator(proxyPort: 7654)
        #expect(pac.result(for: "www.lemonde.fr") == "PROXY 127.0.0.1:7654")
        #expect(pac.result(for: "example.com") == "PROXY 127.0.0.1:7654")
    }

    /// The promise, enforced before the connection exists: excluded traffic never
    /// reaches the process at all, rather than reaching it and being tunnelled.
    @Test("An excluded host never reaches the proxy")
    func excluded() throws {
        let pac = try Evaluator(directHosts: ["bnpparibas", "lastpass.com"])
        #expect(pac.result(for: "bnpparibas") == "DIRECT")
        #expect(pac.result(for: "mabanque.bnpparibas") == "DIRECT")
        #expect(pac.result(for: "www.lastpass.com") == "DIRECT")
        // A name that merely ends with the same letters is a different site.
        #expect(pac.result(for: "notlastpass.com").hasPrefix("PROXY"))
    }

    @Test("Local development never crosses the proxy", arguments: [
        "localhost", "myapp.local", "service.internal", "api.test",
        "site.localhost", "host.docker.internal", "docker.internal",
        "buildserver",
    ])
    func localDevelopment(host: String) throws {
        let pac = try Evaluator()
        #expect(pac.result(for: host) == "DIRECT", "\(host)")
    }

    @Test("Private and loopback addresses go direct", arguments: [
        "127.0.0.1", "127.1.2.3", "10.0.0.5", "192.168.1.10",
        "172.16.0.1", "172.31.255.254", "169.254.1.1", "[::1]", "[fd00::1]",
    ])
    func privateAddresses(host: String) throws {
        let pac = try Evaluator()
        #expect(pac.result(for: host) == "DIRECT", "\(host)")
    }

    /// 172.32 is public even though 172.16–172.31 is not, and a rule that treats the
    /// whole of 172/8 as private would send real traffic unfiltered.
    @Test("Public addresses still go to the proxy", arguments: [
        "8.8.8.8", "172.32.0.1", "172.15.0.1", "1.1.1.1", "93.184.216.34",
    ])
    func publicAddresses(host: String) throws {
        let pac = try Evaluator()
        #expect(pac.result(for: host).hasPrefix("PROXY"), "\(host)")
    }

    /// The rule the whole file exists under: evaluating a PAC must not generate DNS
    /// traffic, because the thing it configures is where DNS goes.
    @Test("The script never calls dnsResolve")
    func noDNSResolve() {
        // Comments are stripped first: the generated file explains *why* it avoids
        // dnsResolve, and a test that reads the prose rather than the code would fail
        // on its own documentation.
        let code = ProxyAutoConfig.script(proxyPort: 1, directHosts: ["a.example"])
            .split(separator: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")

        for resolver in ["dnsResolve", "dnsResolveEx", "isResolvable", "myIpAddress"] {
            #expect(!code.contains(resolver), "\(resolver) est appelé")
        }
    }

    /// Quitting the application must not stop the machine browsing.
    @Test("The fail-open script sends everything direct")
    func failOpen() throws {
        let context = try #require(JSContext())
        context.evaluateScript(ProxyAutoConfig.failOpen)
        let result = context.objectForKeyedSubscript("FindProxyForURL")?
            .call(withArguments: ["https://example.com/", "example.com"])
        #expect(result?.toString() == "DIRECT")
    }

    /// An unchanged configuration has to produce an identical file, or every rebuild
    /// looks to the system like a configuration change.
    @Test("The same input produces the same script")
    func deterministic() {
        let a = ProxyAutoConfig.script(proxyPort: 7654, directHosts: ["b.example", "a.example"])
        let b = ProxyAutoConfig.script(proxyPort: 7654, directHosts: ["a.example", "b.example", "a.example"])
        #expect(a == b)
    }

    /// The real list, at its real size, answering in the time a request can afford.
    @Test("Four thousand exclusions still answer immediately")
    func realSize() throws {
        let hosts = (0..<4_500).map { "host\($0).example" } + ["mabanque.bnpparibas"]
        let script = ProxyAutoConfig.script(proxyPort: 7654, directHosts: hosts)

        let context = try #require(JSContext())
        context.evaluateScript(script)
        let function = try #require(context.objectForKeyedSubscript("FindProxyForURL"))

        // Warm, then measure the shape that matters: a miss, which walks every label.
        _ = function.call(withArguments: ["https://www.lemonde.fr/", "www.lemonde.fr"])
        let started = Date()
        for _ in 0..<10_000 {
            _ = function.call(withArguments: ["https://www.lemonde.fr/", "www.lemonde.fr"])
        }
        let each = Date().timeIntervalSince(started) / 10_000

        print(String(format: "  PAC %.1f Ko · %.1f µs par requête",
                     Double(script.utf8.count) / 1024, each * 1_000_000))
        #expect(each < 0.0005, "un PAC sur le chemin de chaque requête ne peut pas coûter cela")

        let value = function.call(withArguments: ["https://mabanque.bnpparibas/", "mabanque.bnpparibas"])
        #expect(value?.toString() == "DIRECT")
    }
}
