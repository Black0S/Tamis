import Foundation
import TamisSystem

// Serves the proxy auto-configuration file, and outlives the application.
//
//   tamis-pac --port 7655
//
// Installed as a launch agent, because macOS keeps asking for this URL after Tamis is
// closed. When the proxy is not answering it serves DIRECT for everything: quitting the
// application must not stop the machine browsing.

setvbuf(stdout, nil, _IOLBF, 0)

let arguments = Array(CommandLine.arguments.dropFirst())
func value(after flag: String) -> String? {
    guard let i = arguments.firstIndex(of: flag), i + 1 < arguments.count else { return nil }
    return arguments[i + 1]
}

let port = UInt16(value(after: "--port") ?? "7655") ?? 7655
let proxyPort = UInt16(value(after: "--proxy-port") ?? "7654") ?? 7654
let pacURL = value(after: "--pac").map(URL.init(fileURLWithPath:))
    ?? Installation.supportDirectory.appending(path: "proxy.pac")

let server = PACServer(pacURL: pacURL, proxyPort: proxyPort)
do {
    try server.start(port: port)
} catch {
    FileHandle.standardError.write(Data("tamis-pac : \(error)\n".utf8))
    exit(1)
}

print("PAC servi sur http://127.0.0.1:\(server.boundPort ?? port)/tamis.pac")
print("  fichier      \(pacURL.path(percentEncoded: false))")
print("  proxy        127.0.0.1:\(proxyPort)")
print("  repli        DIRECT si le proxy ne répond pas")

while true { try await Task.sleep(for: .seconds(3600)) }
