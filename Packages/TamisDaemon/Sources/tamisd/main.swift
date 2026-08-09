import Foundation
import TamisDaemon

// The privileged half of Tamis, and the smallest thing that could hold a key.
//
// It creates the certificate authority on first run, keeps it root-owned at 0600, and
// signs one leaf per request. It opens no socket, reads nothing from the network, and
// exports no method that returns the signing key — the three properties that let the
// rest of Tamis parse hostile content without ever being able to mint a certificate on
// its own.

setvbuf(stdout, nil, _IOLBF, 0)

let keeper = AuthorityKeeper()
do {
    let created = try keeper.prepare()
    print(created ? "autorité créée" : "autorité chargée")
} catch {
    FileHandle.standardError.write(Data("tamisd : \(error)\n".utf8))
    exit(1)
}

let delegate = AuthorityListener(keeper: keeper)
let listener = NSXPCListener(machServiceName: AuthorityServiceName.mach)
listener.delegate = delegate
listener.resume()

print("tamisd en écoute sur \(AuthorityServiceName.mach)")
RunLoop.current.run()
