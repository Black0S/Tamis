// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisDNS",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisDNS", targets: ["TamisDNS"])
    ],
    targets: [
        .target(
            name: "TamisDNS",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "tamis-dnsbench",
            dependencies: ["TamisDNS"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisDNSTests",
            dependencies: ["TamisDNS"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
