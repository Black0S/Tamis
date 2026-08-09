// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisDaemon",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisDaemon", targets: ["TamisDaemon"])
    ],
    dependencies: [
        .package(path: "../TamisTLS"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "TamisDaemon",
            dependencies: ["TamisTLS", .product(name: "X509", package: "swift-certificates")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "tamisd",
            dependencies: ["TamisDaemon", "TamisTLS"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisDaemonTests",
            dependencies: ["TamisDaemon", "TamisTLS"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
