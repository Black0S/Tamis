// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisSystem",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisSystem", targets: ["TamisSystem"])
    ],
    targets: [
        .target(name: "TamisSystem", swiftSettings: [.swiftLanguageMode(.v6)]),
        .executableTarget(
            name: "tamis-preflight",
            dependencies: ["TamisSystem"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisSystemTests",
            dependencies: ["TamisSystem"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
