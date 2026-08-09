// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisApps",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisApps", targets: ["TamisApps"])
    ],
    targets: [
        .target(name: "TamisApps", swiftSettings: [.swiftLanguageMode(.v6)]),
        .executableTarget(
            name: "tamis-apps",
            dependencies: ["TamisApps"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisAppsTests",
            dependencies: ["TamisApps"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
