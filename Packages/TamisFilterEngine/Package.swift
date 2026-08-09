// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisFilterEngine",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisFilterEngine", targets: ["TamisFilterEngine"])
    ],
    targets: [
        .target(
            name: "TamisFilterEngine",
            resources: [.copy("Resources")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "tamis-bench",
            dependencies: ["TamisFilterEngine"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisFilterEngineTests",
            dependencies: ["TamisFilterEngine"],
            resources: [.copy("Resources")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
