// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisLists",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisLists", targets: ["TamisLists"])
    ],
    targets: [
        .target(
            name: "TamisLists",
            resources: [.copy("Resources")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "tamis-exclusions",
            dependencies: ["TamisLists"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisListsTests",
            dependencies: ["TamisLists"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
