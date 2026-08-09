// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisLists",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisLists", targets: ["TamisLists"])
    ],
    dependencies: [
        .package(path: "../TamisFilterEngine"),
        .package(path: "../TamisDNS"),
    ],
    targets: [
        .target(
            name: "TamisLists",
            resources: [.copy("Resources")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // The diagnostic tools reach for the engines; the library deliberately does
        // not, so nothing that imports TamisLists inherits them.
        .executableTarget(
            name: "tamis-lists",
            dependencies: ["TamisLists", "TamisFilterEngine", "TamisDNS"],
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
