// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisUserScripts",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisUserScripts", targets: ["TamisUserScripts"])
    ],
    targets: [
        .target(
            name: "TamisUserScripts",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisUserScriptsTests",
            dependencies: ["TamisUserScripts"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
