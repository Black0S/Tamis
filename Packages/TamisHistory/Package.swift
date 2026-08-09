// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisHistory",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisHistory", targets: ["TamisHistory"])
    ],
    targets: [
        .target(name: "TamisHistory", swiftSettings: [.swiftLanguageMode(.v6)]),
        .testTarget(
            name: "TamisHistoryTests",
            dependencies: ["TamisHistory"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
