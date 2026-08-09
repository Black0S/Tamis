// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisApp",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "../TamisFilterEngine"),
        .package(path: "../TamisDNS"),
        .package(path: "../TamisUserScripts"),
        .package(path: "../TamisLists"),
        .package(path: "../TamisApps"),
        .package(path: "../TamisHistory"),
    ],
    targets: [
        .executableTarget(
            name: "TamisApp",
            dependencies: ["TamisFilterEngine", "TamisDNS", "TamisUserScripts", "TamisLists", "TamisApps", "TamisHistory"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        )
    ]
)
