// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisTLS",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisTLS", targets: ["TamisTLS"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "TamisTLS",
            dependencies: [.product(name: "X509", package: "swift-certificates")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisTLSTests",
            dependencies: ["TamisTLS"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
