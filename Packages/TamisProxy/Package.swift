// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "TamisProxy",
    platforms: [.macOS(.v26)],
    products: [
        .library(name: "TamisProxy", targets: ["TamisProxy"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.83.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.31.0"),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.36.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(path: "../TamisTLS"),
        .package(path: "../TamisFilterEngine"),
    ],
    targets: [
        .target(
            name: "TamisProxy",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "X509", package: "swift-certificates"),
                "TamisTLS",
                "TamisFilterEngine",
            ],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "TamisProxyTests",
            dependencies: ["TamisProxy", "TamisTLS", .product(name: "NIOSSL", package: "swift-nio-ssl"), .product(name: "NIOHTTP1", package: "swift-nio"), .product(name: "NIOConcurrencyHelpers", package: "swift-nio"), .product(name: "X509", package: "swift-certificates")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
