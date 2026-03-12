// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "aegis-secret",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "AegisSecretCore",
            targets: ["AegisSecretCore"]
        ),
        .executable(
            name: "aegis-secret",
            targets: ["aegis-secret"]
        ),
        .executable(
            name: "aegis-secret-mcp",
            targets: ["aegis-secret-mcp"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/modelcontextprotocol/swift-sdk.git", from: "0.11.0")
    ],
    targets: [
        .target(
            name: "AegisSecretCore"
        ),
        .executableTarget(
            name: "aegis-secret",
            dependencies: ["AegisSecretCore"]
        ),
        .executableTarget(
            name: "aegis-secret-mcp",
            dependencies: [
                "AegisSecretCore",
                .product(name: "MCP", package: "swift-sdk")
            ]
        ),
        .testTarget(
            name: "AegisSecretCoreTests",
            dependencies: ["AegisSecretCore"]
        ),
    ]
)
