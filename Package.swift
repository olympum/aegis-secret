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
    ],
    targets: [
        .target(
            name: "AegisSecretCore"
        ),
        .executableTarget(
            name: "aegis-secret",
            dependencies: ["AegisSecretCore"]
        ),
        .testTarget(
            name: "AegisSecretCoreTests",
            dependencies: ["AegisSecretCore"]
        ),
    ]
)
