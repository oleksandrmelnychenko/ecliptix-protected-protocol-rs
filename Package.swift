// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "EcliptixProtectedProtocol",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "EcliptixProtectedProtocol",
            targets: ["EcliptixProtectedProtocolSwift"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixProtectedProtocol",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.0.0/EcliptixProtectedProtocol.xcframework.zip",
            checksum: "3abb154c8536692f02b3ab278e202ccdc461c8c2a08d4daf230603db405b3b6b"
        ),
        .target(
            name: "EcliptixProtectedProtocolSwift",
            dependencies: ["EcliptixProtectedProtocol"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
