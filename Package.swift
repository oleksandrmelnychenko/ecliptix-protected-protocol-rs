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
            targets: ["EcliptixProtectedProtocolSwift", "EcliptixProtectedProtocol"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixProtectedProtocol",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.0.0/EcliptixProtectedProtocol.xcframework.zip",
            checksum: "88d5ed8498e57da3f698c529bffeefb8c877b66c2e745b5c4fb12e46791de373"
        ),
        .target(
            name: "EcliptixProtectedProtocolSwift",
            dependencies: ["EcliptixProtectedProtocol"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
