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
            url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.0.2/ecliptix-protected-protocol.xcframework.zip",
            checksum: "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        .target(
            name: "EcliptixProtectedProtocolSwift",
            dependencies: ["EcliptixProtectedProtocol"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
