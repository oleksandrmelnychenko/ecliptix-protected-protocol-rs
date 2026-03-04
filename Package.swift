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
            targets: ["EcliptixProtectedProtocol"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "EcliptixProtectedProtocolBinary",
            url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.0.0/EcliptixProtectedProtocol.xcframework.zip",
            checksum: "4bb99aa22d3029d6f199fce9350cd3e0bbc30d0b3f3ad131e64e8f1d794ea8bf"
        ),
        .target(
            name: "EcliptixProtectedProtocol",
            dependencies: ["EcliptixProtectedProtocolBinary"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
