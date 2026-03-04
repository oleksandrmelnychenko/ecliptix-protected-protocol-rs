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
            checksum: "01e1679318ed24d217b64af9e24fa536caf3e1cd359ef85e8a4569ee4de31514"
        ),
        .target(
            name: "EcliptixProtectedProtocolSwift",
            dependencies: ["EcliptixProtectedProtocol"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
