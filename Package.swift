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
            checksum: "065281d0db6f0c52ab97a4b912b20faeb84c580fec845578d0f70fcbcc380b21"
        ),
        .target(
            name: "EcliptixProtectedProtocol",
            dependencies: ["EcliptixProtectedProtocolBinary"],
            path: "swift/Sources/EcliptixProtectedProtocol"
        )
    ]
)
