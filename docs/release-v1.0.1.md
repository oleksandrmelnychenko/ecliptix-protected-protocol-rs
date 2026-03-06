# Ecliptix Protected Protocol v1.0.1

## Summary

- hardened the core protocol defaults and removed implicit legacy permissive paths
- added mandatory authorization for external group join flows
- bound handshake identity material more strictly to close misbinding risk
- enforced group franking policy on receive path, not only sender path
- aligned Rust, C FFI, and Swift wrappers around the same security model
- improved Swift session verification UX with peer identity, binding hash, and verified handshake helpers
- removed stale audit PoCs and dead key-abstraction code

## Swift Package Manager

```swift
.binaryTarget(
    name: "EcliptixProtectedProtocolBinary",
    url: "https://github.com/oleksandrmelnychenko/ecliptix-protected-protocol-rs/releases/download/v1.0.1/ecliptix-protected-protocol.xcframework.zip",
    checksum: "9171c6bdb4158202562ca681150fe375702286443b087f6bab3b459a1eceedcd"
)
```

## Release Artifacts

- archive: `dist/apple/ecliptix-protected-protocol.xcframework.zip`
- sha256: `9171c6bdb4158202562ca681150fe375702286443b087f6bab3b459a1eceedcd`

## Notable Breaking Changes

- default group creation now uses a hardened shielded posture
- external join now requires an explicit authorization artifact
- Swift and FFI consumers should verify peers via identity APIs instead of trusting handshake completion alone
- group decrypt FFI result now exposes sealed/franking payload details directly

## Verification Performed

- `cargo fmt`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features`
- local Apple release staticlibs built for:
  - `aarch64-apple-darwin`
  - `aarch64-apple-ios`
  - `aarch64-apple-ios-sim`
  - `x86_64-apple-ios`
- local XCFramework archive and checksum generated from the same build flow as CI
