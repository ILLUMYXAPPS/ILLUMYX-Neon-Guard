// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NeonGuardClient",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(name: "NeonGuardClient", targets: ["NeonGuardClient"])
    ],
    targets: [
        .target(name: "NeonGuardClient"),
        .testTarget(name: "NeonGuardClientTests", dependencies: ["NeonGuardClient"])
    ]
)
