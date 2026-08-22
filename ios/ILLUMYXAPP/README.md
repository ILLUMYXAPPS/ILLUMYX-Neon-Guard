# ILLUMYXAPP iOS target

This is the native iOS application shell for ILLUMYXAPP.

- Bundle identifier: `com.illumyx.illumyxapp`
- Apple Team ID: `FJLRQ22M9C`
- Minimum iOS: 16.0
- SwiftUI application entry point: `ILLUMYXAPPApp.swift`

## Security integration

The existing `NeonGuardClient` Swift package remains the security boundary. The app must consume that package rather than embedding authorization policy, blocklists, HMAC secrets, or other server-side secrets.

## Before TestFlight

1. Open `ILLUMYXAPP.xcodeproj` in Xcode on a Mac.
2. Confirm the target uses `com.illumyx.illumyxapp` and Team `FJLRQ22M9C`.
3. Add the local `NeonGuardClient` package from `../Package.swift` if Xcode has not resolved it automatically.
4. Select a real iPad/iPhone destination and build.
5. Resolve any signing or provisioning prompts in Xcode.
6. Run the repository CI checks before merging the target branch.
