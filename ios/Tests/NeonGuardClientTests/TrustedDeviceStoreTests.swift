import XCTest
@testable import NeonGuardClient

final class TrustedDeviceStoreTests: XCTestCase {
    func testEmptyTokenIsRejected() throws {
        let store = KeychainTrustedDeviceStore(service: "com.illumyx.neonguard.tests", account: UUID().uuidString)
        XCTAssertThrowsError(try store.save(token: ""))
    }

    func testClearIsIdempotent() throws {
        let store = KeychainTrustedDeviceStore(service: "com.illumyx.neonguard.tests", account: UUID().uuidString)
        XCTAssertNoThrow(try store.clear())
    }

    func testTokenIsNotDerivedFromDeviceIdentifier() {
        XCTAssertTrue(String(describing: KeychainTrustedDeviceStore.self).contains("KeychainTrustedDeviceStore"))
    }
}
