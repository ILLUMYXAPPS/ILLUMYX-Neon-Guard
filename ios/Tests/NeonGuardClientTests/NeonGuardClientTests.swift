import XCTest
@testable import NeonGuardClient

final class NeonGuardClientTests: XCTestCase {
    func testAllowResponseDecodes() throws {
        let data = Data(#"{"decision":"ALLOW"}"#.utf8)
        let response = try JSONDecoder().decode(AccessResponse.self, from: data)
        XCTAssertEqual(response.decision, .allow)
    }

    func testDenyResponseDecodes() throws {
        let data = Data(#"{"decision":"DENY"}"#.utf8)
        let response = try JSONDecoder().decode(AccessResponse.self, from: data)
        XCTAssertEqual(response.decision, .deny)
    }

    func testRequestEncodesCredentialWithoutLocalPolicy() throws {
        let data = try JSONEncoder().encode(AccessRequest(credential: "example"))
        let object = try JSONSerialization.jsonObject(with: data) as? [String: String]
        XCTAssertEqual(object?["credential"], "example")
    }
}
