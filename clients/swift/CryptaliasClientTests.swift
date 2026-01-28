import Foundation
import XCTest

final class CryptaliasClientTests: XCTestCase {
  func testVerifyJwsPayload() throws {
    let url = URL(fileURLWithPath: "../testdata/jws.json")
    let data = try Data(contentsOf: url)
    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
    let jws = json?["jws"] as? String ?? ""
    let jwk = json?["jwk"] as? [String: Any] ?? [:]
    let payload = try verifyJwsPayload(jws: jws, jwk: jwk)
    let expected = (json?["payload"] as? [String: Any])?["address"] as? String
    XCTAssertEqual(payload["address"] as? String, expected)
  }
}
