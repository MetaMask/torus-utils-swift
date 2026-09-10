import BigInt
import FetchNodeDetails
import Foundation
@testable import TorusUtils
import XCTest

final class CitadelUtilsTests: XCTestCase {
    func testBuildAllowURLUsesExactEncodedQueryNames() throws {
        let url = try CitadelUtils.buildAllowUrl(params: CitadelAllowParams(
            buildEnv: .development,
            verifier: "google",
            verifierId: "user+alias@example.com",
            network: "sapphire_devnet",
            clientId: "client id",
            recordId: "record-id",
            source: "ios sdk",
            oauthInitiated: .set,
            oauthCompleted: .unset,
            oauthVerificationFailed: .set
        ))
        let components = try XCTUnwrap(URLComponents(url: url, resolvingAgainstBaseURL: false))
        let values = Dictionary(uniqueKeysWithValues: try XCTUnwrap(components.queryItems).map {
            ($0.name, $0.value)
        })

        XCTAssertEqual(url.host, "api-develop.web3auth.io")
        XCTAssertEqual(url.path, "/citadel-service/v1/signer/allow")
        XCTAssertEqual(values["recordid"], "record-id")
        XCTAssertEqual(values["verifier"], "google")
        XCTAssertEqual(values["verifierid"], "user+alias@example.com")
        XCTAssertEqual(values["network"], "sapphire_devnet")
        XCTAssertEqual(values["clientid"], "client id")
        XCTAssertEqual(values["source"], "ios sdk")
        XCTAssertEqual(values["oauthInitiated"], "1")
        XCTAssertEqual(values["oauthCompleted"], "0")
        XCTAssertEqual(values["oauthVerificationFailed"], "1")
        XCTAssertNil(values["oauthVerified"] ?? nil)
        XCTAssertNil(values["oauthFailed"] ?? nil)
    }

    func testBuildAuditPayloadMatchesJavascriptShape() {
        let retrieveParams = RetrieveSharesParams(
            endpoints: ["endpoint"],
            indexes: [BigUInt(1)],
            nodePubKeys: [TorusNodePubModel(_X: "x", _Y: "y")],
            verifier: "aggregate-verifier",
            verifierParams: VerifierParams(
                verifier_id: "user-id",
                sub_verifier_ids: ["google"]
            ),
            idToken: "id-token",
            recordId: "record-id",
            authConnection: "auth0"
        )
        let result = CitadelUtils.buildAuditPayload(
            network: .SAPPHIRE_DEVNET,
            clientId: "client-id",
            params: retrieveParams,
            authFlowAuditParams: CitadelAuthFlowAuditParams(
                oauthVerified: true,
                oauthCompleted: true
            )
        )

        XCTAssertEqual(result.recordId, "record-id")
        XCTAssertEqual(result.authConnection, "auth0")
        XCTAssertEqual(result.authConnectionId, "google")
        XCTAssertEqual(result.groupedAuthConnectionId, "aggregate-verifier")
        XCTAssertEqual(result.oAuthUserId, "user-id")
        XCTAssertEqual(result.web3AuthNetwork, "sapphire_devnet")
        XCTAssertEqual(result.web3AuthClientId, "client-id")
        XCTAssertEqual(result.oauthCompleted, true)
        XCTAssertEqual(result.oauthVerified, true)
    }

    func testGenerateRecordIDReturnsUUID() {
        let recordId = CitadelUtils.generateRecordId()
        XCTAssertEqual(UUID(uuidString: recordId)?.uuidString.lowercased(), recordId)
    }
}
