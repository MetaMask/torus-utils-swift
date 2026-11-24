import BigInt
import FetchNodeDetails
import JWTKit
import TorusUtils
import XCTest

class CyanTest: XCTestCase {
    var TORUS_TEST_EMAIL = "hello@tor.us"
    var TORUS_TEST_VERIFIER = "torus-test-health"
    var TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate"
    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .CYAN)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .CYAN))
    }

    func test_should_fetch_public_address() async throws {
        let verifier: String = "tkey-google-cyan"
        let verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xA3767911A84bE6907f26C572bc89426dDdDB2825")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xA3767911A84bE6907f26C572bc89426dDdDB2825")
        XCTAssertEqual(val.oAuthKeyData!.X, "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a")
        XCTAssertEqual(val.oAuthKeyData!.Y, "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xA3767911A84bE6907f26C572bc89426dDdDB2825")
        XCTAssertEqual(val.finalKeyData!.X, "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a")
        XCTAssertEqual(val.finalKeyData!.Y, "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1")
        XCTAssertNil(val.metadata?.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, UserType(rawValue: "v1"))
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_fetch_user_type_and_addresses() async throws {
        var verifier: String = "tkey-google-cyan"
        var verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        var data = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(data.finalKeyData!.evmAddress, "0x3507F0d192a44E436B8a6C32a37d57D022861b1a")
        XCTAssertLessThan(data.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData?.evmAddress, "0xA3767911A84bE6907f26C572bc89426dDdDB2825")
        XCTAssertEqual(data.oAuthKeyData?.X, "2853f323437da98ce021d06854f4b292db433c0ad03b204ef223ac2583609a6a")
        XCTAssertEqual(data.oAuthKeyData?.Y, "f026b4788e23523e0c8fcbf0bdcf1c1a62c9cde8f56170309607a7a52a19f7c1")
        XCTAssertEqual(data.finalKeyData?.evmAddress, "0x3507F0d192a44E436B8a6C32a37d57D022861b1a")
        XCTAssertEqual(data.finalKeyData?.X, "8aaadab9530cb157d0b0dfb7b27d1a3aaca45274563c22c92c77ee2191779051")
        XCTAssertEqual(data.finalKeyData?.Y, "d57b89d9f62bb6609d8542c3057943805c8c72f6f27d39781b820f27d7210f12")
        XCTAssertEqual(data.metadata?.pubNonce?.x, "5f2505155e2c1119ee8a76d0f3b22fccee45871d4aab3cb6209bdbc302b5abc2")
        XCTAssertEqual(data.metadata?.pubNonce?.y, "a20f30868759a6095697d5631483faa650f489b33c0e2958ad8dc29e707c0a99")
        XCTAssertEqual(data.metadata?.nonce, BigUInt.zero)
        XCTAssertEqual(data.metadata?.upgraded, false)
        XCTAssertEqual(data.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(data.nodesData)

        verifier = "tkey-google-cyan"
        verifierID = "somev2user@gmail.com"
        data = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(data.finalKeyData!.evmAddress, "0x8EA83Ace86EB414747F2b23f03C38A34E0217814")
        XCTAssertLessThan(data.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData?.evmAddress, "0x29446f428293a4E6470AEaEDa6EAfA0F842EF54e")
        XCTAssertEqual(data.oAuthKeyData?.X, "8b6f2048aba8c7833e3b02c5b6522bb18c484ad0025156e428f17fb8d8c34021")
        XCTAssertEqual(data.oAuthKeyData?.Y, "cd9ba153ff89d665f655d1be4c6912f3ff93996e6fe580d89e78bf1476fef2aa")
        XCTAssertEqual(data.finalKeyData?.evmAddress, "0x8EA83Ace86EB414747F2b23f03C38A34E0217814")
        XCTAssertEqual(data.finalKeyData?.X, "cbe7b0f0332e5583c410fcacb6d4ff685bec053cfd943ac75f5e4aa3278a6fbb")
        XCTAssertEqual(data.finalKeyData?.Y, "b525c463f438c7a3c4b018c8c5d16c9ef33b9ac6f319140a22b48b17bdf532dd")
        XCTAssertEqual(data.metadata?.pubNonce?.x, "da0039dd481e140090bed9e777ce16c0c4a16f30f47e8b08b73ac77737dd2d4")
        XCTAssertEqual(data.metadata?.pubNonce?.y, "7fecffd2910fa47dbdbc989f5c119a668fc922937175974953cbb51c49268265")
        XCTAssertEqual(data.metadata?.nonce, BigUInt.zero)
        XCTAssertEqual(data.metadata?.upgraded, false)
        XCTAssertEqual(data.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(data.nodesData?.nodeIndexes)

        verifier = "tkey-google-cyan"
        verifierID = "caspertorus@gmail.com"
        data = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(data.finalKeyData!.evmAddress, "0xCC1f953f6972a9e3d685d260399D6B85E2117561")
        XCTAssertLessThan(data.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData?.evmAddress, "0xe8a19482cbe5FaC896A5860Ca4156fb999DDc73b")
        XCTAssertEqual(data.oAuthKeyData?.X, "c491ba39155594896b27cf71a804ccf493289d918f40e6ba4d590f1c76139e9e")
        XCTAssertEqual(data.oAuthKeyData?.Y, "d4649ed9e46461e1af00399a4c65fabb1dc219b3f4af501a7d635c17f57ab553")
        XCTAssertEqual(data.finalKeyData?.evmAddress, "0xCC1f953f6972a9e3d685d260399D6B85E2117561")
        XCTAssertEqual(data.finalKeyData?.X, "8d784434becaad9b23d9293d1f29c4429447315c4cac824cbf2eb21d3f7d79c8")
        XCTAssertEqual(data.finalKeyData?.Y, "fe46a0ef5efe33d16f6cfa678a597be930fbec5432cbb7f3580189c18bd7e157")
        XCTAssertEqual(data.metadata?.pubNonce?.x, "50e250cc6ac1d50d32d2b0f85f11c6625a917a115ced4ef24f4eac183e1525c7")
        XCTAssertEqual(data.metadata?.pubNonce?.y, "8067a52d02b8214bf82e91b66ce5009f674f4c3998b103059c46c386d0c17f90")
        XCTAssertEqual(data.metadata?.nonce, BigUInt.zero)
        XCTAssertEqual(data.metadata?.upgraded, false)
        XCTAssertEqual(data.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(data.nodesData)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier: String = "tkey-google-cyan"
        let verifierID: String = fakeEmail
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let data = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)
        XCTAssertNotEqual(data.finalKeyData?.evmAddress, "")
        XCTAssertNotEqual(data.oAuthKeyData?.evmAddress, "")
        XCTAssertEqual(data.metadata?.typeOfUser, .v1)
        XCTAssertEqual(data.metadata?.upgraded, false)
    }

    func test_should_be_able_to_login() async throws {
        let verifier: String = TORUS_TEST_VERIFIER
        let verifierID: String = TORUS_TEST_EMAIL
        let jwt = try! generateIdToken(email: verifierID)
        let verifierParams = VerifierParams(verifier_id: verifierID)
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: jwt))

        XCTAssertEqual(data.finalKeyData.evmAddress, "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.finalKeyData.evmAddress, "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9")
        XCTAssertEqual(data.finalKeyData.X, "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1")
        XCTAssertEqual(data.finalKeyData.Y, "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359")
        XCTAssertEqual(data.finalKeyData.privKey, "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8")
        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0xC615aA03Dd8C9b2dc6F7c43cBDfF2c34bBa47Ec9")
        XCTAssertEqual(data.oAuthKeyData.X, "e2ed6033951af2851d1bea98799e62fb1ff24b952c1faea17922684678ba42d1")
        XCTAssertEqual(data.oAuthKeyData.Y, "beef0efad88e81385952c0068ca48e8b9c2121be87cb0ddf18a68806db202359")
        XCTAssertEqual(data.oAuthKeyData.privKey, "5db51619684b32a2ff2375b4c03459d936179dfba401cb1c176b621e8a2e4ac8")
        XCTAssertNil(data.metadata.pubNonce)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.typeOfUser, .v1)
        XCTAssertNil(data.metadata.upgraded)
        XCTAssertNotNil(data.nodesData)
    }

    func test_should_be_able_to_aggregate_login() async throws {
        let verifier: String = TORUS_TEST_AGGREGATE_VERIFIER
        let verifierID: String = TORUS_TEST_EMAIL
        let jwt = try! generateIdToken(email: TORUS_TEST_EMAIL)
        let verifierParams = VerifierParams(verifier_id: verifierID, sub_verifier_ids: [TORUS_TEST_VERIFIER], verify_params: [VerifyParams(verifier_id: TORUS_TEST_EMAIL, idtoken: jwt)])
        let hashedIDToken = try KeyUtils.keccak256Data(jwt)
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: hashedIDToken))

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04")
        XCTAssertEqual(data.finalKeyData.X, "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223")
        XCTAssertEqual(data.finalKeyData.Y, "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd")
        XCTAssertEqual(data.finalKeyData.privKey, "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf")
        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x34117FDFEFBf1ad2DFA6d4c43804E6C710a6fB04")
        XCTAssertEqual(data.oAuthKeyData.X, "afd12f2476006ef6aa8778190b29676a70039df8688f9dee69c779bdc8ff0223")
        XCTAssertEqual(data.oAuthKeyData.Y, "e557a5ee879632727f5979d6b9cea69d87e3dab54a8c1b6685d86dfbfcd785dd")
        XCTAssertEqual(data.oAuthKeyData.privKey, "45a5b62c4ff5490baa75d33bf4f03ba6c5b0095678b0f4055312eef7b780b7bf")
        XCTAssertNotNil(data.sessionData)
        XCTAssertNil(data.metadata.pubNonce)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.typeOfUser, .v1)
        XCTAssertNil(data.metadata.upgraded)
        XCTAssertNotNil(data.nodesData)
    }
}
