import BigInt
import FetchNodeDetails
import JWTKit
import TorusUtils
import XCTest

class TestnetTest: XCTestCase {
    var TORUS_TEST_EMAIL = "archit1@tor.us"
    var TORUS_TEST_VERIFIER = "torus-test-health"
    var TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate"
    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .TESTNET)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .TESTNET))
    }

    func test_should_fetch_public_address() async throws {
        let verifier = "google-lrc"
        let verifierID = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x9bcBAde70546c0796c00323CD1b97fa0a425A506")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x9bcBAde70546c0796c00323CD1b97fa0a425A506")
        XCTAssertEqual(val.finalKeyData!.X, "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5")
        XCTAssertEqual(val.finalKeyData!.Y, "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438")
        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x9bcBAde70546c0796c00323CD1b97fa0a425A506")
        XCTAssertEqual(val.oAuthKeyData!.X, "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5")
        XCTAssertEqual(val.oAuthKeyData!.Y, "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438")
        XCTAssertNil(val.metadata?.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v1)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_fetch_user_type_and_public_address() async throws {
        var verifier: String = "google-lrc"
        var verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        var val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xf5804f608C233b9cdA5952E46EB86C9037fd6842")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x9bcBAde70546c0796c00323CD1b97fa0a425A506")
        XCTAssertEqual(val.oAuthKeyData!.X, "894f633b3734ddbf08867816bc55da60803c1e7c2a38b148b7fb2a84160a1bb5")
        XCTAssertEqual(val.oAuthKeyData!.Y, "1cf2ea7ac63ee1a34da2330413692ba8538bf7cd6512327343d918e0102a1438")
        XCTAssertEqual(val.finalKeyData!.X, "ed737569a557b50722a8b5c0e4e5ca30cef1ede2f5674a0616b78246bb93dfd0")
        XCTAssertEqual(val.finalKeyData!.Y, "d9e8e6c54c12c4da38c2f0d1047fcf6089036127738f4ef72a83431339586ca9")
        XCTAssertEqual(val.metadata!.pubNonce!.x, "f3f7caefd6540d923c9993113f34226371bd6714a5be6882dedc95a6a929a8")
        XCTAssertEqual(val.metadata!.pubNonce!.y, "f28620603601ce54fa0d70fd691fb72ff52f5bf164bf1a91617922eaad8cc7a5")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)

        verifier = "tkey-google-lrc"
        verifierID = "somev2user@gmail.com"
        val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xE91200d82029603d73d6E307DbCbd9A7D0129d8D")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x376597141d8d219553378313d18590F373B09795")
        XCTAssertEqual(val.oAuthKeyData!.X, "86cd2db15b7a9937fa8ab7d0bf8e7f4113b64d1f4b2397aad35d6d4749d2fb6c")
        XCTAssertEqual(val.oAuthKeyData!.Y, "86ef47a3724144331c31a3a322d85b6fc1a5d113b41eaa0052053b6e3c74a3e2")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xE91200d82029603d73d6E307DbCbd9A7D0129d8D")
        XCTAssertEqual(val.finalKeyData!.X, "c350e338dde24df986915992fea6e0aef3560c245ca144ee7fe1498784c4ef4e")
        XCTAssertEqual(val.finalKeyData!.Y, "a605e52b65d3635f89654519dfa7e31f7b45f206ef4189866ad0c2240d40f97f")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "ad121b67fa550da814bbbd54ec7070705d058c941e04c03e07967b07b2f90345")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "bfe2395b177a72ebb836aaf24cedff2f14cd9ed49047990f5cdb99e4981b5753")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)

        verifier = "tkey-google-lrc"
        verifierID = "caspertorus@gmail.com"
        val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x1016DA7c47A04C76036637Ea02AcF1d29c64a456")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xd45383fbF04BccFa0450d7d8ee453ca86b7C6544")
        XCTAssertEqual(val.oAuthKeyData!.X, "d25cc473fbb448d20b5551f3c9aa121e1924b3d197353347187c47ad13ecd5d8")
        XCTAssertEqual(val.oAuthKeyData!.Y, "3394000f43160a925e6c3017dde1354ecb2b61739571c6584f58edd6b923b0f5")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x1016DA7c47A04C76036637Ea02AcF1d29c64a456")
        XCTAssertEqual(val.finalKeyData!.X, "d3e222f6b23f0436b7c86e9cc4164eb5ea8448e4c0e7539c8b4f7fd00e8ec5c7")
        XCTAssertEqual(val.finalKeyData!.Y, "1c47f5faccec6cf57c36919f6f0941fe3d8d65033cf2cc78f209304386044222")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "4f86b0e69992d1551f1b16ceb0909453dbe17b9422b030ee6c5471c2e16b65d0")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "640384f3d39debb04c4e9fe5a5ec6a1b494b0ad66d00ac9be6f166f21d116ca4")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, true)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier: String = "google-lrc"
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

        XCTAssertEqual(data.finalKeyData.evmAddress, "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6")
        XCTAssertEqual(data.oAuthKeyData.X, "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd")
        XCTAssertEqual(data.oAuthKeyData.Y, "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9")
        XCTAssertEqual(data.oAuthKeyData.privKey, "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3")
        XCTAssertEqual(data.finalKeyData.evmAddress, "0xF8d2d3cFC30949C1cb1499C9aAC8F9300535a8d6")
        XCTAssertEqual(data.finalKeyData.X, "6de2e34d488dd6a6b596524075b032a5d5eb945bcc33923ab5b88fd4fd04b5fd")
        XCTAssertEqual(data.finalKeyData.Y, "d5fb7b51b846e05362461357ec6e8ca075ea62507e2d5d7253b72b0b960927e9")
        XCTAssertEqual(data.finalKeyData.privKey, "9b0fb017db14a0a25ed51f78a258713c8ae88b5e58a43acb70b22f9e2ee138e3")
        XCTAssertNotNil(data.sessionData)
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
        let hashedIDToken = try KeyUtils.keccak256Data(jwt)
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let verifierParams = VerifierParams(verifier_id: verifierID,
                                            sub_verifier_ids: [TORUS_TEST_VERIFIER],
                                            verify_params: [VerifyParams(verifier_id: verifierID, idtoken: jwt)])
        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: hashedIDToken))

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x938a40E155d118BD31E439A9d92D67bd55317965")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x938a40E155d118BD31E439A9d92D67bd55317965")
        XCTAssertEqual(data.oAuthKeyData.X, "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95")
        XCTAssertEqual(data.oAuthKeyData.Y, "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6")
        XCTAssertEqual(data.oAuthKeyData.privKey, "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1")
        XCTAssertEqual(data.finalKeyData.evmAddress, "0x938a40E155d118BD31E439A9d92D67bd55317965")
        XCTAssertEqual(data.finalKeyData.X, "1c50e34ef5b7afcf5b0c6501a6ae00ec3a09a321dd885c5073dd122e2a251b95")
        XCTAssertEqual(data.finalKeyData.Y, "2cc74beb28f2c4a7c4034f80836d51b2781b36fefbeafb4eb1cd055bdf73b1e6")
        XCTAssertEqual(data.finalKeyData.privKey, "3cbfa57d702327ec1af505adc88ad577804a1a7780bc013ed9e714c547fb5cb1")
        XCTAssertNotNil(data.sessionData)
        XCTAssertNil(data.metadata.pubNonce)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.typeOfUser, .v1)
        XCTAssertNil(data.metadata.upgraded)
        XCTAssertNotNil(data.nodesData)
    }
}
