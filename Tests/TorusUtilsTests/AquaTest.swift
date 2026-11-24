import BigInt
import FetchNodeDetails
import JWTKit
import TorusUtils
import XCTest

class AquaTest: XCTestCase {
    var TORUS_TEST_EMAIL = "hello@tor.us"
    var TORUS_TEST_VERIFIER = "torus-test-health"
    var TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate"
    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .AQUA)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .AQUA))
    }

    func test_should_fetch_public_address() async throws {
        let verifier: String = "tkey-google-aqua"
        let verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xDfA967285AC699A70DA340F60d00DB19A272639d")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xDfA967285AC699A70DA340F60d00DB19A272639d")
        XCTAssertEqual(val.oAuthKeyData!.X, "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d")
        XCTAssertEqual(val.oAuthKeyData!.Y, "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c")

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xDfA967285AC699A70DA340F60d00DB19A272639d")
        XCTAssertEqual(val.finalKeyData!.X, "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d")
        XCTAssertEqual(val.finalKeyData!.Y, "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c")
        XCTAssertNil(val.metadata?.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v1)
    }

    func test_should_fetch_user_type_and_public_addresses() async throws {
        var verifier: String = "tkey-google-aqua"
        var verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let result1 = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)
        XCTAssertLessThan(result1.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(result1.oAuthKeyData!.evmAddress, "0xDfA967285AC699A70DA340F60d00DB19A272639d")
        XCTAssertEqual(result1.oAuthKeyData!.X, "4fc8db5d3fe164a3ab70fd6348721f2be848df2cc02fd2db316a154855a7aa7d")
        XCTAssertEqual(result1.oAuthKeyData!.Y, "f76933cbf5fe2916681075bb6cb4cde7d5f6b6ce290071b1b7106747d906457c")
        XCTAssertEqual(result1.finalKeyData!.evmAddress, "0x79F06350eF34Aeed4BE68e26954D405D573f1438")
        XCTAssertEqual(result1.finalKeyData!.X, "99df45abc8e6ee03d2f94df33be79e939eadfbed20c6b88492782fdc3ef1dfd3")
        XCTAssertEqual(result1.finalKeyData!.Y, "12bf3e54599a177fdb88f8b22419df7ddf1622e1d2344301edbe090890a72b16")
        XCTAssertEqual(result1.metadata!.pubNonce!.x, "dc5a031fd2e0b55dbaece314ea125bac9da5f0a916bf156ff36b5ad71380ea32")
        XCTAssertEqual(result1.metadata!.pubNonce!.y, "affd749b98c209d2f9cf4dacb145d7897f82f1e2924a47b07874302ecc0b8ef1")
        XCTAssertEqual(result1.metadata?.nonce, 0)
        XCTAssertEqual(result1.metadata?.upgraded, false)
        XCTAssertEqual(result1.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(result1.nodesData)

        // 1/1 user
        verifier = "tkey-google-aqua"
        verifierID = "somev2user@gmail.com"
        let result2 = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertLessThan(result2.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(result2.oAuthKeyData!.evmAddress, "0x4ea5260fF85678A2a326D08DF9C44d1f559a5828")
        XCTAssertEqual(result2.oAuthKeyData!.X, "0e6febe33a9d4eeb680cc6b63ff6237ad1971f27adcd7f104a3b1de18eda9337")
        XCTAssertEqual(result2.oAuthKeyData!.Y, "a5a915561f3543688e71281a850b9ee10b9690f305d9e79028dfc8359192b82d")
        XCTAssertEqual(result2.finalKeyData!.evmAddress, "0xBc32f315515AdE7010cabC5Fd68c966657A570BD")
        XCTAssertEqual(result2.finalKeyData!.X, "4897f120584ee18a72b9a6bb92c3ef6e45fc5fdff70beae7dc9325bd01332022")
        XCTAssertEqual(result2.finalKeyData!.Y, "2066dbef2fcdded4573e3c04d1c04edd5d44662168e636ed9d0b0cbe2e67c968")
        XCTAssertEqual(result2.finalKeyData!.evmAddress, "0xBc32f315515AdE7010cabC5Fd68c966657A570BD")
        XCTAssertEqual(result2.metadata?.pubNonce?.x, "1601cf4dc4362b219260663d5ec5119699fbca185d08b7acb2e36cad914340d5")
        XCTAssertEqual(result2.metadata?.pubNonce?.y, "c2f7871f61ee71b4486ac9fb40ec759099800e737139dc5dfaaaed8c9d77c3c1")
        XCTAssertEqual(result2.metadata?.nonce, BigUInt(0))
        XCTAssertEqual(result2.metadata?.upgraded, false)
        XCTAssertEqual(result2.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(result2.nodesData)

        // 2/n user
        verifierID = "caspertorus@gmail.com"
        let result3 = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertLessThan(result2.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(result3.oAuthKeyData!.evmAddress, "0x4ce0D09C3989eb3cC9372cC27fa022D721D737dD")
        XCTAssertEqual(result3.oAuthKeyData!.X, "e76d2f7fa2c0df324b4ab74629c3af47aa4609c35f1d2b6b90b77a47ab9a1281")
        XCTAssertEqual(result3.oAuthKeyData!.Y, "b33b35148d72d357070f66372e07fec436001bdb15c098276b120b9ed64c1e5f")
        XCTAssertEqual(result3.finalKeyData!.evmAddress, "0x5469C5aCB0F30929226AfF4622918DA8E1424a8D")
        XCTAssertEqual(result3.finalKeyData!.X, "c20fac685bb67169e92f1d5d8894d4eea18753c0ef3b7b1b2224233b2dfa3539")
        XCTAssertEqual(result3.finalKeyData!.Y, "c4f080b5c8d5c55c8eaba4bec70f668f36db4126f358b491d631fefea7c19d21")
        XCTAssertEqual(result3.metadata?.pubNonce?.x, "17b1ebce1fa874452a96d0c6d74c1445b78f16957c7decc5d2a202b0ce4662f5")
        XCTAssertEqual(result3.metadata?.pubNonce?.y, "b5432cb593753e1b3ecf98b05dc03e57bc02c415e1b80a1ffc5a401ec1f0abd6")
        XCTAssertEqual(result3.metadata?.nonce, 0)
        XCTAssertEqual(result3.metadata?.upgraded, false)
        XCTAssertEqual(result3.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(result3.nodesData)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier: String = "tkey-google-aqua"
        let verifierID: String = fakeEmail
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let data = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertNotNil(data.finalKeyData?.evmAddress)
        XCTAssertNotNil(data.oAuthKeyData?.evmAddress)
        XCTAssertEqual(data.metadata?.typeOfUser, .v1)
        XCTAssertEqual(data.metadata?.upgraded, false)
        XCTAssertNotNil(data.nodesData)
    }

    func test_should_be_able_to_login() async throws {
        let verifier: String = TORUS_TEST_VERIFIER
        let verifierID: String = TORUS_TEST_EMAIL
        let verifierParams = VerifierParams(verifier_id: verifierID)
        let jwt = try! generateIdToken(email: verifierID)
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: jwt))

        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195")
        XCTAssertEqual(data.finalKeyData.X, "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664")
        XCTAssertEqual(data.finalKeyData.Y, "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f")
        XCTAssertEqual(data.finalKeyData.privKey, "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d")
        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x9EBE51e49d8e201b40cAA4405f5E0B86d9D27195")
        XCTAssertEqual(data.oAuthKeyData.X, "c7bcc239f0957bb05bda94757eb4a5f648339424b22435da5cf7a0f2b2323664")
        XCTAssertEqual(data.oAuthKeyData.Y, "63795690a33e575ee12d832935d563c2b5f2e1b1ffac63c32a4674152f68cb3f")
        XCTAssertEqual(data.oAuthKeyData.privKey, "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d")
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

        let verifierParams = VerifierParams(verifier_id: verifierID, sub_verifier_ids: [TORUS_TEST_VERIFIER], verify_params: [VerifyParams(verifier_id: TORUS_TEST_EMAIL, idtoken: jwt)])

        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: hashedIDToken))
        XCTAssertEqual(data.finalKeyData.evmAddress, "0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D")
        XCTAssertEqual(data.finalKeyData.X, "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d")
        XCTAssertEqual(data.finalKeyData.Y, "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10")
        XCTAssertEqual(data.finalKeyData.privKey, "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355")
        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x5b58d8a16fDA79172cd42Dc3068d5CEf26a5C81D")
        XCTAssertEqual(data.oAuthKeyData.X, "37a4ac8cbef68e88bcec5909d9b6fffb539187365bb723f3d7bffe56ae80e31d")
        XCTAssertEqual(data.oAuthKeyData.Y, "f963f2d08ed4dd0da9b8a8d74c6fdaeef7bdcde31f84fcce19fa2173d40b2c10")
        XCTAssertEqual(data.oAuthKeyData.privKey, "488d39ac548e15cfb0eaf161d86496e1645b09437df21311e24a56c4efd76355")
        XCTAssertNil(data.metadata.pubNonce)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.typeOfUser, .v1)
        XCTAssertNil(data.metadata.upgraded)
        XCTAssertNotNil(data.nodesData)
    }

    func test_retrieveShares_some_nodes_down() async throws {
        let verifier: String = TORUS_TEST_VERIFIER
        let verifierID: String = TORUS_TEST_EMAIL
        let verifierParams = VerifierParams(verifier_id: verifierID)
        let jwt = try! generateIdToken(email: verifierID)
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        var endpoints = nodeDetails.getTorusNodeEndpoints()
        endpoints[endpoints.count - 1] = "https://ndjnfjbfrj/random"
        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: endpoints, indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: jwt))
        XCTAssertEqual(data.finalKeyData.privKey, "f726ce4ac79ae4475d72633c94769a8817aff35eebe2d4790aed7b5d8a84aa1d")
    }
}
