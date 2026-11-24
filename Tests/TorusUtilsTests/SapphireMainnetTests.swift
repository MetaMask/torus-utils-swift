import BigInt
import curveSecp256k1
import FetchNodeDetails
import JWTKit
import TorusUtils
import XCTest

class SapphireMainnetTests: XCTestCase {
    static var fetchNodeDetails: AllNodeDetailsModel?
    static var utils: TorusUtils?
    static var endpoints: [String] = []
    static var nodePubKeys: [TorusNodePubModel] = []
    static var privKey: String = ""

    let TORUS_TEST_EMAIL = "hello@tor.us"
    let TORUS_TEST_VERIFIER = "torus-test-health"
    let TORUS_TEST_AGGREGATE_VERIFIER = "torus-aggregate-sapphire-mainnet"
    let HASH_ENABLED_VERIFIER = "torus-test-verifierid-hash"
    let TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com"

    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .SAPPHIRE_MAINNET)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .SAPPHIRE_MAINNET, enableOneKey: true))
    }

    func test_should_fetch_public_address() async throws {
        let verifier = "tkey-google-sapphire-mainnet"
        let verifierID = TORUS_TEST_EMAIL

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xb1a49C6E50a1fC961259a8c388EAf5953FA5152b")
        XCTAssertEqual(val.oAuthKeyData!.X, "a9f5a463aefb16e90f4cbb9de4a5b6b7f6c6a3831cefa0f20cccb9e7c7b01c20")
        XCTAssertEqual(val.oAuthKeyData!.Y, "3376c6734da57ab3a67c7792eeea20707d16992dd2c827a59499f4c056b00d08")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x327b2742768B436d09153429E762FADB54413Ded")
        XCTAssertEqual(val.finalKeyData!.X, "1567e030ca76e520c180c50bc6baed07554ebc35c3132495451173e9310d8be5")
        XCTAssertEqual(val.finalKeyData!.Y, "123c0560757ffe6498bf2344165d0f295ea74eb8884683675e5f17ae7bb41cdb")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "56e803db7710adbfe0ecca35bc6a3ad27e966df142e157e76e492773c88e8433")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "f4168594c1126ca731756dd480f992ee73b0834ba4b787dd892a9211165f50a3")
        XCTAssertEqual(val.metadata?.nonce, BigUInt(0))
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier = "tkey-google-sapphire-mainnet"
        let verifierID = fakeEmail

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let data = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertNotEqual(data.finalKeyData?.evmAddress, "")
        XCTAssertNotEqual(data.oAuthKeyData?.evmAddress, "")
        XCTAssertEqual(data.metadata?.typeOfUser, .v2)
        XCTAssertEqual(data.metadata?.upgraded, false)
    }

    func test_should_be_able_to_key_assign_to_tss_verifier_id() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let nonce = 0
        let tssTag = "default"
        let tssVerifierID: String = fakeEmail + "\u{0015}" + tssTag + "\u{0016}" + String(nonce)
        let verifier = "tkey-google-sapphire-mainnet"
        let verifierID = fakeEmail

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let data = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: verifier, verifierId: verifierID, extendedVerifierId: tssVerifierID)

        XCTAssertNotEqual(data.finalKeyData?.evmAddress, "")
        XCTAssertNotEqual(data.oAuthKeyData?.evmAddress, "")
        XCTAssertEqual(data.metadata?.typeOfUser, .v2)
        XCTAssertEqual(data.metadata?.upgraded, false)
    }

    func test_should_fetch_public_address_of_tss_verifier_id() async throws {
        let email = TORUS_EXTENDED_VERIFIER_EMAIL
        let nonce = 0
        let tssTag = "default"
        let tssVerifierID: String = email + "\u{0015}" + tssTag + "\u{0016}" + String(nonce)
        let verifier = TORUS_TEST_VERIFIER
        let verifierID = email

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: verifier, verifierId: verifierID, extendedVerifierId: tssVerifierID)

        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A")
        XCTAssertEqual(val.oAuthKeyData!.X, "a772c71ca6c650506f26a180456a6bdf462996781a10f1740f4e65314f360f29")
        XCTAssertEqual(val.oAuthKeyData!.Y, "776c2178ff4620c67197b2f26b1222503919ff26a7cbd0fdbc91a2c9764e56cb")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x98EC5b049c5C0Dc818C69e95CF43534AEB80261A")
        XCTAssertEqual(val.finalKeyData!.X, "a772c71ca6c650506f26a180456a6bdf462996781a10f1740f4e65314f360f29")
        XCTAssertEqual(val.finalKeyData!.Y, "776c2178ff4620c67197b2f26b1222503919ff26a7cbd0fdbc91a2c9764e56cb")
        XCTAssertNil(val.metadata?.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, BigUInt(0))
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_allow_test_tss_verifier_to_fetch_shares() async throws {
        let email = generateRandomEmail(of: 6)
        let nonce = 0
        let tssTag = "default"
        let tssVerifierID: String = email + "\u{0015}" + tssTag + "\u{0016}" + String(nonce)
        let verifier = TORUS_TEST_VERIFIER
        let verifierID = email
        let token = try generateIdToken(email: email)

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let verifierParams = VerifierParams(verifier_id: verifierID, extended_verifier_id: tssVerifierID)
        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: token))

        XCTAssertNotNil(data.finalKeyData.privKey)
        XCTAssertNotNil(data.oAuthKeyData.evmAddress)
        XCTAssertEqual(data.metadata.typeOfUser, .v2)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.upgraded, true)
    }

    func test_should_fetch_public_address_when_verifier_is_hash_enabled() async throws {
        let verifier = HASH_ENABLED_VERIFIER
        let verifierID = TORUS_TEST_EMAIL

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC")
        XCTAssertEqual(val.oAuthKeyData!.X, "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8")
        XCTAssertEqual(val.oAuthKeyData!.Y, "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB")
        XCTAssertEqual(val.finalKeyData!.X, "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8")
        XCTAssertEqual(val.finalKeyData!.Y, "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f")
        XCTAssertEqual(val.metadata?.nonce, BigUInt(0))
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_fetch_user_type_and_public_address_when_verifier_is_hash_enabled() async throws {
        // duplicated test
        let verifier = HASH_ENABLED_VERIFIER
        let verifierID = TORUS_TEST_EMAIL

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC")
        XCTAssertEqual(val.oAuthKeyData!.X, "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8")
        XCTAssertEqual(val.oAuthKeyData!.Y, "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB")
        XCTAssertEqual(val.finalKeyData!.X, "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8")
        XCTAssertEqual(val.finalKeyData!.Y, "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f")
        XCTAssertEqual(val.metadata?.nonce, BigUInt(0))
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_login_when_verifier_is_hash_enabled() async throws {
        let verifier = HASH_ENABLED_VERIFIER
        let verifierID = TORUS_TEST_EMAIL
        let jwt = try generateIdToken(email: verifierID)

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let verifierParams = VerifierParams(verifier_id: verifierID)

        let val = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: jwt))

        XCTAssertLessThan(val.metadata.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData.evmAddress, "0xCb76F4C8cbAe524997787B57efeeD99f6D3BD5AB")
        XCTAssertEqual(val.finalKeyData.X, "b943bfdc29c515195270d3a219da6a57bcaf6e58e57d03e2accb8c716e6949c8")
        XCTAssertEqual(val.finalKeyData.Y, "a0fe9ac87310d302a821f89a747d80c9b7dc5cbd0956571f84b09e58d11eee90")
        XCTAssertEqual(val.finalKeyData.privKey, "13941ecd812b08d8a33a20bc975f0cd1c3f82de25b20c0c863ba5f21580b65f6")
        XCTAssertEqual(val.oAuthKeyData.evmAddress, "0xeBe48BE7693a36Ff562D18c4494AC4496A45EaaC")
        XCTAssertEqual(val.oAuthKeyData.X, "147d0a97d498ac17172dd92546617e06f2c32c405d414dfc06632b8fbcba93d8")
        XCTAssertEqual(val.oAuthKeyData.Y, "cc6e57662c3866c4316c05b0fe902db9aaf5541fbf5fda854c3b4634eceeb43c")
        XCTAssertEqual(val.oAuthKeyData.privKey, "d768b327cbde681e5850a7d14f1c724bba2b8f8ab7fe2b1c4f1ee6979fc25478")
        XCTAssertEqual(val.metadata.pubNonce!.x, "498ed301af25a3b7136f478fa58677c79a6d6fe965bc13002a6f459b896313bd")
        XCTAssertEqual(val.metadata.pubNonce!.y, "d6feb9a1e0d6d0627fbb1ce75682bc09ab4cf0e2da4f0f7fcac0ba9d07596c8f")
        XCTAssertEqual(val.metadata.nonce, BigUInt("3c2b6ba5b54ca0ba4ae978eb48429a84c47b7b3e526b35e7d46dd716887f52bf", radix: 16))
        XCTAssertEqual(val.metadata.upgraded, false)
        XCTAssertEqual(val.metadata.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_login() async throws {
        let verifier = TORUS_TEST_VERIFIER
        let verifierID = TORUS_TEST_EMAIL
        let jwt = try generateIdToken(email: verifierID)

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let verifierParams = VerifierParams(verifier_id: verifierID)

        let val = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: jwt))

        XCTAssertLessThan(val.metadata.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData.evmAddress, "0x70520A7F04868ACad901683699Fa32765C9F6871")
        XCTAssertEqual(val.finalKeyData.X, "adff099b5d3b1e238b43fba1643cfa486e8d9e8de22c1e6731d06a5303f9025b")
        XCTAssertEqual(val.finalKeyData.Y, "21060328e7889afd303acb63201b6493e3061057d1d81279931ab4a6cabf94d4")
        XCTAssertEqual(val.finalKeyData.privKey, "dfb39b84e0c64b8c44605151bf8670ae6eda232056265434729b6a8a50fa3419")
        XCTAssertEqual(val.oAuthKeyData.evmAddress, "0x925c97404F1aBdf4A8085B93edC7B9F0CEB3C673")
        XCTAssertEqual(val.oAuthKeyData.X, "5cd8625fc01c7f7863a58c914a8c43b2833b3d0d5059350bab4acf6f4766a33d")
        XCTAssertEqual(val.oAuthKeyData.Y, "198a4989615c5c2c7fa4d49c076ea7765743d09816bb998acb9ff54f5db4a391")
        XCTAssertEqual(val.oAuthKeyData.privKey, "90a219ac78273e82e36eaa57c15f9070195e436644319d6b9aea422bb4d31906")
        XCTAssertEqual(val.metadata.pubNonce!.x, "ab4d287c263ab1bb83c37646d0279764e50fe4b0c34de4da113657866ddcf318")
        XCTAssertEqual(val.metadata.pubNonce!.y, "ad35db2679dfad4b62d77cf753d7b98f73c902e5d101cc2c3c1209ece6d94382")
        XCTAssertEqual(val.metadata.nonce, BigUInt("4f1181d8689f0d0960f1a6f9fe26e03e557bdfba11f4b6c8d7b1285e9c271b13", radix: 16))
        XCTAssertEqual(val.metadata.upgraded, false)
        XCTAssertEqual(val.metadata.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_aggregate_login() async throws {
        let email: String = generateRandomEmail(of: 6)
        let jwt = try! generateIdToken(email: email)
        let hashedIDToken = try KeyUtils.keccak256Data(jwt)
        let verifierParams = VerifierParams(verifier_id: email, sub_verifier_ids: [TORUS_TEST_VERIFIER], verify_params: [VerifyParams(verifier_id: email, idtoken: jwt)])

        let nodeDetails = try await fnd.getNodeDetails(verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierID: email)

        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierParams: verifierParams, idToken: hashedIDToken))

        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)
        XCTAssertNotNil(data.finalKeyData.privKey)
        XCTAssertNotNil(data.oAuthKeyData.evmAddress)
        XCTAssertEqual(data.metadata.typeOfUser, .v2)
    }

    func test_should_be_able_to_update_sessiontime_of_the_token_signature_data() async throws {
        let verifier: String = TORUS_TEST_VERIFIER
        let verifierID: String = TORUS_TEST_EMAIL
        let jwt = try! generateIdToken(email: verifierID)

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let verifierParams = VerifierParams(verifier_id: verifierID)

        let customSessionTime = Int(3600)
        torus.setSessionTime(sessionTime: customSessionTime)

        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: jwt))

        let signatures = data.sessionData.sessionTokenData.map({ $0!.token })
        let parsedSignatures = signatures.map({
            let data = Data(base64Encoded: $0.data(using: .utf8)!)!
            let json = String(data: data, encoding: .utf8)!
            return json
        })
        let now = Int(Date().timeIntervalSince1970)
        for item in parsedSignatures {
            let json = try JSONSerialization.jsonObject(with: item.data(using: .utf8)!) as? [String: Any]
            let exp = json!["exp"] as! Int
            let sessionTime = exp - now
            XCTAssertGreaterThanOrEqual(sessionTime, customSessionTime - 30)
            XCTAssertLessThanOrEqual(sessionTime, customSessionTime + 30)
        }
    }
}
