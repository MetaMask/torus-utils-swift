import BigInt
import FetchNodeDetails
import JWTKit
import TorusUtils
import XCTest

class MainnetTests: XCTestCase {
    static var fetchNodeDetails: AllNodeDetailsModel?
    static var utils: TorusUtils?
    static var endpoints: [String] = []
    static var nodePubKeys: [TorusNodePubModel] = []
    static var privKey: String = ""

    let TORUS_TEST_VERIFIER = "torus-test-health"
    let TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate"
    let TORUS_TEST_EMAIL = "hello@tor.us"

    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .MAINNET)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .MAINNET))
    }

    func test_should_fetch_public_address() async throws {
        let verifier = "google"
        let verifierID = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A")
        XCTAssertEqual(val.finalKeyData!.X, "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4")
        XCTAssertEqual(val.finalKeyData!.Y, "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1")
        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A")
        XCTAssertEqual(val.oAuthKeyData!.X, "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4")
        XCTAssertEqual(val.oAuthKeyData!.Y, "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1")
        XCTAssertNil(val.metadata?.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v1)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_fetch_user_type_and_public_address() async throws {
        var verifier: String = "google"
        var verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        var val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xb2e1c3119f8D8E73de7eaF7A535FB39A3Ae98C5E")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xb2e1c3119f8D8E73de7eaF7A535FB39A3Ae98C5E")

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x0C44AFBb5395a9e8d28DF18e1326aa0F16b9572A")
        XCTAssertEqual(val.oAuthKeyData!.X, "3b5655d78978b6fd132562b5cb66b11bcd868bd2a9e16babe4a1ca50178e57d4")
        XCTAssertEqual(val.oAuthKeyData!.Y, "15338510798d6b55db28c121d86babcce19eb9f1882f05fae8ee9b52ed09e8f1")
        XCTAssertEqual(val.finalKeyData!.X, "072beda348a832aed06044a258cb6a8d428ec7c245c5da92db5da4f3ab433e55")
        XCTAssertEqual(val.finalKeyData!.Y, "54ace0d3df2504fa29f17d424a36a0f92703899fad0afee93d010f6d84b310e5")
        XCTAssertEqual(val.metadata!.pubNonce!.x, "eb22d93244acf7fcbeb6566da722bc9c8e5433cd28da25ca0650d9cb32806c39")
        XCTAssertEqual(val.metadata!.pubNonce!.y, "765541e214f067cfc44dcf41e582ae09b71c2e607a301cc8a45e1f316a6ba91c")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)

        verifier = "tkey-google"
        verifierID = "somev2user@gmail.com"
        val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xA9c6829e4899b6D630130ebf59D046CA868D7f83")
        XCTAssertEqual(val.oAuthKeyData!.X, "5566cd940ea540ba1a3ba2ff0f5fd3d9a3a74350ac3baf47b811592ae6ea1c30")
        XCTAssertEqual(val.oAuthKeyData!.Y, "07a302e87e8d9eb5d143f570c248657288c13c09ecbe1e3a8720449daf9315b0")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xFf669A15bFFcf32D3C5B40bE9E5d409d60D43526")
        XCTAssertEqual(val.finalKeyData!.X, "bbfd26b1e61572c4e991a21b64f12b313cb6fce6b443be92d4d5fd8f311e8f33")
        XCTAssertEqual(val.finalKeyData!.Y, "df2c905356ec94faaa111a886be56ed6fa215b7facc1d1598486558355123c25")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "96f4b7d3c8c8c69cabdea46ae1eedda346b03cad8ba1a454871b0ec6a69861f3")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "da3aed7f7e9d612052beb1d92ec68a8dcf60faf356985435b424af2423f66672")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)

        verifier = "tkey-google"
        verifierID = "caspertorus@gmail.com"
        val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x40A4A04fDa1f29a3667152C8830112FBd6A77BDD")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x61E52B6e488EC3dD6FDc0F5ed04a62Bb9c6BeF53")
        XCTAssertEqual(val.oAuthKeyData!.X, "c01282dd68d2341031a1cff06f70d821cad45140f425f1c25055a8aa64959df8")
        XCTAssertEqual(val.oAuthKeyData!.Y, "cb3937773bb819d60b780b6d4c2edcf27c0f7090ba1fc2ff42504a8138a8e2d7")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x40A4A04fDa1f29a3667152C8830112FBd6A77BDD")
        XCTAssertEqual(val.finalKeyData!.X, "6779af3031d9e9eec6b4133b0ae13e367c83a614f92d2008e10c7f3b8e6723bc")
        XCTAssertEqual(val.finalKeyData!.Y, "80edc4502abdfb220dd6e2fcfa2dbb058125dc95873e4bfa6877f9c26da7fdff")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "16214bf232167258fb5f98fa9d84968ffec3236aaf0994fc366940c4bc07a5b1")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "475e8c09d2cc8f6c12a767f51c052b1bf8e8d3a2a2b6818d4b199dc283e80ac4")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier: String = "google"
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

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x90A926b698047b4A87265ba1E9D8b512E8489067")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x90A926b698047b4A87265ba1E9D8b512E8489067")
        XCTAssertEqual(data.oAuthKeyData.X, "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f")
        XCTAssertEqual(data.oAuthKeyData.Y, "0ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1")
        XCTAssertEqual(data.oAuthKeyData.privKey, "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44")
        XCTAssertEqual(data.finalKeyData.evmAddress, "0x90A926b698047b4A87265ba1E9D8b512E8489067")
        XCTAssertEqual(data.finalKeyData.X, "a92d8bf1f01ad62e189a5cb0f606b89aa6df1b867128438c38e3209f3b9fc34f")
        XCTAssertEqual(data.finalKeyData.Y, "0ad1ffaecb2178b02a37c455975368be9b967ead1b281202cc8d48c77618bff1")
        XCTAssertEqual(data.finalKeyData.privKey, "0129494416ab5d5f674692b39fa49680e07d3aac01b9683ee7650e40805d4c44")
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

        let verifierParams = VerifierParams(verifier_id: verifierID, sub_verifier_ids: [TORUS_TEST_VERIFIER], verify_params: [VerifyParams(verifier_id: verifierID, idtoken: jwt)])
        let data = try await torus.retrieveShares(params: RetrieveSharesParams(endpoints: nodeDetails.getTorusNodeEndpoints(), indexes: nodeDetails.getTorusIndexes(), nodePubKeys: nodeDetails.getTorusNodePub(), verifier: verifier, verifierParams: verifierParams, idToken: hashedIDToken))

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x621a4d458cFd345dAE831D9E756F10cC40A50381")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x621a4d458cFd345dAE831D9E756F10cC40A50381")
        XCTAssertEqual(data.oAuthKeyData.X, "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236")
        XCTAssertEqual(data.oAuthKeyData.Y, "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e")
        XCTAssertEqual(data.oAuthKeyData.privKey, "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534")
        XCTAssertEqual(data.finalKeyData.evmAddress, "0x621a4d458cFd345dAE831D9E756F10cC40A50381")
        XCTAssertEqual(data.finalKeyData.X, "52abc69ebec21deacd273dbdcb4d40066b701177bba906a187676e3292e1e236")
        XCTAssertEqual(data.finalKeyData.Y, "5e57e251db2c95c874f7ec852439302a62ef9592c8c50024e3d48018a6f77c7e")
        XCTAssertEqual(data.finalKeyData.privKey, "f55d89088a0c491d797c00da5b2ed6dc9c269c960ff121e45f255d06a91c6534")
        XCTAssertNotNil(data.sessionData)
        XCTAssertNil(data.metadata.pubNonce)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.typeOfUser, .v1)
        XCTAssertNil(data.metadata.upgraded)
        XCTAssertNotNil(data.nodesData)
    }
}
