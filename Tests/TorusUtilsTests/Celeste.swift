import BigInt
import FetchNodeDetails
import Foundation
import TorusUtils
import XCTest

class CelesteTest: XCTestCase {
    var TORUS_TEST_EMAIL = "hello@tor.us"
    var TORUS_TEST_VERIFIER = "torus-test-health"
    var TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate"
    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .CELESTE)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .CELESTE))
    }

    func test_should_fetch_public_address() async throws {
        let verifier = "tkey-google-celeste"
        let verifierID = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113")
        XCTAssertEqual(val.finalKeyData!.X, "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9")
        XCTAssertEqual(val.finalKeyData!.Y, "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb")
        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113")
        XCTAssertEqual(val.oAuthKeyData!.X, "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9")
        XCTAssertEqual(val.oAuthKeyData!.Y, "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb")
        XCTAssertNil(val.metadata?.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v1)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_fetch_user_type_and_public_address() async throws {
        var verifier: String = "tkey-google-celeste"
        var verifierID: String = TORUS_TEST_EMAIL
        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)
        var val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xC3115b9d6FaB99739b23DA9dfcBA47A4Ec4Cd113")
        XCTAssertEqual(val.oAuthKeyData!.X, "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9")
        XCTAssertEqual(val.oAuthKeyData!.Y, "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb")
        XCTAssertEqual(val.finalKeyData!.X, "b89b9d66b247d7294a98616b95b7bfa1675aa85a1df4d89f2780283864f1b6e9")
        XCTAssertEqual(val.finalKeyData!.Y, "65422a8ccd66e638899fc53497e468a9a0bf50d45c9cb85ae0ffcfc13f433ffb")
        XCTAssertNil(val.metadata!.pubNonce)
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v1)

        verifier = "tkey-google-celeste"
        verifierID = "somev2user@gmail.com"
        val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x8d69CE354DA39413f205FdC8680dE1F3FBBb36e2")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xda4afB35493094Dd2C05b186Ca0FABAD96491B21")
        XCTAssertEqual(val.oAuthKeyData!.X, "cfa646a2949ebe559205c5c407d734d1b6927f2ea5fbeabfcbc31ab9a985a336")
        XCTAssertEqual(val.oAuthKeyData!.Y, "8f988eb8b59515293820aa38af172b153e8d25307db8d5f410407c20e062b6e6")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x8d69CE354DA39413f205FdC8680dE1F3FBBb36e2")
        XCTAssertEqual(val.finalKeyData!.X, "5962144e03b993b0e503eb4e6e0196427f9fc9472f0dfd1be2ca5d4939f91680")
        XCTAssertEqual(val.finalKeyData!.Y, "f6e81f01f483110badab18371237d15834f9ecf31c3588c165dae32ec446ac38")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "2f630074151394ba1f715986a9215f4e36c9f22fc264ff880ef6d162c1300aa8")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "704cb63e5f7a291735c54e22242ef53673642ec1660da00f1abc2e7909da03d7")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "2f630074151394ba1f715986a9215f4e36c9f22fc264ff880ef6d162c1300aa8")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "704cb63e5f7a291735c54e22242ef53673642ec1660da00f1abc2e7909da03d7")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)

        verifier = "tkey-google-celeste"
        verifierID = "caspertorus@gmail.com"
        val = try await torus.getUserTypeAndAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x8108c29976C458e76f797AD55A3715Ce80a3fe78")
        XCTAssertLessThan(val.metadata!.serverTimeOffset, 20)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xc8c4748ec135196fb482C761da273C31Ec48B099")
        XCTAssertEqual(val.oAuthKeyData!.X, "0cc857201e6c304dd893b243e323fe95982e5a99c0994cf902efa2432a672eb4")
        XCTAssertEqual(val.oAuthKeyData!.Y, "37a2f53c250b3e1186e38ece3dfcbcb23e325913038703531831b96d3e7b54cc")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x8108c29976C458e76f797AD55A3715Ce80a3fe78")
        XCTAssertEqual(val.finalKeyData!.X, "e95fe2d595ade03f56d9c9a147fbb67705041704f147576fa4a8afbe7dc69470")
        XCTAssertEqual(val.finalKeyData!.Y, "3e20e4b331466769c4dd78f4561bfb2849010b4005b09c2ed082380326724ebe")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "f8ff2c44cc0abf512d35b35c3c5cbc0eda700d49bc13b72c5492b0cdb2ca3619")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "88fb3087cec269c8c39d25b04f15298d33712f13b0f9665821328dfc7a567afb")
        XCTAssertEqual(val.metadata?.nonce, 0)
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier: String = "tkey-google-celeste"
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

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x58420FB83971C4490D8c9B091f8bfC890D716617")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x58420FB83971C4490D8c9B091f8bfC890D716617")
        XCTAssertEqual(data.oAuthKeyData.X, "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74")
        XCTAssertEqual(data.oAuthKeyData.Y, "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1")
        XCTAssertEqual(data.oAuthKeyData.privKey, "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914")
        XCTAssertEqual(data.finalKeyData.evmAddress, "0x58420FB83971C4490D8c9B091f8bfC890D716617")
        XCTAssertEqual(data.finalKeyData.X, "73b82ce0f8201a962636d404fe7a683f37c2267a9528576e1dac9964940add74")
        XCTAssertEqual(data.finalKeyData.Y, "6d28c46c5385b90322bde74d6c5096e154eae2838399f4d6e8d752f7b0c449c1")
        XCTAssertEqual(data.finalKeyData.privKey, "0ae056aa938080c9e8bf6641261619e09fd510c91bb5aad14b0de9742085a914")
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

        XCTAssertEqual(data.finalKeyData.evmAddress, "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564")
        XCTAssertLessThan(data.metadata.serverTimeOffset, 20)

        XCTAssertEqual(data.oAuthKeyData.evmAddress, "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564")
        XCTAssertEqual(data.oAuthKeyData.X, "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca")
        XCTAssertEqual(data.oAuthKeyData.Y, "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb")
        XCTAssertEqual(data.oAuthKeyData.privKey, "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e")
        XCTAssertEqual(data.finalKeyData.evmAddress, "0x535Eb1AefFAc6f699A2a1A5846482d7b5b2BD564")
        XCTAssertEqual(data.finalKeyData.X, "df6eb11d52e76b388a44896e9442eda17096c2b67b0be957a4ba0b68a70111ca")
        XCTAssertEqual(data.finalKeyData.Y, "bfd29ab1e97b3f7c444bb3e7ad0acb39d72589371387436c7d623d1e83f3d6eb")
        XCTAssertEqual(data.finalKeyData.privKey, "356305761eca57f27b09700d76456ad627b084152725dbfdfcfa0abcd9d4f17e")
        XCTAssertNotNil(data.sessionData)
        XCTAssertNil(data.metadata.pubNonce)
        XCTAssertEqual(data.metadata.nonce, BigUInt(0))
        XCTAssertEqual(data.metadata.typeOfUser, .v1)
        XCTAssertNil(data.metadata.upgraded)
        XCTAssertNotNil(data.nodesData)
    }
}
