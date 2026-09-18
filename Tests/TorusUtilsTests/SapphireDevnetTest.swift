import BigInt
import curveSecp256k1
import FetchNodeDetails
import JWTKit
import TorusUtils
import XCTest

final class SapphireDevnetTest: XCTestCase {
    let TORUS_TEST_VERIFIER = "torus-test-health"
    let TORUS_TEST_AGGREGATE_VERIFIER = "torus-test-health-aggregate"

    let TORUS_TEST_EMAIL = "devnettestuser@tor.us"
    let TORUS_HASH_ENABLED_TEST_EMAIL = "saasas@tr.us"
    let TORUS_IMPORT_EMAIL = "Sydnie.Lehner73@yahoo.com"
    let TORUS_EXTENDED_VERIFIER_EMAIL = "testextenderverifierid@example.com"
    let HASH_ENABLED_VERIFIER = "torus-test-verifierid-hash"

    var fnd: NodeDetailManager!
    var torus: TorusUtils!

    override func setUp() {
        super.setUp()
        fnd = NodeDetailManager(network: .SAPPHIRE_DEVNET)
        torus = try! TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .SAPPHIRE_DEVNET))
    }

    func test_should_fetch_ed25519_public_address() async throws {
        let verifierID = "Willa_Funk11@gmail.com"
        let nodeDetails = try await fnd.getNodeDetails(verifier: TORUS_TEST_VERIFIER, verifierID: verifierID)
        let ed25519Torus = try TorusUtils(params: TorusOptions(
            clientId: "YOUR_CLIENT_ID",
            network: .SAPPHIRE_DEVNET,
            enableOneKey: true,
            keyType: .ed25519
        ))

        let result = try await ed25519Torus.getPublicAddress(
            endpoints: nodeDetails.getTorusNodeSSSEndpoints(),
            verifier: TORUS_TEST_VERIFIER,
            verifierId: verifierID
        )

        XCTAssertEqual(result.finalKeyData?.evmAddress, "HHmiJMCAwhyf9ZWNtj7FEKGXeeC2NjUjPobpDKm43yKs")
        XCTAssertEqual(result.oAuthKeyData?.evmAddress, "49yLu8yLqpuCXchzjQSt1tpBz8AP2E9EzzP7a8QtxmTE")
    }

    func test_should_retrieve_ed25519_shares() async throws {
        let verifierID = "edd2519TestUser951@example.com"
        let nodeDetails = try await fnd.getNodeDetails(verifier: TORUS_TEST_VERIFIER, verifierID: verifierID)
        let token = try generateIdToken(email: verifierID)
        let ed25519Torus = try TorusUtils(params: TorusOptions(
            clientId: "YOUR_CLIENT_ID",
            network: .SAPPHIRE_DEVNET,
            enableOneKey: true,
            keyType: .ed25519
        ))
        let result = try await ed25519Torus.retrieveShares(params: RetrieveSharesParams(
            endpoints: nodeDetails.getTorusNodeSSSEndpoints(),
            indexes: nodeDetails.getTorusIndexes(),
            nodePubKeys: nodeDetails.getTorusNodePub(),
            verifier: TORUS_TEST_VERIFIER,
            verifierParams: VerifierParams(verifier_id: verifierID),
            idToken: token
        ))

        XCTAssertEqual(result.finalKeyData.evmAddress, "6jNaYT5c1EgYaASeBte79hSQ1m1FKq6fsAzMo8SgxpiF")
        XCTAssertEqual(result.oAuthKeyData.evmAddress, "CmbriSJicm3fga5cTtwWEmZxC2eMzXbntZRt7CMNoo1w")
        XCTAssertEqual(result.postboxKeyData.privKey, "4a0629fffdec0303b76e5e8dfabf21edd4e1957e234e180b7767453a0b301bd0")
        XCTAssertEqual(result.postboxKeyData.X, "ae706aa0becae4b1d6435a42010bdc616254e136d5054bdf431a04e36068fa1c")
        XCTAssertEqual(result.postboxKeyData.Y, "c54dc56e25661c227ad5bfab26368da7fce8629f22c127b24b2c2db93a3c45f1")
        XCTAssertFalse(result.finalKeyData.privKey.isEmpty)
    }

    func test_should_fetch_public_address() async throws {
        let verifier = TORUS_TEST_VERIFIER
        let verifierID = TORUS_TEST_EMAIL

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let val = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa")
        XCTAssertEqual(val.oAuthKeyData!.X, "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b")
        XCTAssertEqual(val.oAuthKeyData!.Y, "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x462A8BF111A55C9354425F875F89B22678c0Bc44")
        XCTAssertEqual(val.finalKeyData!.X, "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1")
        XCTAssertEqual(val.finalKeyData!.Y, "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed")
        XCTAssertEqual(val.metadata?.nonce, BigUInt(0))
        XCTAssertEqual(val.metadata?.upgraded, false)
        XCTAssertEqual(val.metadata?.typeOfUser, .v2)
        XCTAssertNotNil(val.nodesData)
    }

    func test_should_be_able_to_import_key_for_a_new_user() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        var jwt = try generateIdToken(email: fakeEmail)
        let privateKey = try KeyUtils.generateSecret()

        let verifier = TORUS_TEST_VERIFIER
        let verifierID = fakeEmail

        let nodeDetails = try await fnd.getNodeDetails(verifier: verifier, verifierID: verifierID)

        let verifierParams = VerifierParams(verifier_id: verifierID)

        let val = try await torus.importPrivateKey(params: ImportPrivateKeyParams(
            endpoints: nodeDetails.getTorusNodeSSSEndpoints(),
            nodeIndexes: nodeDetails.getTorusIndexes(),
            nodePubKeys: nodeDetails.getTorusNodePub(),
            verifier: verifier,
            verifierParams: verifierParams,
            idToken: jwt,
            newPrivateKey: privateKey
        ))
        XCTAssertEqual(val.finalKeyData.privKey, privateKey)

        jwt = try generateIdToken(email: fakeEmail)
        let shareRetrieval = try await torus.retrieveShares(params: RetrieveSharesParams(
            endpoints: nodeDetails.getTorusNodeSSSEndpoints(),
            indexes: nodeDetails.getTorusIndexes(),
            nodePubKeys: nodeDetails.getTorusNodePub(),
            verifier: verifier,
            verifierParams: verifierParams,
            idToken: jwt
        ))
        XCTAssertEqual(shareRetrieval.finalKeyData.privKey, privateKey)

        let addressRetrieval = try await torus.getPublicAddress(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierId: verifierID)
        let publicAddress = try SecretKey(hex: privateKey).toPublic().serialize(compressed: false)
        let retrievedAddress = KeyUtils.getPublicKeyFromCoords(pubKeyX: addressRetrieval.finalKeyData!.X, pubKeyY: addressRetrieval.finalKeyData!.Y)
        XCTAssertEqual(publicAddress, retrievedAddress)
    }

    func test_should_be_able_to_key_assign() async throws {
        let fakeEmail = generateRandomEmail(of: 6)
        let verifier = TORUS_TEST_VERIFIER
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
        let verifier = TORUS_TEST_VERIFIER
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

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30")
        XCTAssertEqual(val.oAuthKeyData!.X, "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c")
        XCTAssertEqual(val.oAuthKeyData!.Y, "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0xBd6Bc8aDC5f2A0526078Fd2016C4335f64eD3a30")
        XCTAssertEqual(val.finalKeyData!.X, "d45d4ad45ec643f9eccd9090c0a2c753b1c991e361388e769c0dfa90c210348c")
        XCTAssertEqual(val.finalKeyData!.Y, "fdc151b136aa7df94e97cc7d7007e2b45873c4b0656147ec70aad46e178bce1e")
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
        let data = try await torus.retrieveShares(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: verifier, verifierParams: verifierParams, idToken: token)

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

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xaEafa3Fc7349E897F8fCe981f55bbD249f12aC8C")
        XCTAssertEqual(val.oAuthKeyData!.X, "72d9172d7edc623266d6c625db91505e6b64a5524e6d7c7c0184b1bbdea1e986")
        XCTAssertEqual(val.oAuthKeyData!.Y, "8c26d557a0a9cb22dc2a30d36bf67de93a0eb6d4ef503a849c7de2d14dcbdaaa")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x8a7e297e20804786767B1918a5CFa11683e5a3BB")
        XCTAssertEqual(val.finalKeyData!.X, "7927d5281aea24fd93f41696f79c91370ec0097ff65e83e95691fffbde6d733a")
        XCTAssertEqual(val.finalKeyData!.Y, "f22735f0e72ff225274cf499d50b240b7571063e0584471b2b4dab337ad5d8da")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "5712d789f7ecf3435dd9bf1136c2daaa634f0222d64e289d2abe30a729a6a22b")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "2d2b4586fd5fd9d15c22f66b61bc475742754a8b96d1edb7b2590e4c4f97b3f0")
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

        XCTAssertEqual(val.oAuthKeyData!.evmAddress, "0xaEafa3Fc7349E897F8fCe981f55bbD249f12aC8C")
        XCTAssertEqual(val.oAuthKeyData!.X, "72d9172d7edc623266d6c625db91505e6b64a5524e6d7c7c0184b1bbdea1e986")
        XCTAssertEqual(val.oAuthKeyData!.Y, "8c26d557a0a9cb22dc2a30d36bf67de93a0eb6d4ef503a849c7de2d14dcbdaaa")
        XCTAssertEqual(val.finalKeyData!.evmAddress, "0x8a7e297e20804786767B1918a5CFa11683e5a3BB")
        XCTAssertEqual(val.finalKeyData!.X, "7927d5281aea24fd93f41696f79c91370ec0097ff65e83e95691fffbde6d733a")
        XCTAssertEqual(val.finalKeyData!.Y, "f22735f0e72ff225274cf499d50b240b7571063e0584471b2b4dab337ad5d8da")
        XCTAssertEqual(val.metadata?.pubNonce?.x, "5712d789f7ecf3435dd9bf1136c2daaa634f0222d64e289d2abe30a729a6a22b")
        XCTAssertEqual(val.metadata?.pubNonce?.y, "2d2b4586fd5fd9d15c22f66b61bc475742754a8b96d1edb7b2590e4c4f97b3f0")
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

        let val = try await torus.retrieveShares(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: verifier, verifierParams: verifierParams, idToken: jwt)

        XCTAssertLessThan(val.metadata.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData.evmAddress, "0x8a7e297e20804786767B1918a5CFa11683e5a3BB")
        XCTAssertEqual(val.finalKeyData.X, "7927d5281aea24fd93f41696f79c91370ec0097ff65e83e95691fffbde6d733a")
        XCTAssertEqual(val.finalKeyData.Y, "f22735f0e72ff225274cf499d50b240b7571063e0584471b2b4dab337ad5d8da")
        XCTAssertEqual(val.finalKeyData.privKey, "f161f63a84f1c935525ec0bda74bc5a15de6a9a7be28fad237ef6162df335fe6")
        XCTAssertEqual(val.oAuthKeyData.evmAddress, "0xaEafa3Fc7349E897F8fCe981f55bbD249f12aC8C")
        XCTAssertEqual(val.oAuthKeyData.X, "72d9172d7edc623266d6c625db91505e6b64a5524e6d7c7c0184b1bbdea1e986")
        XCTAssertEqual(val.oAuthKeyData.Y, "8c26d557a0a9cb22dc2a30d36bf67de93a0eb6d4ef503a849c7de2d14dcbdaaa")
        XCTAssertEqual(val.oAuthKeyData.privKey, "62e110d9d698979c1966d14b2759006cf13be7dfc86a63ff30812e2032163f2f")
        XCTAssertEqual(val.metadata.pubNonce!.x, "5712d789f7ecf3435dd9bf1136c2daaa634f0222d64e289d2abe30a729a6a22b")
        XCTAssertEqual(val.metadata.pubNonce!.y, "2d2b4586fd5fd9d15c22f66b61bc475742754a8b96d1edb7b2590e4c4f97b3f0")
        XCTAssertEqual(val.metadata.nonce, BigUInt("8e80e560ae59319938f7ef727ff2c5346caac1c7f5be96d3076e3342ad1d20b7", radix: 16))
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

        let val = try await torus.retrieveShares(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierParams: verifierParams, idToken: jwt)

        XCTAssertLessThan(val.metadata.serverTimeOffset, 20)

        XCTAssertEqual(val.finalKeyData.evmAddress, "0x462A8BF111A55C9354425F875F89B22678c0Bc44")
        XCTAssertEqual(val.finalKeyData.X, "36e257717f746cdd52ba85f24f7c9040db8977d3b0354de70ed43689d24fa1b1")
        XCTAssertEqual(val.finalKeyData.Y, "58ec9768c2fe871b3e2a83cdbcf37ba6a88ad19ec2f6e16a66231732713fd507")
        XCTAssertEqual(val.finalKeyData.privKey, "230dad9f42039569e891e6b066ff5258b14e9764ef5176d74aeb594d1a744203")
        XCTAssertEqual(val.oAuthKeyData.evmAddress, "0x137B3607958562D03Eb3C6086392D1eFa01aA6aa")
        XCTAssertEqual(val.oAuthKeyData.X, "118a674da0c68f16a1123de9611ba655f4db1e336fe1b2d746028d65d22a3c6b")
        XCTAssertEqual(val.oAuthKeyData.Y, "8325432b3a3418d632b4fe93db094d6d83250eea60fe512897c0ad548737f8a5")
        XCTAssertEqual(val.oAuthKeyData.privKey, "6b3c872a269aa8994a5acc8cdd70ea3d8d182d42f8af421c0c39ea124e9b66fa")
        XCTAssertEqual(val.metadata.pubNonce!.x, "5d03a0df9b3db067d3363733df134598d42873bb4730298a53ee100975d703cc")
        XCTAssertEqual(val.metadata.pubNonce!.y, "279434dcf0ff22f077877a70bcad1732412f853c96f02505547f7ca002b133ed")

        XCTAssertEqual(val.metadata.nonce, BigUInt("b7d126751b68ecd09e371a23898e6819dee54708a5ead4f6fe83cdc79c0f1c4a", radix: 16))
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
        let data = try await torus.retrieveShares(endpoints: nodeDetails.getTorusNodeSSSEndpoints(), verifier: TORUS_TEST_AGGREGATE_VERIFIER, verifierParams: verifierParams, idToken: hashedIDToken)

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

        let data = try await torus.retrieveShares(endpoints: nodeDetails.getTorusNodeEndpoints(), verifier: verifier, verifierParams: verifierParams, idToken: jwt)

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
