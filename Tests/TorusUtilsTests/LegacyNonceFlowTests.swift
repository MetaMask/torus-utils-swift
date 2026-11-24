import BigInt
import FetchNodeDetails
@testable import TorusUtils
import XCTest

final class LegacyNonceFlowTests: MockNodeTestCase {
    private let endpoints = ["https://nodes.test/0", "https://nodes.test/1", "https://nodes.test/2"]
    private var nodeNonces: [[String: Any]] = []
    private var isNewKey = false

    // nonce_data in the shape the nodes send it
    private func v1Nonce(_ nonce: String) -> [String: Any] {
        ["typeOfUser": "v1", "nonce": nonce, "pubNonce": ["x": "", "y": ""], "seed": "", "upgraded": false]
    }

    private func v2Nonce(_ nonce: Int) throws -> [String: Any] {
        let pub = try Secp256k1TestKeys.point(nonce)
        return ["typeOfUser": "v2", "nonce": "", "pubNonce": ["x": pub.x, "y": pub.y], "seed": "", "upgraded": false]
    }

    override func setUp() {
        super.setUp()
        isNewKey = false
        nodeNonces = []
        let oAuthPub = try! Secp256k1TestKeys.point(1)
        MockNodeURLProtocol.handler = { [unowned self] request, _ in
            guard let index = self.endpoints.firstIndex(of: request.url?.absoluteString ?? "") else {
                return [String: Any]()
            }
            return [
                "id": 1,
                "jsonrpc": "2.0",
                "result": [
                    "keys": [["pub_key_X": oAuthPub.x, "pub_key_Y": oAuthPub.y, "address": "0x0", "nonce_data": self.nodeNonces[index]]],
                    "is_new_key": self.isNewKey,
                    "node_index": String(index + 1),
                ] as [String: Any],
            ]
        }
    }

    private func lookup(network: Web3AuthNetwork = .MAINNET, enableOneKey: Bool = true) async throws -> TorusPublicKey {
        let torus = try TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: network, enableOneKey: enableOneKey))
        return try await torus.getPublicAddress(endpoints: endpoints, verifier: "google", verifierId: "hello@tor.us")
    }

    func test_adds_v1_node_nonce_to_oauth_key_with_no_metadata_call() async throws {
        for enableOneKey in [true, false] {
            MockNodeURLProtocol.clearRequests()
            nodeNonces = [v1Nonce(Secp256k1TestKeys.hex(2)), v1Nonce(Secp256k1TestKeys.hex(2)), v1Nonce(Secp256k1TestKeys.hex(2))]

            let result = try await lookup(enableOneKey: enableOneKey)

            let finalPub = try Secp256k1TestKeys.point(3)
            XCTAssertEqual(result.finalKeyData?.X, finalPub.x, "enableOneKey \(enableOneKey)")
            XCTAssertEqual(result.finalKeyData?.Y, finalPub.y, "enableOneKey \(enableOneKey)")
            XCTAssertEqual(result.metadata?.typeOfUser, .v1)
            XCTAssertEqual(result.metadata?.nonce, BigUInt(2))
            XCTAssertNil(result.metadata?.pubNonce)
            XCTAssertFalse(MockNodeURLProtocol.requestedURLs.isEmpty)
            XCTAssertTrue(MockNodeURLProtocol.requestedURLs.allSatisfy { endpoints.contains($0) }, "\(MockNodeURLProtocol.requestedURLs)")
        }
    }

    func test_uses_oauth_key_for_existing_key_with_no_nonce() async throws {
        nodeNonces = [v1Nonce(""), v1Nonce(""), v1Nonce("")]

        let result = try await lookup()

        let oAuthPub = try Secp256k1TestKeys.point(1)
        XCTAssertEqual(result.finalKeyData?.X, oAuthPub.x)
        XCTAssertEqual(result.finalKeyData?.Y, oAuthPub.y)
        XCTAssertEqual(result.metadata?.typeOfUser, .v1)
        XCTAssertEqual(result.metadata?.nonce, BigUInt(0))
    }

    func test_skips_v1_answer_with_no_nonce_for_new_key_and_uses_next_node_nonce() async throws {
        isNewKey = true
        nodeNonces = [v1Nonce(""), try v2Nonce(2), try v2Nonce(2)]

        let result = try await lookup()

        let finalPub = try Secp256k1TestKeys.point(3)
        XCTAssertEqual(result.finalKeyData?.X, finalPub.x)
        XCTAssertEqual(result.finalKeyData?.Y, finalPub.y)
        XCTAssertEqual(result.metadata?.typeOfUser, .v2)
    }

    func test_fails_for_new_key_when_no_node_sends_a_nonce() async throws {
        isNewKey = true
        nodeNonces = [v1Nonce(""), v1Nonce(""), v1Nonce("")]

        do {
            _ = try await lookup()
            XCTFail("expected lookup to throw")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("invalid public key result"), error.localizedDescription)
        }
    }

    func test_ignores_v2_nonce_when_enable_one_key_is_false() async throws {
        nodeNonces = [try v2Nonce(2), try v2Nonce(2), try v2Nonce(2)]

        let result = try await lookup(enableOneKey: false)

        let oAuthPub = try Secp256k1TestKeys.point(1)
        XCTAssertEqual(result.finalKeyData?.X, oAuthPub.x)
        XCTAssertEqual(result.finalKeyData?.Y, oAuthPub.y)
        XCTAssertEqual(result.metadata?.typeOfUser, .v1)
        XCTAssertEqual(result.metadata?.nonce, BigUInt(0))
        XCTAssertNil(result.metadata?.pubNonce)
        XCTAssertEqual(result.metadata?.upgraded, false)
    }

    func test_sapphire_uses_v2_node_nonce_with_no_metadata_call() async throws {
        nodeNonces = [try v2Nonce(2), try v2Nonce(2), try v2Nonce(2)]

        let result = try await lookup(network: .SAPPHIRE_MAINNET, enableOneKey: false)

        let finalPub = try Secp256k1TestKeys.point(3)
        let noncePub = try Secp256k1TestKeys.point(2)
        XCTAssertEqual(result.finalKeyData?.X, finalPub.x)
        XCTAssertEqual(result.finalKeyData?.Y, finalPub.y)
        XCTAssertEqual(result.metadata?.typeOfUser, .v2)
        XCTAssertEqual(result.metadata?.pubNonce?.x, noncePub.x)
        XCTAssertEqual(result.metadata?.upgraded, false)
        XCTAssertTrue(MockNodeURLProtocol.requestedURLs.allSatisfy { endpoints.contains($0) }, "\(MockNodeURLProtocol.requestedURLs)")
    }

    func test_first_node_nonce_selection() throws {
        let v1Empty = GetOrSetNonceResult(typeOfUser: "v1", nonce: "", pubNonce: PubNonce(x: "", y: ""))
        let v1WithNonce = GetOrSetNonceResult(typeOfUser: "v1", nonce: "02")
        let v2 = GetOrSetNonceResult(typeOfUser: "v2", nonce: "", pubNonce: PubNonce(x: "ab", y: "cd"))

        // an existing key accepts an empty v1 answer
        XCTAssertEqual(NodeUtils.firstNodeNonce([nil, v1Empty, v2], isNewKey: false)?.typeOfUser, "v1")
        // a new key skips an empty v1 answer, a node that has not seen the first nonce write also answers v1
        XCTAssertEqual(NodeUtils.firstNodeNonce([v1Empty, v2], isNewKey: true)?.typeOfUser, "v2")
        XCTAssertEqual(NodeUtils.firstNodeNonce([v1Empty, v1WithNonce], isNewKey: true)?.nonce, "02")
        XCTAssertNil(NodeUtils.firstNodeNonce([v1Empty, nil], isNewKey: true))
        XCTAssertNil(NodeUtils.firstNodeNonce([], isNewKey: false))
    }
}

final class NoNonceSharesTests: XCTestCase {
    private let nodePubKeys: [INodePub] = [5, 6, 7].map { k in
        let pub = try! Secp256k1TestKeys.point(k)
        return INodePub(X: pub.x, Y: pub.y)
    }

    private let importKey = Secp256k1TestKeys.hex(0x1234)

    func test_splits_the_key_itself_and_sends_no_nonce() throws {
        let shares = try KeyUtils.generateShares(
            keyType: .secp256k1,
            serverTimeOffset: 0,
            nodeIndexes: [1, 2, 3],
            nodePubKeys: nodePubKeys,
            privateKey: importKey,
            withNonce: false
        )

        let importPub = try Secp256k1TestKeys.point(0x1234)
        XCTAssertEqual(shares.count, 3)
        for share in shares {
            XCTAssertEqual(share.oauth_pub_key_x.addLeading0sForLength64().lowercased(), importPub.x)
            XCTAssertEqual(share.oauth_pub_key_y.addLeading0sForLength64().lowercased(), importPub.y)
            XCTAssertEqual(share.nonce_data, "")
            XCTAssertEqual(share.nonce_signature, "")
        }
    }

    func test_with_nonce_still_sends_nonce_data() throws {
        let shares = try KeyUtils.generateShares(
            keyType: .secp256k1,
            serverTimeOffset: 0,
            nodeIndexes: [1, 2, 3],
            nodePubKeys: nodePubKeys,
            privateKey: importKey
        )

        let importPub = try Secp256k1TestKeys.point(0x1234)
        for share in shares {
            XCTAssertNotEqual(share.oauth_pub_key_x.addLeading0sForLength64().lowercased(), importPub.x)
            XCTAssertFalse(share.nonce_data.isEmpty)
            XCTAssertFalse(share.nonce_signature.isEmpty)
        }
    }

    func test_rejects_ed25519_keys() {
        XCTAssertThrowsError(try KeyUtils.generateShares(
            keyType: .ed25519,
            serverTimeOffset: 0,
            nodeIndexes: [1, 2, 3],
            nodePubKeys: nodePubKeys,
            privateKey: importKey,
            withNonce: false
        )) { error in
            XCTAssertTrue(error.localizedDescription.contains("only secp256k1"), error.localizedDescription)
        }
    }
}
