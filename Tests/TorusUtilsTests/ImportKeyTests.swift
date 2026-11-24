import BigInt
import FetchNodeDetails
@testable import TorusUtils
import XCTest

final class ImportKeyTests: MockNodeTestCase {
    private let endpoints = ["https://nodes.test/0", "https://nodes.test/1", "https://nodes.test/2"]
    private let importKey = Secp256k1TestKeys.hex(0x1234)
    private let mismatchMessage = "imported key mismatch: the nodes returned a different final key than expected, this should never occur, please contact web3auth support."
    private var nodePubKeys: [TorusNodePubModel] {
        [5, 6, 7].map { k in
            let pub = try! Secp256k1TestKeys.point(k)
            return TorusNodePubModel(_X: pub.x, _Y: pub.y)
        }
    }

    private func torusKey(finalPrivKey: String) -> TorusKey {
        TorusKey(
            finalKeyData: TorusKey.FinalKeyData(evmAddress: "", X: "", Y: "", privKey: finalPrivKey),
            oAuthKeyData: TorusKey.OAuthKeyData(evmAddress: "", X: "", Y: "", privKey: ""),
            postboxKeyData: TorusKey.PostboxKeyData(X: "", Y: "", privKey: ""),
            sessionData: TorusKey.SessionData(sessionTokenData: [], sessionAuthKey: ""),
            metadata: TorusPublicKey.Metadata(pubNonce: nil, nonce: 0, typeOfUser: .v1, upgraded: nil, serverTimeOffset: 0),
            nodesData: TorusKey.NodesData(nodeIndexes: [])
        )
    }

    func test_returns_the_key_when_the_nodes_stored_the_import_nonce() throws {
        XCTAssertNoThrow(try TorusUtils.assertImportedKey(torusKey: torusKey(finalPrivKey: importKey), importedPrivateKey: importKey))
        // the nodes may drop leading zeros or use upper case
        XCTAssertNoThrow(try TorusUtils.assertImportedKey(torusKey: torusKey(finalPrivKey: "1234"), importedPrivateKey: importKey.uppercased()))
    }

    func test_fails_when_the_nodes_kept_a_different_nonce() {
        XCTAssertThrowsError(try TorusUtils.assertImportedKey(torusKey: torusKey(finalPrivKey: Secp256k1TestKeys.hex(0x9999)), importedPrivateKey: importKey)) { error in
            XCTAssertEqual(error as? TorusUtilError, .runtime(mismatchMessage))
        }
    }

    func test_fails_for_an_empty_final_key() {
        XCTAssertThrowsError(try TorusUtils.assertImportedKey(torusKey: torusKey(finalPrivKey: ""), importedPrivateKey: importKey)) { error in
            XCTAssertEqual(error as? TorusUtilError, .runtime(mismatchMessage))
        }
    }

    /// Runs importPrivateKey against mock nodes and returns the nonce data of the shares sent to ImportShares.
    private func importedNonceData(network: Web3AuthNetwork, enableOneKey: Bool) async throws -> [String] {
        let endpoints = self.endpoints
        let importedItems = CapturedItems()
        MockNodeURLProtocol.handler = { request, body in
            guard let index = endpoints.firstIndex(of: request.url?.absoluteString ?? "") else {
                return [String: Any]()
            }
            switch body["method"] as? String {
            case "CommitmentRequest":
                return ["id": 1, "jsonrpc": "2.0", "result": ["signature": "", "data": "", "nodepubx": "", "nodepuby": "", "nodeindex": String(index + 1)]]
            case "ImportShares":
                importedItems.set((body["params"] as? [String: Any])?["item"] as? [[String: Any]] ?? [])
                return ["id": 1, "jsonrpc": "2.0", "error": ["code": -32603, "message": "mock", "data": "mock"]]
            default:
                return [String: Any]()
            }
        }

        let torus = try TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: network, enableOneKey: enableOneKey))
        do {
            _ = try await torus.importPrivateKey(params: ImportPrivateKeyParams(
                endpoints: endpoints,
                nodeIndexes: [1, 2, 3],
                nodePubKeys: nodePubKeys,
                verifier: "google",
                verifierParams: VerifierParams(verifier_id: "hello@tor.us"),
                idToken: "token",
                newPrivateKey: importKey
            ))
            XCTFail("expected the mock ImportShares error")
        } catch {
            XCTAssertEqual(error as? TorusUtilError, .importShareFailed)
        }
        let items = importedItems.get()
        XCTAssertEqual(items.count, endpoints.count)
        return items.map { $0["nonce_data"] as? String ?? "<missing>" }
    }

    private final class CapturedItems {
        private let lock = NSLock()
        private var items: [[String: Any]] = []

        func set(_ newItems: [[String: Any]]) {
            lock.lock(); defer { lock.unlock() }
            items = newItems
        }

        func get() -> [[String: Any]] {
            lock.lock(); defer { lock.unlock() }
            return items
        }
    }

    func test_legacy_import_without_one_key_sends_no_nonce() async throws {
        let nonceData = try await importedNonceData(network: .MAINNET, enableOneKey: false)
        XCTAssertEqual(nonceData, ["", "", ""])
    }

    func test_legacy_import_with_one_key_sends_nonce() async throws {
        let nonceData = try await importedNonceData(network: .MAINNET, enableOneKey: true)
        XCTAssertTrue(nonceData.allSatisfy { !$0.isEmpty && $0 != "<missing>" }, "\(nonceData)")
    }

    func test_sapphire_import_sends_nonce() async throws {
        let nonceData = try await importedNonceData(network: .SAPPHIRE_MAINNET, enableOneKey: false)
        XCTAssertTrue(nonceData.allSatisfy { !$0.isEmpty && $0 != "<missing>" }, "\(nonceData)")
    }
}

final class NewKeyRequirementsTests: MockNodeTestCase {
    private let endpoints = ["https://nodes.test/0", "https://nodes.test/1", "https://nodes.test/2"]

    private func retrieve(indexes: [BigUInt], nodePubKeys: [TorusNodePubModel], importedShares: [ImportedShare]? = nil) async throws -> TorusKey {
        try await NodeUtils.retrieveOrImportShare(
            serverTimeOffset: 0,
            enableOneKey: false,
            network: .SAPPHIRE_MAINNET,
            clientId: "YOUR_CLIENT_ID",
            buildEnv: .production,
            endpoints: endpoints,
            indexes: indexes,
            nodePubKeys: nodePubKeys,
            verifier: "google",
            verifierParams: VerifierParams(verifier_id: "hello@tor.us"),
            idToken: "token",
            importedShares: importedShares,
            overrideExistingKey: false,
            extraParams: TorusUtilsExtraParams(),
            keyType: .secp256k1,
            checkCommitment: true,
            recordId: "",
            source: nil
        )
    }

    func test_new_key_without_node_details_throws() async throws {
        let endpoints = self.endpoints
        // no node has a key for the user, so the commitments carry no pub_key_x
        MockNodeURLProtocol.handler = { request, body in
            guard let index = endpoints.firstIndex(of: request.url?.absoluteString ?? ""), body["method"] as? String == "CommitmentRequest" else {
                return [String: Any]()
            }
            return ["id": 1, "jsonrpc": "2.0", "result": ["signature": "", "data": "", "nodepubx": "", "nodepuby": "", "nodeindex": String(index + 1)]]
        }

        do {
            _ = try await retrieve(indexes: [], nodePubKeys: [])
            XCTFail("expected a missing node details error")
        } catch {
            XCTAssertEqual(error as? TorusUtilError, .runtime("nodePubkeys and indexes are required to create a new key"))
        }
        XCTAssertFalse(MockNodeURLProtocol.requestedURLs.contains { $0.contains("metadata") })
    }

    func test_invalid_imported_shares_length_throws() async throws {
        let pub = try Secp256k1TestKeys.point(5)
        let shares = try KeyUtils.generateShares(
            serverTimeOffset: 0,
            nodeIndexes: [1, 2],
            nodePubKeys: [INodePub(X: pub.x, Y: pub.y), INodePub(X: pub.x, Y: pub.y)],
            privateKey: Secp256k1TestKeys.hex(0x1234)
        )

        do {
            _ = try await retrieve(indexes: [1, 2, 3], nodePubKeys: [], importedShares: shares)
            XCTFail("expected an imported shares length error")
        } catch {
            XCTAssertEqual(error as? TorusUtilError, .runtime("Invalid imported shares length"))
        }
    }
}
