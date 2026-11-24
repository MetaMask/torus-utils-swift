import BigInt
import FetchNodeDetails
@testable import TorusUtils
import XCTest

final class VerifierLookupTests: MockNodeTestCase {
    private let endpoints = ["https://nodes.test/0", "https://nodes.test/1", "https://nodes.test/2"]
    private var nodePubKeys: [TorusNodePubModel] {
        [5, 6, 7].map { k in
            let pub = try! Secp256k1TestKeys.point(k)
            return TorusNodePubModel(_X: pub.x, _Y: pub.y)
        }
    }

    /// Runs a share request that checks the key existence with VerifierLookupRequest instead of commitments.
    private func retrieve(lookupResponse: [String: Any], methods: RecordedValues) async throws -> TorusKey {
        let endpoints = self.endpoints
        MockNodeURLProtocol.handler = { request, body in
            guard endpoints.contains(request.url?.absoluteString ?? ""), let method = body["method"] as? String else {
                return [String: Any]()
            }
            methods.append(method)
            if method == "VerifierLookupRequest" {
                return lookupResponse
            }
            return ["id": 1, "jsonrpc": "2.0", "error": ["code": -32603, "message": "mock", "data": "mock"]]
        }
        return try await NodeUtils.retrieveOrImportShare(
            serverTimeOffset: 0,
            enableOneKey: false,
            network: .SAPPHIRE_MAINNET,
            clientId: "YOUR_CLIENT_ID",
            buildEnv: .production,
            endpoints: endpoints,
            indexes: [1, 2, 3],
            nodePubKeys: nodePubKeys,
            verifier: "google",
            verifierParams: VerifierParams(verifier_id: "hello@tor.us"),
            idToken: "token",
            importedShares: nil,
            overrideExistingKey: false,
            extraParams: TorusUtilsExtraParams(),
            keyType: .secp256k1,
            checkCommitment: false,
            recordId: "",
            source: nil
        )
    }

    private func lookupError(_ data: String) -> [String: Any] {
        ["id": 1, "jsonrpc": "2.0", "error": ["code": -32602, "message": "Input error", "data": data]]
    }

    func test_lookup_error_throws() async throws {
        let methods = RecordedValues()
        do {
            _ = try await retrieve(lookupResponse: lookupError("some other failure"), methods: methods)
            XCTFail("expected a lookup error")
        } catch {
            XCTAssertEqual(error as? TorusUtilError, .runtime("node results do not match at first lookup Input error, some other failure"))
        }
        XCTAssertFalse(methods.get().contains("ImportShares"))
    }

    func test_unassigned_verifier_error_imports_a_new_key() async throws {
        let methods = RecordedValues()
        do {
            _ = try await retrieve(lookupResponse: lookupError("Verifier + VerifierID has not yet been assigned"), methods: methods)
            XCTFail("expected the mock ImportShares error")
        } catch {
            XCTAssertEqual(error as? TorusUtilError, .importShareFailed)
        }
        XCTAssertTrue(methods.get().contains("ImportShares"))
    }

    func test_existing_key_fetches_shares_without_import() async throws {
        let pub = try Secp256k1TestKeys.point(0x1234)
        let methods = RecordedValues()
        let response: [String: Any] = ["id": 1, "jsonrpc": "2.0", "result": ["keys": [["pub_key_X": pub.x, "pub_key_Y": pub.y, "address": "0x0"]]]]
        do {
            _ = try await retrieve(lookupResponse: response, methods: methods)
            XCTFail("expected the mock share error")
        } catch {}
        XCTAssertTrue(methods.get().contains("GetShareOrKeyAssign"))
        XCTAssertFalse(methods.get().contains("ImportShares"))
    }

    func test_no_threshold_lookup_result_throws() async throws {
        let methods = RecordedValues()
        do {
            _ = try await retrieve(lookupResponse: [:], methods: methods)
            XCTFail("expected an invalid lookup result error")
        } catch {
            XCTAssertEqual(error as? TorusUtilError, .runtime("invalid lookup result for verifier: google, verifierId: hello@tor.us"))
        }
    }
}

final class CommitmentRetryTests: MockNodeTestCase {
    func test_commitment_request_retries_network_errors() async throws {
        let endpoints = ["https://nodes.test/0", "https://nodes.test/1", "https://nodes.test/2"]
        let methods = RecordedValues()
        let failedOnce = RecordedValues()
        MockNodeURLProtocol.handler = { request, body in
            let url = request.url?.absoluteString ?? ""
            guard let index = endpoints.firstIndex(of: url), let method = body["method"] as? String else {
                return [String: Any]()
            }
            methods.append(method)
            if method == "CommitmentRequest" {
                if !failedOnce.get().contains(url) {
                    failedOnce.append(url)
                    throw URLError(.timedOut)
                }
                return ["id": 1, "jsonrpc": "2.0", "result": ["signature": "", "data": "", "nodepubx": "", "nodepuby": "", "nodeindex": String(index + 1), "pub_key_x": "abc"]]
            }
            return ["id": 1, "jsonrpc": "2.0", "error": ["code": -32603, "message": "mock", "data": "mock"]]
        }

        do {
            _ = try await NodeUtils.retrieveOrImportShare(
                serverTimeOffset: 0,
                enableOneKey: false,
                network: .SAPPHIRE_MAINNET,
                clientId: "YOUR_CLIENT_ID",
                buildEnv: .production,
                endpoints: endpoints,
                indexes: [],
                nodePubKeys: [],
                verifier: "google",
                verifierParams: VerifierParams(verifier_id: "hello@tor.us"),
                idToken: "token",
                importedShares: nil,
                overrideExistingKey: false,
                extraParams: TorusUtilsExtraParams(),
                keyType: .secp256k1,
                checkCommitment: true,
                recordId: "",
                source: nil
            )
            XCTFail("expected the mock share error")
        } catch {
            XCTAssertNotEqual(error as? TorusUtilError, .commitmentRequestFailed)
        }
        XCTAssertEqual(methods.get().filter { $0 == "CommitmentRequest" }.count, 2 * endpoints.count)
        XCTAssertTrue(methods.get().contains("GetShareOrKeyAssign"))
    }
}

final class CitadelApiKeyTests: MockNodeTestCase {
    private func allowApiKeyHeader(apiKey: String?) async throws -> String? {
        let headers = RecordedValues()
        MockNodeURLProtocol.handler = { request, _ in
            headers.append(request.value(forHTTPHeaderField: "x-api-key") ?? "<none>")
            return ["success": true]
        }
        try await CitadelUtils.callAllowApi(params: CitadelAllowParams(
            buildEnv: .production,
            verifier: "google",
            verifierId: "hello@tor.us",
            network: "sapphire_mainnet",
            clientId: "YOUR_CLIENT_ID",
            recordId: "record"
        ), apiKey: apiKey)
        return headers.get().first
    }

    func test_custom_api_key_is_sent() async throws {
        let header = try await allowApiKeyHeader(apiKey: "custom-key")
        XCTAssertEqual(header, "custom-key")
    }

    func test_default_api_key_is_not_sent() async throws {
        let defaultHeader = try await allowApiKeyHeader(apiKey: "torus-default")
        XCTAssertEqual(defaultHeader, "<none>")
        let missingHeader = try await allowApiKeyHeader(apiKey: nil)
        XCTAssertEqual(missingHeader, "<none>")
    }
}

final class ImportPrivateKeyValidationTests: XCTestCase {
    func test_invalid_private_key_length_throws() async throws {
        let endpoints = ["https://nodes.test/0", "https://nodes.test/1", "https://nodes.test/2"]
        let nodePubKeys = try [5, 6, 7].map { k -> TorusNodePubModel in
            let pub = try Secp256k1TestKeys.point(k)
            return TorusNodePubModel(_X: pub.x, _Y: pub.y)
        }
        let torus = try TorusUtils(params: TorusOptions(clientId: "YOUR_CLIENT_ID", network: .SAPPHIRE_MAINNET))
        for newPrivateKey in [String(repeating: "ab", count: 33), "zz"] {
            do {
                _ = try await torus.importPrivateKey(params: ImportPrivateKeyParams(
                    endpoints: endpoints,
                    nodeIndexes: [1, 2, 3],
                    nodePubKeys: nodePubKeys,
                    verifier: "google",
                    verifierParams: VerifierParams(verifier_id: "hello@tor.us"),
                    idToken: "token",
                    newPrivateKey: newPrivateKey
                ))
                XCTFail("expected an invalid private key length error")
            } catch {
                XCTAssertEqual(error as? TorusUtilError, .runtime("Invalid private key length for given secp256k1 key"))
            }
        }
    }
}

final class RecordedValues {
    private let lock = NSLock()
    private var values: [String] = []

    func append(_ value: String) {
        lock.lock(); defer { lock.unlock() }
        values.append(value)
    }

    func get() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return values
    }
}
