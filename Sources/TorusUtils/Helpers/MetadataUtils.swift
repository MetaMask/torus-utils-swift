import BigInt
import FetchNodeDetails
import Foundation
import OSLog
#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

internal class MetadataUtils {
    public static func decryptNodeData(eciesData: EciesHexOmitCiphertext, ciphertextHex: String, privKey: String) throws -> String {
        return try EncryptionUtils.decryptNodeData(eciesData: eciesData, ciphertextHex: ciphertextHex, privKey: privKey)
    }

    public static func decrypt(privateKey: String, opts: ECIES) throws -> Data {
        return try EncryptionUtils.decrypt(privateKey: privateKey, opts: opts)
    }

    public static func encrypt(publicKey: String, msg: String) throws -> Ecies {
        return try EncryptionUtils.encrypt(publicKey: publicKey, msg: msg)
    }

    internal static func makeUrlRequest(url: String, httpMethod: httpMethod = .post) throws -> URLRequest {
        guard
            let url = URL(string: url)
        else {
            throw TorusUtilError.runtime("Invalid Url \(url)")
        }
        var rq = URLRequest(url: url)
        rq.httpMethod = httpMethod.name
        rq.addValue("application/json", forHTTPHeaderField: "Content-Type")
        rq.addValue("application/json", forHTTPHeaderField: "Accept")
        return rq
    }

    public static func generateMetadataParams(serverTimeOffset: Int, message: String, privateKey: String, X: String, Y: String, keyType: TorusKeyType? = nil) throws -> MetadataParams {
        let privKey = try SecretKey(hex: privateKey)

        let timeStamp = String(BigUInt(TimeInterval(serverTimeOffset) + Date().timeIntervalSince1970), radix: 16)
        let setData: MetadataParams.SetData = .init(data: message, timestamp: timeStamp)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let encodedData = try encoder
            .encode(setData)

        let hash = try KeyUtils.keccak256Data(encodedData).toHexString()
        let sigData = try ECDSA.signRecoverable(key: privKey, hash: hash).serialize()
        _ = try ECDSA.recover(signature: Signature(hex: sigData), hash: hash)
        return .init(pub_key_X: X, pub_key_Y: Y, setData: setData, signature: Data(hex: sigData).base64EncodedString(), keyType: keyType)
    }

    public static func getMetadata(legacyMetadataHost: String, params: GetMetadataParams) async throws -> BigUInt {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        var request = try makeUrlRequest(url: "\(legacyMetadataHost)/get")
        request.httpBody = try encoder.encode(params)
        let urlSession = URLSession(configuration: .default)
        let val = try await urlSession.data(for: request)
        let data: GetMetadataResponse = try JSONDecoder().decode(GetMetadataResponse.self, from: val.0)
        let msg: String = data.message
        let ret = BigUInt(msg, radix: 16) ?? 0
        return ret
    }

    public static func getOrSetNonce(legacyMetadataHost: String, serverTimeOffset: Int, X: String, Y: String, privateKey: String? = nil, getOnly: Bool = false, keyType: TorusKeyType? = nil) async throws -> GetOrSetNonceResult {
        var data: Data
        let msg = getOnly ? "getNonce" : "getOrSetNonce"
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        if privateKey != nil {
            let val = try generateMetadataParams(serverTimeOffset: serverTimeOffset, message: msg, privateKey: privateKey!, X: X, Y: Y, keyType: keyType)
            data = try encoder.encode(val)
        } else {
            var val = GetNonceParams(pub_key_X: X, pub_key_Y: Y, set_data: GetNonceSetDataParams(data: msg))
            // Preserve the legacy secp256k1 request shape while explicitly
            // selecting Ed25519 for the new curve.
            val.key_type = keyType == .ed25519 ? keyType : nil
            data = try encoder.encode(val)
        }
        var request = try makeUrlRequest(url: "\(legacyMetadataHost)/get_or_set_nonce")
        request.httpBody = data
        let urlSession = URLSession(configuration: .default)
        let val = try await urlSession.data(for: request)

        let decoded = try JSONDecoder().decode(GetOrSetNonceResult.self, from: val.0)
        return decoded
    }

    public static func getOrSetSapphireMetadataNonce(metadataHost: String, network: Web3AuthNetwork, X: String, Y: String, serverTimeOffset: Int? = nil, privateKey: String? = nil, getOnly: Bool = false, keyType: TorusKeyType = .secp256k1) async throws -> GetOrSetNonceResult {
        guard network.isSapphire else {
            throw TorusUtilError.metadataNonceMissing
        }
        if privateKey != nil {
            return try await getOrSetNonce(
                legacyMetadataHost: metadataHost,
                serverTimeOffset: serverTimeOffset ?? 0,
                X: X,
                Y: Y,
                privateKey: privateKey,
                getOnly: getOnly,
                keyType: keyType
            )
        }

        struct SapphireSetData: Codable {
            let operation: String
        }
        struct SapphireMetadataParams: Codable {
            let pub_key_X: String
            let pub_key_Y: String
            let key_type: TorusKeyType
            let set_data: SapphireSetData
        }

        let params = SapphireMetadataParams(
            pub_key_X: X,
            pub_key_Y: Y,
            // torus.js v17 keeps this fallback on secp256k1; Ed25519 nonce
            // seed data is expected directly from the node response.
            key_type: .secp256k1,
            set_data: SapphireSetData(operation: getOnly ? "getNonce" : "getOrSetNonce")
        )
        var lastResult: GetOrSetNonceResult?
        for attempt in 0 ..< 5 {
            var request = try makeUrlRequest(url: "\(metadataHost)/get_or_set_nonce")
            request.httpBody = try JSONEncoder().encode(params)
            let (data, _) = try await URLSession.shared.data(for: request)
            let result = try JSONDecoder().decode(GetOrSetNonceResult.self, from: data)
            lastResult = result
            if getOnly || (result.pubNonce != nil && !(result.pubNonce!.x.isEmpty || result.pubNonce!.y.isEmpty)) {
                return result
            }
            if attempt < 4 {
                try await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
        return lastResult!
    }

    private struct EncryptedSeed: Decodable {
        let enc_text: String
        let metadata: EciesHexOmitCiphertext
    }

    public static func decryptSeedData(seedBase64: String, finalUserKey: BigInt) throws -> String {
        guard let encoded = Data(base64Encoded: seedBase64) else {
            throw TorusUtilError.decodingFailed("Invalid encrypted seed")
        }
        let encryptedSeed = try JSONDecoder().decode(EncryptedSeed.self, from: encoded)
        let decryptionKey = try KeyUtils.getSecpKeyFromEd25519(finalUserKey)
            .magnitude.serialize().hexString.addLeading0sForLength64()
        do {
            return try decryptNodeData(
                eciesData: encryptedSeed.metadata,
                ciphertextHex: encryptedSeed.enc_text,
                privKey: decryptionKey
            )
        } catch {
            throw TorusUtilError.decryptionFailed
        }
    }
}
