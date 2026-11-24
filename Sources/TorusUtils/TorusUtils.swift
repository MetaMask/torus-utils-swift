import BigInt
import FetchNodeDetails
import Foundation
import OSLog
#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

var utilsLogType = OSLogType.default

public class TorusUtils {
    private var sessionTime: Int = 86400 // 24 hour

    var serverTimeOffset: Int?

    var network: Web3AuthNetwork

    var clientId: String

    var buildEnv: BuildEnv

    var source: String?

    var keyType: TorusKeyType

    var enableOneKey: Bool

    var apiKey: String = "torus-default"

    /// Initializes TorusUtils with the provided options
    ///
    /// - Parameters:
    ///   - params: `TorusOptions`
    ///   - logLevel: `OSLogType`, only needs to be provided if the default logging level should be changed
    ///
    /// - Returns: `TorusUtils`
    ///
    /// - Throws: `TorusUtilError.invalidInput`
    public init(params: TorusOptions, loglevel: OSLogType = .default) throws {
        if params.keyType == .ed25519, params.network.isLegacy {
            throw TorusUtilError.runtime("keyType: ed25519 is not supported by \(params.network.name) network")
        }

        serverTimeOffset = params.serverTimeOffset
        network = params.network
        clientId = params.clientId
        buildEnv = params.buildEnv
        source = params.source
        keyType = params.keyType
        utilsLogType = loglevel
        enableOneKey = params.enableOneKey
    }

    /// Sets the apiKey
    ///
    /// - Parameters:
    ///   - apiKey: The api key to be assigned
    public func setApiKey(apiKey: String) {
        self.apiKey = apiKey
    }

    /// Reverts the apiKey for `TorusUtils` to the default value
    public func removeApiKey() {
        apiKey = "torus-default"
    }

    /// Sets the sessionTime
    ///
    /// - Parameters:
    ///   - sessionTime: The amount of time a session should be valid for in seconds, default is 24 hours.
    public func setSessionTime(sessionTime: Int) {
        self.sessionTime = sessionTime
    }

    /// Convenience function to quickly retrieve the postbox key from `TorusKey`
    ///
    /// - Parameters:
    ///   - torusKey: `TorusKey`
    ///
    /// - Returns: `String`
    public static func getPostboxKey(torusKey: TorusKey) -> String {
        torusKey.postboxKeyData.privKey
    }

    /// Login for the provided user
    ///
    /// - Parameters:
    ///   - endpoints: The endpoints to be queried for the relevant network.
    ///   - verifier: The verifier to query, this can be a single verifier or an aggregate verifier.
    ///   - verifier_id: The identity of the user to be queried against the verifier, this is usually an emal.
    ///   - verifierParams: `VerifierParams`
    ///   - idToken: This is the identity token of the user. For single verifiers this will be a jwt, in the case of an aggregate verifier, this will be a keccak256 hash of the jwt.
    ///
    /// - Returns: `TorusKey`
    ///
    /// - Throws: `TorusUtilError`
    public func retrieveShares(params: RetrieveSharesParams) async throws -> TorusKey {
        guard !params.endpoints.isEmpty else {
            throw TorusUtilError.runtime("endpoints param is required")
        }
        guard !params.nodePubKeys.isEmpty else {
            throw TorusUtilError.runtime("nodePubKeys param is required")
        }
        guard params.nodePubKeys.count == params.indexes.count else {
            throw TorusUtilError.runtime("nodePubKeys length must be same as indexes length")
        }
        guard params.nodePubKeys.count == params.endpoints.count else {
            throw TorusUtilError.runtime("nodePubKeys length must be same as endpoints length")
        }

        if params.extraParams.session_token_exp_second == nil {
            params.extraParams.session_token_exp_second = sessionTime
        }

        let callerSuppliedRecordId = !(params.recordId?.isEmpty ?? true)
        let recordId = callerSuppliedRecordId ? params.recordId! : CitadelUtils.generateRecordId()

        do {
            let result = try await NodeUtils.retrieveOrImportShare(
                serverTimeOffset: serverTimeOffset,
                enableOneKey: enableOneKey,
                network: network,
                clientId: clientId,
                buildEnv: buildEnv,
                endpoints: params.endpoints,
                indexes: params.indexes,
                nodePubKeys: params.nodePubKeys,
                verifier: params.verifier,
                verifierParams: params.verifierParams,
                idToken: params.idToken,
                importedShares: [],
                overrideExistingKey: false,
                extraParams: params.extraParams,
                keyType: keyType,
                checkCommitment: params.checkCommitment,
                recordId: recordId,
                source: source,
                apiKey: apiKey
            )

            if callerSuppliedRecordId {
                reportUserAuthFlowAudit(
                    params: params,
                    recordId: recordId,
                    authFlowAuditParams: CitadelAuthFlowAuditParams(oauthVerified: true, oauthCompleted: true)
                )
            } else {
                reportSignerAllow(params: makeAllowParams(
                    verifier: params.verifier,
                    verifierId: params.verifierParams.verifier_id,
                    recordId: recordId,
                    oauthVerified: .set
                ))
            }
            return result
        } catch {
            if callerSuppliedRecordId {
                reportUserAuthFlowAudit(
                    params: params,
                    recordId: recordId,
                    authFlowAuditParams: CitadelAuthFlowAuditParams(
                        oauthCompleted: true,
                        oauthVerificationFailed: true
                    )
                )
            } else {
                reportSignerAllow(params: makeAllowParams(
                    verifier: params.verifier,
                    verifierId: params.verifierParams.verifier_id,
                    recordId: recordId,
                    oauthVerificationFailed: .set
                ))
            }
            throw error
        }
    }

    /// Without node details this can only log in existing users; creating a new key throws.
    @available(*, deprecated, message: "Use retrieveShares(params:) with indexes and nodePubKeys")
    public func retrieveShares(
        endpoints: [String],
        verifier: String,
        verifierParams: VerifierParams,
        idToken: String,
        extraParams: TorusUtilsExtraParams = TorusUtilsExtraParams()
    ) async throws -> TorusKey {
        if extraParams.session_token_exp_second == nil {
            extraParams.session_token_exp_second = sessionTime
        }
        return try await NodeUtils.retrieveOrImportShare(
            serverTimeOffset: serverTimeOffset,
            enableOneKey: enableOneKey,
            network: network,
            clientId: clientId,
            buildEnv: buildEnv,
            endpoints: endpoints,
            indexes: [],
            nodePubKeys: [],
            verifier: verifier,
            verifierParams: verifierParams,
            idToken: idToken,
            importedShares: [],
            overrideExistingKey: false,
            extraParams: extraParams,
            keyType: keyType,
            checkCommitment: true,
            recordId: CitadelUtils.generateRecordId(),
            source: source,
            apiKey: apiKey
        )
    }

    /// Retrieves user information, defaulting the user type to .v2
    ///
    /// - Parameters:
    ///   - endpoints: The endpoints to be queried for the relevant network.
    ///   - verifier: The verifier to query, this can be a single verifier or an aggregate verifier.
    ///   - verifier_id: The identity of the user to be queried against the verifier, this is usually an emal.
    ///   - extended_verifier_id: This is only used if querying a tss verifier, otherwise it is not supplied. Format is (verifierId + "\u{0015}" + tssTag + "\u{0016}" + randomNonce)
    ///
    /// - Returns: `TorusPublicKey`
    ///
    /// - Throws: `TorusUtilError
    public func getPublicAddress(endpoints: [String], verifier: String, verifierId: String, extendedVerifierId: String? = nil) async throws -> TorusPublicKey {
        return try await getNewPublicAddress(endpoints: endpoints, verifier: verifier, verifierId: verifierId, extendedVerifierId: extendedVerifierId, enableOneKey: enableOneKey)
    }

    /// Imports a private key for the provided user
    ///
    /// - Parameters:
    ///   - endpoints: The endpoints to be queried for the relevant network.
    ///   - nodeIndexes: The node indexes for the endpoints.
    ///   - nodePubKeys: The public keys for the endpoints. `TorusNodePubModel`
    ///   - verifier: The verifier to query, this can be a single verifier or an aggregate verifier.
    ///   - verifier_id: The identity of the user to be queried against the verifier, this is usually an emal.
    ///   - verifierParams: `VerifierParams`
    ///   - idToken: This is the identity token of the user. For single verifiers this will be a jwt, in the case of an aggregate verifier, this will be a keccak256 hash of the jwt.
    ///   - newPrivateKey: The private key that is being imported.
    ///
    /// - Returns: `TorusKey`
    ///
    /// - Throws: `TorusUtilError`
    public func importPrivateKey(params: ImportPrivateKeyParams) async throws -> TorusKey {
        let nodePubs = TorusNodePubModelToINodePub(nodes: params.nodePubKeys)
        if params.endpoints.count != params.nodeIndexes.count {
            throw TorusUtilError.runtime("Length of endpoints must be the same as length of nodeIndexes")
        }
        if params.endpoints.count != params.nodePubKeys.count {
            throw TorusUtilError.runtime("Length of endpoints must be the same as length of nodePubKeys")
        }

        let privateKeyHex = params.newPrivateKey.addLeading0sForLength64()
        if privateKeyHex.count != 64 || Data(hex: privateKeyHex).count != 32 {
            throw TorusUtilError.runtime("Invalid private key length for given \(keyType.rawValue) key")
        }

        // a legacy dApp without OneKey uses the key itself, so it imports the key with no nonce
        let withNonce = !network.isLegacy || enableOneKey
        let sharesData = try KeyUtils.generateShares(
            keyType: keyType,
            serverTimeOffset: serverTimeOffset ?? 0,
            nodeIndexes: params.nodeIndexes,
            nodePubKeys: nodePubs,
            privateKey: params.newPrivateKey,
            withNonce: withNonce
        )

        if keyType == .ed25519 {
            let importedPubKey = Ed25519Utils.encode(Ed25519Utils.point(fromScalar: try Ed25519Utils.scalar(fromSeed: Data(hex: privateKeyHex))))
            guard let firstShare = sharesData.first, Ed25519Utils.encode(firstShare.final_user_point) == importedPubKey else {
                throw TorusUtilError.runtime("invalid shares data for ed25519 key, public key is not matching after generating shares")
            }
        }

        if params.extraParams.session_token_exp_second == nil {
            params.extraParams.session_token_exp_second = sessionTime
        }

        let torusKey = try await NodeUtils.retrieveOrImportShare(
            serverTimeOffset: serverTimeOffset ?? 0,
            enableOneKey: enableOneKey,
            network: network,
            clientId: clientId,
            buildEnv: buildEnv,
            endpoints: params.endpoints,
            indexes: params.nodeIndexes,
            nodePubKeys: params.nodePubKeys,
            verifier: params.verifier,
            verifierParams: params.verifierParams,
            idToken: params.idToken,
            importedShares: sharesData,
            overrideExistingKey: true,
            extraParams: params.extraParams,
            keyType: keyType,
            checkCommitment: params.checkCommitment,
            recordId: params.recordId ?? CitadelUtils.generateRecordId(),
            source: source,
            apiKey: apiKey
        )
        try TorusUtils.assertImportedKey(torusKey: torusKey, importedPrivateKey: params.newPrivateKey)
        return torusKey
    }

    /// The final key must be the imported key.
    /// The metadata server keeps a nonce that already exists and still answers with success,
    /// so if a different nonce was stored first, this check is the only signal that the import nonce was dropped.
    /// An empty final key (an upgraded account without a private nonce) also fails here.
    internal static func assertImportedKey(torusKey: TorusKey, importedPrivateKey: String) throws {
        let finalPrivKey = torusKey.finalKeyData.privKey.addLeading0sForLength64().lowercased()
        let importedKey = importedPrivateKey.addLeading0sForLength64().lowercased()
        if finalPrivKey != importedKey {
            throw TorusUtilError.runtime("imported key mismatch: the nodes returned a different final key than expected, this should never occur, please contact web3auth support.")
        }
    }

    @available(*, deprecated, message: "Use importPrivateKey(params:)")
    public func importPrivateKey(
        endpoints: [String],
        nodeIndexes: [BigUInt],
        nodePubKeys: [TorusNodePubModel],
        verifier: String,
        verifierParams: VerifierParams,
        idToken: String,
        newPrivateKey: String,
        extraParams: TorusUtilsExtraParams = TorusUtilsExtraParams()
    ) async throws -> TorusKey {
        try await importPrivateKey(params: ImportPrivateKeyParams(
            endpoints: endpoints,
            nodeIndexes: nodeIndexes,
            nodePubKeys: nodePubKeys,
            verifier: verifier,
            verifierParams: verifierParams,
            idToken: idToken,
            newPrivateKey: newPrivateKey,
            extraParams: extraParams
        ))
    }

    public func reportSignerAllow(params: CitadelAllowParams) {
        Task {
            do {
                try await CitadelUtils.callAllowApi(params: params, apiKey: apiKey)
            } catch {
                os_log(
                    "Failed to log Citadel allow API: %{public}@",
                    log: getTorusLogger(log: TorusUtilsLogger.network, type: .error),
                    type: .error,
                    String(describing: error)
                )
            }
        }
    }

    public func reportUserAuthFlowAudit(
        params: RetrieveSharesParams,
        recordId: String? = nil,
        authFlowAuditParams: CitadelAuthFlowAuditParams
    ) {
        let auditParams = CitadelUtils.buildAuditPayload(
            network: network,
            clientId: clientId,
            params: params,
            recordId: recordId,
            authFlowAuditParams: authFlowAuditParams
        )
        let environment = buildEnv
        Task {
            do {
                try await CitadelUtils.callAuditApi(buildEnv: environment, params: auditParams)
            } catch {
                os_log(
                    "Failed to log Citadel auth audit API: %{public}@",
                    log: getTorusLogger(log: TorusUtilsLogger.network, type: .error),
                    type: .error,
                    String(describing: error)
                )
            }
        }
    }

    private func makeAllowParams(
        verifier: String,
        verifierId: String,
        recordId: String,
        oauthVerificationFailed: CitadelAllowParamsSetOrUnsetFlag? = nil,
        oauthVerified: CitadelAllowParamsSetOrUnsetFlag? = nil
    ) -> CitadelAllowParams {
        CitadelAllowParams(
            buildEnv: buildEnv,
            verifier: verifier,
            verifierId: verifierId,
            network: network.name,
            clientId: clientId,
            recordId: recordId,
            source: source,
            oauthVerified: oauthVerified,
            oauthVerificationFailed: oauthVerificationFailed
        )
    }

    /// Retrieves user information
    ///
    /// - Parameters:
    ///   - endpoints: The endpoints to be queried for the relevant network.
    ///   - verifier: The verifier to query, this can be a single verifier or an aggregate verifier.
    ///   - verifier_id: The identity of the user to be queried against the verifier, this is usually an emal.
    ///   - extended_verifier_id: This is only used if querying a tss verifier, otherwise it is not supplied. Format is (verifierId + "\u{0015}" + tssTag + "\u{0016}" + randomNonce)
    ///
    /// - Returns: `TorusPublicKey`
    ///
    /// - Throws: `TorusUtilError`
    public func getUserTypeAndAddress(
        endpoints: [String],
        verifier: String,
        verifierId: String,
        extendedVerifierId: String? = nil
    ) async throws -> TorusPublicKey {
        return try await getNewPublicAddress(endpoints: endpoints, verifier: verifier, verifierId: verifierId, extendedVerifierId: extendedVerifierId, enableOneKey: true)
    }

    private func getNewPublicAddress(endpoints: [String], verifier: String, verifierId: String, extendedVerifierId: String? = nil, enableOneKey: Bool) async throws -> TorusPublicKey {
        let keyAssignResult = try await NodeUtils.getPubKeyOrKeyAssign(
            endpoints: endpoints,
            verifier: verifier,
            verifierId: verifierId,
            serverTimeOffset: serverTimeOffset,
            extendedVerifierId: extendedVerifierId,
            keyType: keyType
        )
        return try formatPublicKeyData(keyAssignResult: keyAssignResult, extendedVerifierId: extendedVerifierId, enableOneKey: enableOneKey)
    }

    internal func formatPublicKeyData(keyAssignResult: KeyLookupResult, extendedVerifierId: String?, enableOneKey: Bool) throws -> TorusPublicKey {
        if keyAssignResult.errorResult != nil {
            let error = keyAssignResult.errorResult!.message
            if error.lowercased().contains("verifier not supported") {
                throw TorusUtilError.runtime("Verifier not supported. Check if you: 1. Are on the right network (Torus testnet/mainnet) 2. Have setup a verifier on dashboard.web3auth.io?")
            } else {
                throw TorusUtilError.runtime(error)
            }
        }

        // no need of nonce for extendedVerifierId (tss verifier id)
        guard let assignedKey = keyAssignResult.keyResult?.keys.first else {
            throw TorusUtilError.runtime("node results do not match at final lookup")
        }
        let nonceResult = keyAssignResult.nonceResult
        if nonceResult == nil && extendedVerifierId == nil {
            throw TorusUtilError.runtime("metadata nonce is missing in share response")
        }

        let oAuthPoint = try Point(x: assignedKey.pub_key_X, y: assignedKey.pub_key_Y)
        var pubNonce: PubNonce?
        var nonce: BigUInt = BigUInt(nonceResult?.nonce ?? "0", radix: 16) ?? BigUInt(0)
        var typeOfUser: UserType = nonceResult?.typeOfUser == UserType.v1.rawValue ? .v1 : .v2
        let finalPoint: Point

        // 0 means unset, as in torus.js
        let finalServerTimeOffset = (serverTimeOffset ?? 0) != 0 ? serverTimeOffset! : keyAssignResult.serverTimeOffset

        if extendedVerifierId != nil {
            // for tss key no need to add pub nonce
            finalPoint = oAuthPoint
        } else if nonceResult?.typeOfUser == UserType.v1.rawValue {
            finalPoint = nonce > BigUInt(0)
                ? try KeyUtils.combinePublicPoints(
                    keyType: keyType,
                    first: oAuthPoint,
                    second: try KeyUtils.publicPoint(privateKey: nonce.serialize().hexString.addLeading0sForLength64(), keyType: keyType)
                )
                : oAuthPoint
        } else if network.isLegacy && !enableOneKey {
            // a legacy dApp without OneKey ignores a v2 nonce
            finalPoint = oAuthPoint
            nonce = BigUInt(0)
            typeOfUser = .v1
        } else {
            guard let pubNonceResult = nonceResult?.pubNonce, !pubNonceResult.x.isEmpty, !pubNonceResult.y.isEmpty else {
                throw TorusUtilError.pubNonceMissing
            }
            finalPoint = try KeyUtils.combinePublicPoints(
                keyType: keyType,
                first: oAuthPoint,
                second: try Point(x: pubNonceResult.x, y: pubNonceResult.y)
            )
            pubNonce = pubNonceResult
        }

        let oAuthPubKeyX = String(oAuthPoint.x, radix: 16).addLeading0sForLength64()
        let oAuthPubKeyY = String(oAuthPoint.y, radix: 16).addLeading0sForLength64()
        let oAuthAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: oAuthPubKeyX, publicKeyY: oAuthPubKeyY)

        let finalPubKeyX = String(finalPoint.x, radix: 16).addLeading0sForLength64()
        let finalPubKeyY = String(finalPoint.y, radix: 16).addLeading0sForLength64()
        let finalAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: finalPubKeyX, publicKeyY: finalPubKeyY)

        return TorusPublicKey(
            oAuthKeyData: TorusPublicKey.OAuthKeyData(
                evmAddress: oAuthAddress,
                X: oAuthPubKeyX,
                Y: oAuthPubKeyY
            ),
            finalKeyData: TorusPublicKey.FinalKeyData(
                evmAddress: finalAddress,
                X: finalPubKeyX,
                Y: finalPubKeyY
            ),
            metadata: TorusPublicKey.Metadata(
                pubNonce: pubNonce,
                nonce: nonce,
                typeOfUser: typeOfUser,
                upgraded: typeOfUser == .v2 ? (nonceResult?.upgraded ?? false) : false,
                serverTimeOffset: finalServerTimeOffset
            ),
            nodesData: TorusPublicKey.NodesData(
                nodeIndexes: keyAssignResult.nodeIndexes
            )
        )
    }
}
