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

    var legacyMetadataHost: String

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

        let defaultHost: String
        if let configuredHost = params.legacyMetadataHost {
            defaultHost = configuredHost
        } else if params.network.isLegacy {
            guard let metadataHost = LEGACY_METADATA_MAP[params.buildEnv] else {
                throw TorusUtilError.configurationError
            }
            defaultHost = metadataHost
        } else {
            defaultHost = params.network == .SAPPHIRE_MAINNET
                ? "https://node-1.node.web3auth.io/metadata"
                : "https://node-1.dev-node.web3auth.io/metadata"
        }
        serverTimeOffset = params.serverTimeOffset
        network = params.network
        clientId = params.clientId
        buildEnv = params.buildEnv
        source = params.source
        keyType = params.keyType
        utilsLogType = loglevel
        enableOneKey = params.enableOneKey
        legacyMetadataHost = defaultHost
    }

    internal static func isLegacyNetworkRouteMap(network: Web3AuthNetwork) -> Bool {
        if network.isLegacy {
            return true
        }
        return false
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

        let shouldUseDkg: Bool
        if let requestedUseDkg = params.useDkg {
            if !requestedUseDkg, network.isLegacy {
                throw TorusUtilError.runtime("useDkg cannot be false for legacy network; \(network.name)")
            }
            shouldUseDkg = keyType == .ed25519 ? false : requestedUseDkg
        } else {
            shouldUseDkg = keyType == .secp256k1
        }

        if params.extraParams.session_token_exp_second == nil {
            params.extraParams.session_token_exp_second = sessionTime
        }

        let callerSuppliedRecordId = !(params.recordId?.isEmpty ?? true)
        let recordId = callerSuppliedRecordId ? params.recordId! : CitadelUtils.generateRecordId()

        do {
            let result = try await NodeUtils.retrieveOrImportShare(
                legacyMetadataHost: legacyMetadataHost,
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
                newPrivateKey: nil,
                extraParams: params.extraParams,
                keyType: keyType,
                useDkg: shouldUseDkg,
                checkCommitment: params.checkCommitment,
                recordId: recordId,
                source: source
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
            legacyMetadataHost: legacyMetadataHost,
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
            newPrivateKey: nil,
            extraParams: extraParams,
            keyType: keyType,
            useDkg: true,
            checkCommitment: true,
            recordId: CitadelUtils.generateRecordId(),
            source: source
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
        if network.isLegacy {
            throw TorusUtilError.legacyImportUnsupported(network.name)
        }

        let nodePubs = TorusNodePubModelToINodePub(nodes: params.nodePubKeys)
        if params.endpoints.count != params.nodeIndexes.count {
            throw TorusUtilError.runtime("Length of endpoints must be the same as length of nodeIndexes")
        }
        if params.endpoints.count != params.nodePubKeys.count {
            throw TorusUtilError.runtime("Length of endpoints must be the same as length of nodePubKeys")
        }

        let sharesData = try KeyUtils.generateShares(
            keyType: keyType,
            serverTimeOffset: serverTimeOffset ?? 0,
            nodeIndexes: params.nodeIndexes,
            nodePubKeys: nodePubs,
            privateKey: params.newPrivateKey
        )

        if params.extraParams.session_token_exp_second == nil {
            params.extraParams.session_token_exp_second = sessionTime
        }

        return try await NodeUtils.retrieveOrImportShare(
            legacyMetadataHost: legacyMetadataHost,
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
            newPrivateKey: params.newPrivateKey,
            extraParams: params.extraParams,
            keyType: keyType,
            useDkg: false,
            checkCommitment: params.checkCommitment,
            recordId: params.recordId ?? CitadelUtils.generateRecordId(),
            source: source
        )
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
                try await CitadelUtils.callAllowApi(params: params)
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
            network: network,
            verifier: verifier,
            verifierId: verifierId,
            legacyMetadataHost: legacyMetadataHost,
            serverTimeOffset: serverTimeOffset,
            extendedVerifierId: extendedVerifierId,
            keyType: keyType
        )

        if keyAssignResult.errorResult != nil {
            let error = keyAssignResult.errorResult!.message
            if error.lowercased().contains("verifier not supported") {
                throw TorusUtilError.runtime("Verifier not supported. Check if you: 1. Are on the right network (Torus testnet/mainnet) 2. Have setup a verifier on dashboard.web3auth.io?")
            } else {
                throw TorusUtilError.runtime(error)
            }
        }

        if keyAssignResult.keyResult == nil || keyAssignResult.keyResult?.keys.count == 0 {
            throw TorusUtilError.runtime("node results do not match at final lookup")
        }

        if keyAssignResult.nonceResult == nil && extendedVerifierId == nil && !TorusUtils.isLegacyNetworkRouteMap(network: network) {
            throw TorusUtilError.runtime("metadata nonce is missing in share response")
        }

        let pubKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: keyAssignResult.keyResult!.keys[0].pub_key_X, pubKeyY: keyAssignResult.keyResult!.keys[0].pub_key_Y)

        var pubNonce: PubNonce?
        let nonce: BigUInt = BigUInt(keyAssignResult.nonceResult?.nonce ?? "0", radix: 16) ?? BigUInt(0)

        var oAuthPubKey: String?
        var finalPubKey: String?

        let finalServerTimeOffset = serverTimeOffset ?? keyAssignResult.serverTimeOffset

        if extendedVerifierId != nil {
            finalPubKey = pubKey
            oAuthPubKey = finalPubKey
        } else if TorusUtils.isLegacyNetworkRouteMap(network: network) {
            let legacyKeysResult = keyAssignResult.keyResult!.keys.map({
                LegacyVerifierLookupResponse.Key(pub_key_X: $0.pub_key_X, pub_key_Y: $0.pub_key_Y, address: $0.address)
            })
            let legacyResult = LegacyVerifierLookupResponse(keys: legacyKeysResult, serverTimeOffset: String(finalServerTimeOffset))
            return try await formatLegacyPublicKeyData(finalKeyResult: legacyResult, enableOneKey: enableOneKey, isNewKey: keyAssignResult.keyResult!.is_new_key, serverTimeOffset: finalServerTimeOffset)
        } else {
            let X = keyAssignResult.keyResult!.keys[0].pub_key_X
            let Y = keyAssignResult.keyResult!.keys[0].pub_key_Y
            let oAuthPoint = try Point(x: X, y: Y)
            oAuthPubKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: X, pubKeyY: Y)
            finalPubKey = oAuthPubKey!
            if keyAssignResult.nonceResult!.pubNonce != nil && !(keyAssignResult.nonceResult!.pubNonce!.x.isEmpty || keyAssignResult.nonceResult!.pubNonce!.y.isEmpty) {
                let pubNonceResult = keyAssignResult.nonceResult!.pubNonce!
                let combined = try KeyUtils.combinePublicPoints(
                    keyType: keyType,
                    first: oAuthPoint,
                    second: try Point(x: pubNonceResult.x, y: pubNonceResult.y)
                )
                finalPubKey = KeyUtils.getPublicKeyFromCoords(
                    pubKeyX: String(combined.x, radix: 16),
                    pubKeyY: String(combined.y, radix: 16)
                )
                pubNonce = pubNonceResult
            } else {
                throw TorusUtilError.pubNonceMissing
            }
        }

        if oAuthPubKey == nil || finalPubKey == nil {
            throw TorusUtilError.privateKeyDeriveFailed
        }

        let (oAuthPubKeyX, oAuthPubKeyY) = try KeyUtils.getPublicKeyCoords(pubKey: oAuthPubKey!)
        let oAuthAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: oAuthPubKeyX, publicKeyY: oAuthPubKeyY)

        let (finalPubKeyX, finalPubKeyY) = try KeyUtils.getPublicKeyCoords(pubKey: finalPubKey!)
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
                typeOfUser: .v2,
                upgraded: keyAssignResult.nonceResult?.upgraded ?? false,
                serverTimeOffset: finalServerTimeOffset
            ),
            nodesData: TorusPublicKey.NodesData(
                nodeIndexes: keyAssignResult.nodeIndexes
            )
        )
    }

    internal func formatLegacyPublicKeyData(finalKeyResult: LegacyVerifierLookupResponse, enableOneKey: Bool, isNewKey: Bool, serverTimeOffset: Int) async throws -> TorusPublicKey {
        let firstResult = finalKeyResult.keys[0]
        let X = firstResult.pub_key_X
        let Y = firstResult.pub_key_Y

        var nonceResult: GetOrSetNonceResult?
        var finalPubKey: String?
        var nonce: BigUInt?
        var typeOfUser: UserType
        var pubNonce: PubNonce?

        let oAuthPubKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: X, pubKeyY: Y)

        let finalServertimeOffset = self.serverTimeOffset ?? serverTimeOffset

        if enableOneKey {
            nonceResult = try await MetadataUtils.getOrSetNonce(legacyMetadataHost: legacyMetadataHost, serverTimeOffset: finalServertimeOffset, X: X, Y: Y, getOnly: !isNewKey)
            nonce = BigUInt(nonceResult!.nonce ?? "0", radix: 16)
            typeOfUser = UserType(rawValue: nonceResult?.typeOfUser?.lowercased() ?? "v1")!

            if typeOfUser == .v1 {
                finalPubKey = oAuthPubKey
                nonce = try await MetadataUtils.getMetadata(legacyMetadataHost: legacyMetadataHost, params: GetMetadataParams(pub_key_X: X, pub_key_Y: Y))

                if nonce! > BigUInt(0) {
                    let noncePrivateKey = try SecretKey(hex: nonce!.magnitude.serialize().hexString.addLeading0sForLength64())
                    let noncePublicKey = try noncePrivateKey.toPublic().serialize(compressed: false)
                    finalPubKey = try KeyUtils.combinePublicKeys(keys: [finalPubKey!, noncePublicKey])
                }
            } else if typeOfUser == .v2 {
                let pubNonceKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: nonceResult!.pubNonce!.x, pubKeyY: nonceResult!.pubNonce!.y)
                finalPubKey = try KeyUtils.combinePublicKeys(keys: [oAuthPubKey, pubNonceKey])
                pubNonce = nonceResult!.pubNonce!
            } else {
                throw TorusUtilError.metadataNonceMissing
            }
        } else {
            typeOfUser = .v1
            finalPubKey = oAuthPubKey
            nonce = try await MetadataUtils.getMetadata(legacyMetadataHost: legacyMetadataHost, params: GetMetadataParams(pub_key_X: X, pub_key_Y: Y))

            if nonce! > BigUInt(0) {
                let noncePrivateKey = try SecretKey(hex: nonce!.magnitude.serialize().hexString.addLeading0sForLength64())
                let noncePublicKey = try noncePrivateKey.toPublic().serialize(compressed: false)
                finalPubKey = try KeyUtils.combinePublicKeys(keys: [finalPubKey!, noncePublicKey])
            }
        }

        let oAuthAddress = try KeyUtils.generateAddressFromPubKey(publicKeyX: X, publicKeyY: Y)

        if typeOfUser == .v2 && finalPubKey == nil {
            throw TorusUtilError.privateKeyDeriveFailed
        }

        let (finalPubKeyX, finalPubKeyY) = try KeyUtils.getPublicKeyCoords(pubKey: finalPubKey!)

        let finalAddress = try KeyUtils.generateAddressFromPubKey(publicKeyX: finalPubKeyX, publicKeyY: finalPubKeyY)

        return TorusPublicKey(
            oAuthKeyData: TorusPublicKey.OAuthKeyData(
                evmAddress: oAuthAddress,
                X: X.addLeading0sForLength64(),
                Y: Y.addLeading0sForLength64()
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
                upgraded: nonceResult?.upgraded ?? false,
                serverTimeOffset: finalServertimeOffset),
            nodesData: TorusPublicKey.NodesData(nodeIndexes: [])
        )
    }
}
