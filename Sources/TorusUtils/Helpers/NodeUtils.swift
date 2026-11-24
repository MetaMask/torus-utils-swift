import BigInt
import FetchNodeDetails
import Foundation
import OSLog
#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

internal class NodeUtils {
    internal static var session = URLSession(configuration: .default)

    /// Picks the first node answer that carries a usable nonce.
    /// For a new key, a v1 answer counts only with a nonce, because a node that has not seen the first nonce write also answers v1.
    internal static func firstNodeNonce(_ nonceDatas: [GetOrSetNonceResult?], isNewKey: Bool) -> GetOrSetNonceResult? {
        return nonceDatas.first(where: { item in
            guard let item else { return false }
            let hasPubNonce = !(item.pubNonce?.x.isEmpty ?? true)
            let hasNonce = !(item.nonce?.isEmpty ?? true)
            return hasPubNonce || (item.typeOfUser == UserType.v1.rawValue && (hasNonce || !isNewKey))
        }) ?? nil
    }

    /// True when any node that agrees on the threshold public key says the key is new.
    internal static func isNewKeyResponse(_ shareResponses: [ShareRequestResult], thresholdPublicKey: KeyAssignment.PublicKey) -> Bool {
        return shareResponses.contains(where: {
            $0.isNewKey == "true" && $0.keys.first?.publicKey.X.lowercased() == thresholdPublicKey.X.lowercased()
        })
    }

    /// Nonce data from the first node that agrees on the threshold public key and carries a usable nonce.
    internal static func selectThresholdNonce(_ shareResponses: [ShareRequestResult], thresholdPublicKey: KeyAssignment.PublicKey, isNewKey: Bool) -> GetOrSetNonceResult? {
        let thresholdPubKeyX = thresholdPublicKey.X.addLeading0sForLength64().lowercased()
        let nonceDatas: [GetOrSetNonceResult?] = shareResponses.map({ item in
            guard let key = item.keys.first, key.publicKey.X.addLeading0sForLength64().lowercased() == thresholdPubKeyX else {
                return nil
            }
            return key.nonceData
        })
        return firstNodeNonce(nonceDatas, isNewKey: isNewKey)
    }

    public static func getPubKeyOrKeyAssign(
        endpoints: [String],
        verifier: String,
        verifierId: String,
        serverTimeOffset: Int? = nil,
        extendedVerifierId: String? = nil,
        keyType: TorusKeyType = .secp256k1) async throws -> KeyLookupResult {
        let threshold = Int(trunc(Double((endpoints.count / 2) + 1)))

        var params = GetOrSetKeyParams(distributed_metadata: true, verifier: verifier, verifier_id: verifierId, extended_verifier_id: extendedVerifierId, one_key_flow: true, fetch_node_index: true, client_time: String(Int(trunc(Double((serverTimeOffset ?? 0) + Int(Date().timeIntervalSince1970))))))
        params.key_type = keyType
        let jsonRPCRequest = JRPCRequest(
            method: JRPC_METHODS.GET_OR_SET_KEY,
            params: params
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let rpcdata = try encoder.encode(jsonRPCRequest)

        var nodeIndexes: [Int] = []

        let (keyResult, lookupResults, errorResult, nonceResult): (KeyLookupResult.KeyResult?, [JRPCResponse<VerifierLookupResponse>?], ErrorMessage?, GetOrSetNonceResult?) = try await withThrowingTaskGroup(of: JRPCResponse?.self, returning: (KeyLookupResult.KeyResult?, [JRPCResponse<VerifierLookupResponse>?], ErrorMessage?, GetOrSetNonceResult?).self) { group -> (KeyLookupResult.KeyResult?, [JRPCResponse<VerifierLookupResponse>?], ErrorMessage?, GetOrSetNonceResult?) in
            for endpoint in endpoints {
                group.addTask {
                    do {
                        var request = try MetadataUtils.makeUrlRequest(url: endpoint)
                        request.httpBody = rpcdata
                        let val = try await session.data(for: request)
                        let decoded = try JSONDecoder().decode(JRPCResponse<VerifierLookupResponse>.self, from: val.0)
                        return decoded
                    } catch {
                        return nil
                    }
                }
            }
            var collected = [JRPCResponse<VerifierLookupResponse>?]()
            var errorResult: ErrorMessage?
            var lookupPubKeys = [JRPCResponse<VerifierLookupResponse>?]()
            var keyResult: KeyLookupResult.KeyResult?
            var nonceResult: GetOrSetNonceResult?
            for try await value in group {
                collected.append(value)

                lookupPubKeys = collected.filter({ $0 != nil && $0?.error == nil && $0?.result != nil })

                errorResult = try thresholdSame(arr: collected.filter({ $0?.error != nil }).map { $0?.error }, threshold: threshold) as? ErrorMessage

                let normalizedKeyResults = lookupPubKeys.map({ normalizeKeysResult(result: ($0!.result)!) })

                keyResult = try thresholdSame(arr: normalizedKeyResults, threshold: threshold)

                // the metadata nonce comes only from the node responses, on every network
                if let thresholdKey = keyResult?.keys.first, nonceResult == nil, extendedVerifierId == nil {
                    let thresholdPubKeyX = thresholdKey.pub_key_X.addLeading0sForLength64().lowercased()
                    nonceResult = firstNodeNonce(
                        collected.map({ x1 in
                            guard let currentKey = x1?.error == nil ? x1?.result?.keys.first : nil,
                                  currentKey.pub_key_X.addLeading0sForLength64().lowercased() == thresholdPubKeyX
                            else {
                                return nil
                            }
                            return currentKey.nonce_data
                        }),
                        isNewKey: keyResult!.is_new_key
                    )
                }

                // keep reading node responses until one of them carries the nonce
                if (keyResult != nil && (nonceResult != nil || extendedVerifierId != nil)) || errorResult != nil {
                    group.cancelAll()
                    break
                }
            }
            return (keyResult, lookupPubKeys, errorResult, nonceResult)
        }

        // nonceResult must exist except for extendedVerifierId along with keyResult
        guard (keyResult != nil && (nonceResult != nil || extendedVerifierId != nil)) || errorResult != nil else {
            throw TorusUtilError.runtime("invalid public key result: nonce data found: \(nonceResult != nil), for verifier: \(verifier), verifierId: \(verifierId) and extendedVerifierId: \(extendedVerifierId ?? "")")
        }

        var serverTimeOffsets: [Int] = []
        if let thresholdKey = keyResult?.keys.first {
            for x1 in lookupResults {
                guard let result = x1?.result, let currentKey = result.keys.first else { continue }
                // push only those indexes for nodes who are returning pub key matching with threshold pub key.
                // this check is important when different nodes have different keys assigned to a user.
                if currentKey.pub_key_X.lowercased() == thresholdKey.pub_key_X.lowercased() {
                    if let nodeIndex = Int(result.node_index) {
                        nodeIndexes.append(nodeIndex)
                    }
                }
                serverTimeOffsets.append(Int(result.server_time_offset ?? "0") ?? 0)
            }
        }

        let serverTimeOffset = (keyResult != nil) ? calculateMedian(arr: serverTimeOffsets) : 0

        return KeyLookupResult(
            keyResult: keyResult,
            nodeIndexes: nodeIndexes,
            serverTimeOffset: serverTimeOffset,
            nonceResult: nonceResult,
            errorResult: errorResult)
    }

    public static func retrieveOrImportShare(
        serverTimeOffset: Int?,
        enableOneKey: Bool,
        network: Web3AuthNetwork,
        clientId: String,
        buildEnv: BuildEnv,
        endpoints: [String],
        indexes: [BigUInt],
        nodePubKeys: [TorusNodePubModel],
        verifier: String,
        verifierParams: VerifierParams,
        idToken: String,
        importedShares: [ImportedShare]?,
        overrideExistingKey: Bool,
        extraParams: TorusUtilsExtraParams,
        keyType: TorusKeyType,
        checkCommitment: Bool,
        recordId: String,
        source: String?
    ) async throws -> TorusKey {
        let threshold = Int(trunc(Double((endpoints.count / 2) + 1)))
        // a legacy dApp without OneKey uses the oAuth key itself, so its new keys store no nonce
        let legacyWithoutOneKey = network.isLegacy && !enableOneKey

        do {
            try await CitadelUtils.callAllowApi(params: CitadelAllowParams(
                buildEnv: buildEnv,
                verifier: verifier,
                verifierId: verifierParams.verifier_id,
                network: network.name,
                clientId: clientId,
                recordId: recordId,
                source: source,
                oauthInitiated: .set,
                oauthCompleted: .set
            ))
        } catch {
            os_log(
                "Failed to log initial Citadel allow API: %{public}@",
                log: getTorusLogger(log: TorusUtilsLogger.network, type: .error),
                type: .error,
                String(describing: error)
            )
        }

        let sessionAuthKey = SecretKey()
        let sessionAuthKeySerialized = try sessionAuthKey.serialize().addLeading0sForLength64()
        let pubKey = try sessionAuthKey.toPublic().serialize(compressed: false)
        let (pubX, pubY) = try KeyUtils.getPublicKeyCoords(pubKey: pubKey)

        let canGenerateShares = indexes.count == endpoints.count && nodePubKeys.count == endpoints.count
        var finalImportedShares: [ImportedShare] = []
        if let importedShares, !importedShares.isEmpty {
            if importedShares.count != endpoints.count {
                throw TorusUtilError.runtime("Invalid imported shares length")
            }
            finalImportedShares = importedShares
        } else if canGenerateShares {
            // new users always get a client-generated, imported key
            finalImportedShares = try KeyUtils.generateShares(
                keyType: keyType,
                serverTimeOffset: serverTimeOffset ?? 0,
                nodeIndexes: indexes,
                nodePubKeys: TorusNodePubModelToINodePub(nodes: nodePubKeys),
                privateKey: try KeyUtils.generateSecret(),
                withNonce: !legacyWithoutOneKey
            )
        }

        var nodeSigs: [CommitmentRequestResult] = []
        var isExistingKey = false
        if checkCommitment {
            nodeSigs = try await commitmentRequest(
                idToken: idToken,
                endpoints: endpoints,
                indexes: indexes,
                canGenerateShares: canGenerateShares,
                keyType: keyType,
                verifier: verifier,
                verifierParams: verifierParams,
                pubKeyX: pubX,
                pubKeyY: pubY,
                serverTimeOffset: serverTimeOffset,
                hasImportedShares: !finalImportedShares.isEmpty,
                overrideExistingKey: overrideExistingKey
            )
            // if user's account already
            isExistingKey = try thresholdSame(
                arr: nodeSigs.compactMap(\.pub_key_x).filter({ !$0.isEmpty }),
                threshold: threshold
            ) != nil
        } else if !overrideExistingKey {
            // in case not allowed to override existing key for import request, check if key exists
            isExistingKey = try await hasExistingKey(
                endpoints: endpoints,
                verifier: verifier,
                verifierId: verifierParams.verifier_id,
                keyType: keyType
            )
        }

        let canImportedShares = overrideExistingKey || !isExistingKey
        if canImportedShares && finalImportedShares.isEmpty {
            throw TorusUtilError.runtime("nodePubkeys and indexes are required to create a new key")
        }
        // a v1 import splits the key itself and stores no nonce
        let isV1Import = canImportedShares && legacyWithoutOneKey

        if checkCommitment && canImportedShares && nodeSigs.count != endpoints.count {
            throw TorusUtilError.commitmentRequestFailed
        }

        var thresholdNonceData: GetOrSetNonceResult?

        let sessionExpiry = extraParams.session_token_exp_second

        var shareResponses = [ShareRequestResult]()
        var thresholdPublicKey: KeyAssignment.PublicKey?

        if canImportedShares {
            var importedItems: [ShareRequestParams.ShareRequestItem] = []
            for j in 0 ..< endpoints.count {
                let importShare = finalImportedShares[j]

                let shareRequestItem = ShareRequestParams.ShareRequestItem(
                    verifieridentifier: verifier,
                    verifier_id: verifierParams.verifier_id,
                    extended_verifier_id: verifierParams.extended_verifier_id,
                    idtoken: idToken,
                    nodesignatures: nodeSigs,
                    pub_key_x: importShare.oauth_pub_key_x,
                    pub_key_y: importShare.oauth_pub_key_y,
                    signing_pub_key_x: importShare.signing_pub_key_x,
                    signing_pub_key_y: importShare.signing_pub_key_y,
                    encrypted_share: importShare.encryptedShare,
                    encrypted_share_metadata: importShare.encryptedShareMetadata,
                    encrypted_seed: importShare.encryptedSeed,
                    node_index: importShare.node_index,
                    key_type: importShare.key_type,
                    nonce_data: importShare.nonce_data,
                    nonce_signature: importShare.nonce_signature,
                    sub_verifier_ids: verifierParams.sub_verifier_ids,
                    session_token_exp_second: sessionExpiry,
                    verify_params: verifierParams.verify_params,
                    sss_endpoint: endpoints[j],
                    
                    nonce: extraParams.nonce,
                    message: extraParams.message,
                    signature: extraParams.signature,
                    clientDataJson: extraParams.clientDataJson,
                    authenticatorData: extraParams.authenticatorData,
                    publicKey: extraParams.publicKey,
                    challenge: extraParams.challenge,
                    rpOrigin: extraParams.rpOrigin,
                    rpId: extraParams.rpId,
                    timestamp: extraParams.timestamp
                )

                importedItems.append(shareRequestItem)
            }

            var params = ShareRequestParams(encrypted: "yes", item: importedItems, client_time: String(Int(trunc(Double((serverTimeOffset ?? 0) + Int(Date().timeIntervalSince1970))))))
            params.verifieridentifier = verifier
            params.temppubx = !checkCommitment && nodeSigs.isEmpty ? pubX : nil
            params.temppuby = !checkCommitment && nodeSigs.isEmpty ? pubY : nil
            params.key_type = keyType

            let jsonRPCRequest = JRPCRequest(
                method: JRPC_METHODS.IMPORT_SHARES,
                params: params
            )

            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            let rpcdata = try encoder.encode(jsonRPCRequest)
            var request = try MetadataUtils.makeUrlRequest(url: endpoints[Int(try getProxyCoordinatorEndpointIndex(endpoints: endpoints, verifier: verifier, verifierId: verifierParams.verifier_id))])
            request.httpBody = rpcdata
            let val = try await session.data(for: request)
            let decoded = try JSONDecoder().decode(JRPCResponse<[ShareRequestResult]>.self, from: val.0)
            guard decoded.error == nil, let result = decoded.result else {
                throw TorusUtilError.importShareFailed
            }

            shareResponses = result

            let pubkeys = shareResponses.filter({ $0.keys.count > 0 }).map { $0.keys[0].publicKey }

            thresholdPublicKey = try thresholdSame(arr: pubkeys, threshold: threshold)
        } else {
            (shareResponses, thresholdPublicKey) = try await withThrowingTaskGroup(of: JRPCResponse?.self, returning: ([ShareRequestResult], KeyAssignment.PublicKey?).self) {
                group -> ([ShareRequestResult], KeyAssignment.PublicKey?) in
                for i in 0 ..< endpoints.count {
                    group.addTask {
                        do {
                            let shareRequestItem = ShareRequestParams.ShareRequestItem(
                                verifieridentifier: verifier,
                                verifier_id: verifierParams.verifier_id,
                                extended_verifier_id: verifierParams.extended_verifier_id,
                                idtoken: idToken,
                                nodesignatures: nodeSigs,
                                key_type: keyType,
                                sub_verifier_ids: verifierParams.sub_verifier_ids,
                                session_token_exp_second: sessionExpiry,
                                verify_params: verifierParams.verify_params,
                                
                                nonce: extraParams.nonce,
                                message: extraParams.message,
                                signature: extraParams.signature,
                                clientDataJson: extraParams.clientDataJson,
                                authenticatorData: extraParams.authenticatorData,
                                publicKey: extraParams.publicKey,
                                challenge: extraParams.challenge,
                                rpOrigin: extraParams.rpOrigin,
                                rpId: extraParams.rpId
                            )

                            var params = ShareRequestParams(encrypted: "yes", item: [shareRequestItem], client_time: String(Int(trunc(Double((serverTimeOffset ?? 0) + Int(Date().timeIntervalSince1970))))))
                            params.verifieridentifier = verifier
                            params.temppubx = !checkCommitment && nodeSigs.isEmpty ? pubX : nil
                            params.temppuby = !checkCommitment && nodeSigs.isEmpty ? pubY : nil
                            params.key_type = keyType

                            let jsonRPCRequest = JRPCRequest(
                                method: JRPC_METHODS.GET_SHARE_OR_KEY_ASSIGN,
                                params: params
                            )

                            let encoder = JSONEncoder()
                            encoder.outputFormatting = .sortedKeys
                            let rpcdata = try encoder.encode(jsonRPCRequest)
                            var request = try MetadataUtils.makeUrlRequest(url: endpoints[i])
                            request.httpBody = rpcdata
                            let val = try await session.data(for: request)
                            let decoded = try JSONDecoder().decode(JRPCResponse<ShareRequestResult>.self, from: val.0)
                            return decoded
                        } catch {
                            return nil
                        }
                    }
                }

                var collected = [JRPCResponse<ShareRequestResult>?]()
                var shareResponses = [ShareRequestResult]()
                var thresholdPublicKey: KeyAssignment.PublicKey?
                for try await value in group {
                    collected.append(value)

                    shareResponses = collected.filter({ $0 != nil && $0!.error == nil && $0!.result != nil }).map({ $0!.result! })

                    let pubkeys = shareResponses.filter({ $0.keys.count > 0 }).map { $0.keys[0].publicKey }

                    thresholdPublicKey = try thresholdSame(arr: pubkeys, threshold: threshold)

                    if let thresholdPublicKey {
                        // keep reading node responses until one of them carries the nonce
                        if verifierParams.extended_verifier_id != nil || selectThresholdNonce(
                            shareResponses,
                            thresholdPublicKey: thresholdPublicKey,
                            isNewKey: isNewKeyResponse(shareResponses, thresholdPublicKey: thresholdPublicKey) && !isV1Import
                        ) != nil {
                            group.cancelAll()
                            break
                        }
                    }
                }

                return (shareResponses, thresholdPublicKey)
            }
        }

        guard let thresholdPublicKey else {
            throw TorusUtilError.retrieveOrImportShareError("invalid result from nodes, threshold number of public key results are not matching, please check configuration")
        }

        if verifierParams.extended_verifier_id == nil {
            // a v1 import stores no nonce, so its empty v1 answer is final
            let isNewKey = isNewKeyResponse(shareResponses, thresholdPublicKey: thresholdPublicKey)
            thresholdNonceData = selectThresholdNonce(shareResponses, thresholdPublicKey: thresholdPublicKey, isNewKey: isNewKey && !isV1Import)
        }

        var serverTimeOffsets: [String] = []
        for item in shareResponses {
            serverTimeOffsets.append(item.serverTimeOffset)
        }
        let serverOffsetTimes = serverTimeOffsets.map({ Int($0) ?? 0 })

        let serverTimeOffsetResponse: Int = serverTimeOffset ?? calculateMedian(arr: serverOffsetTimes)

        let thresholdReqCount = canImportedShares ? endpoints.count : threshold

        // the nonce must come from the nodes, except for an extended verifier id
        if !(shareResponses.count >= thresholdReqCount && (thresholdNonceData != nil || verifierParams.extended_verifier_id != nil)) {
            throw TorusUtilError.retrieveOrImportShareError("Invalid results, threshold pub key: \(thresholdPublicKey.X), nonce data found: \(thresholdNonceData != nil), extended verifierId: \(verifierParams.extended_verifier_id ?? "")")
        }

        var shares: [String?] = []
        var sessionTokenSigs: [String?] = []
        var sessionTokens: [String?] = []
        var nodeIndexes: [Int?] = []
        var sessionTokenDatas: [SessionToken?] = []

        for item in shareResponses {
            if !item.sessionTokenSigs.isEmpty {
                if !item.sessionTokenSigMetadata.isEmpty {
                    let decrypted = try MetadataUtils.decryptNodeData(eciesData: item.sessionTokenSigMetadata[0], ciphertextHex: item.sessionTokenSigs[0], privKey: sessionAuthKeySerialized)
                    sessionTokenSigs.append(decrypted)
                } else {
                    sessionTokenSigs.append(item.sessionTokenSigs[0])
                }
            } else {
                sessionTokenSigs.append(nil)
            }

            if !item.sessionTokens.isEmpty {
                if !item.sessionTokenMetadata.isEmpty {
                    let decrypted = try MetadataUtils.decryptNodeData(eciesData: item.sessionTokenMetadata[0], ciphertextHex: item.sessionTokens[0], privKey: sessionAuthKeySerialized)
                    sessionTokens.append(decrypted)
                } else {
                    sessionTokens.append(item.sessionTokens[0])
                }
            } else {
                sessionTokens.append(nil)
            }

            if !item.keys.isEmpty {
                let latestKey = item.keys[0]
                nodeIndexes.append(latestKey.nodeIndex)
                guard let cipherData = Data(base64Encoded: latestKey.share) else {
                    throw TorusUtilError.decodingFailed("cipher is not base64 encoded")
                }
                guard let cipherTextHex = String(data: cipherData, encoding: .utf8) else {
                    throw TorusUtilError.decodingFailed("cipherData is not utf8")
                }
                let decrypted = try MetadataUtils.decryptNodeData(eciesData: latestKey.shareMetadata, ciphertextHex: cipherTextHex, privKey: sessionAuthKeySerialized)
                shares.append(decrypted)
            } else {
                nodeIndexes.append(nil)
                shares.append(nil)
            }
        }

        let validSigs = sessionTokenSigs.filter({ $0 != nil }).map({ $0! })

        if verifierParams.extended_verifier_id == nil && validSigs.count < threshold {
            throw TorusUtilError.retrieveOrImportShareError("Insufficient number of signatures from nodes")
        }

        let validTokens = sessionTokens.filter({ $0 != nil }).map({ $0! })

        if verifierParams.extended_verifier_id == nil && validTokens.count < threshold {
            throw TorusUtilError.retrieveOrImportShareError("Insufficient number of signatures from nodes")
        }

        for (i, item) in sessionTokens.enumerated() {
            if item == nil {
                sessionTokenDatas.append(nil)
            } else {
                if Data(hexString: item!) != nil {
                    sessionTokenDatas.append(SessionToken(token: Data(hexString: item!)!.base64EncodedString(), signature: sessionTokenSigs[i]!, node_pubx: shareResponses[i].nodePubX, node_puby: shareResponses[i].nodePubY))
                } else {
                    sessionTokenDatas.append(SessionToken(token: item!, signature: sessionTokenSigs[i]!, node_pubx: shareResponses[i].nodePubX, node_puby: shareResponses[i].nodePubY))
                }
            }
        }

        var decryptedShares: [Int: String] = [:]
        for (i, item) in shares.enumerated() {
            if item != nil {
                decryptedShares.updateValue(item!, forKey: nodeIndexes[i]!)
            }
        }
        let elements = Array(0 ... decryptedShares.keys.max()!) // Note: torus.js has a bug that this line resolves

        let allCombis = kCombinations(elements: elements.slice, k: threshold)

        var privateKey: String?

        for j in 0 ..< allCombis.count {
            let currentCombi = allCombis[j]
            let currentCombiShares = decryptedShares.filter({ currentCombi.contains($0.key) })
            let shares = currentCombiShares.map({ $0.value })
            let indices = currentCombiShares.map({ $0.key })
            let derivedPrivateKey = try? Lagrange.lagrangeInterpolation(
                shares: shares,
                nodeIndex: indices,
                order: KeyUtils.getOrderOfCurve(keyType)
            )
            if derivedPrivateKey == nil {
                continue
            }
            let decryptedPoint = try KeyUtils.publicPoint(privateKey: derivedPrivateKey!, keyType: keyType)
            let decryptedPubKeyX = String(decryptedPoint.x, radix: 16).addLeading0sForLength64()
            let decryptedPubKeyY = String(decryptedPoint.y, radix: 16).addLeading0sForLength64()
            let thresholdPubKeyX = thresholdPublicKey.X.addLeading0sForLength64().lowercased()
            let thresholdPubKeyY = thresholdPublicKey.Y.addLeading0sForLength64().lowercased()
            if decryptedPubKeyX.lowercased() == thresholdPubKeyX && decryptedPubKeyY.lowercased() == thresholdPubKeyY {
                privateKey = derivedPrivateKey
                break
            }
        }

        if privateKey == nil {
            throw TorusUtilError.privateKeyDeriveFailed
        }

        let oAuthKey = privateKey!
        let oAuthPoint = try KeyUtils.publicPoint(privateKey: oAuthKey, keyType: keyType)
        let oAuthPublicKeyX = String(oAuthPoint.x, radix: 16).addLeading0sForLength64()
        let oAuthPublicKeyY = String(oAuthPoint.y, radix: 16).addLeading0sForLength64()
        let order = KeyUtils.getOrderOfCurve(keyType)
        var metadataNonce = BigInt(thresholdNonceData?.nonce?.addLeading0sForLength64() ?? "0", radix: 16) ?? BigInt(0)
        let finalPoint: Point
        var pubNonce: PubNonce?
        var typeOfUser: UserType = .v1
        // extended_verifier_id is only exception for torus-test-health verifier
        // otherwise extended verifier id should not even return shares.
        if verifierParams.extended_verifier_id != nil {
            typeOfUser = .v2
            // for tss key no need to add pub nonce
            finalPoint = oAuthPoint
        } else if thresholdNonceData?.typeOfUser == UserType.v1.rawValue {
            typeOfUser = .v1
            let privateKeyWithNonce = ((BigInt(oAuthKey.addLeading0sForLength64(), radix: 16) ?? BigInt(0)) + metadataNonce).modulus(order)
            finalPoint = try KeyUtils.publicPoint(privateKey: privateKeyWithNonce.magnitude.serialize().hexString.addLeading0sForLength64(), keyType: keyType)
        } else if legacyWithoutOneKey {
            // a legacy dApp without OneKey ignores a v2 nonce
            typeOfUser = .v1
            metadataNonce = BigInt(0)
            finalPoint = oAuthPoint
        } else {
            guard let nonceKey = thresholdNonceData?.pubNonce, !nonceKey.x.isEmpty, !nonceKey.y.isEmpty else {
                throw TorusUtilError.pubNonceMissing
            }
            typeOfUser = .v2
            finalPoint = try KeyUtils.combinePublicPoints(
                keyType: keyType,
                first: oAuthPoint,
                second: try Point(x: nonceKey.x, y: nonceKey.y)
            )
            pubNonce = PubNonce(x: nonceKey.x, y: nonceKey.y)
        }

        let oAuthKeyAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: oAuthPublicKeyX, publicKeyY: oAuthPublicKeyY)

        let finalPubX = String(finalPoint.x, radix: 16).addLeading0sForLength64()
        let finalPubY = String(finalPoint.y, radix: 16).addLeading0sForLength64()
        // deriving address from pub key coz pubkey is always available
        // but finalPrivKey won't be available for v2 user upgraded to 2/n
        let finalEvmAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: finalPubX, publicKeyY: finalPubY)

        var finalPrivKey = ""
        if typeOfUser == .v1 || (typeOfUser == .v2 && metadataNonce > BigInt(0)) {
            let privateKeyWithNonce = (
                (BigInt(oAuthKey.addLeading0sForLength64(), radix: 16) ?? BigInt(0)) + metadataNonce
            ).modulus(order)
            if keyType == .ed25519 {
                guard let encryptedSeed = thresholdNonceData?.seed, !encryptedSeed.isEmpty else {
                    throw TorusUtilError.runtime("Invalid data, seed data is missing for ed25519 key")
                }
                finalPrivKey = try MetadataUtils.decryptSeedData(
                    seedBase64: encryptedSeed,
                    finalUserKey: privateKeyWithNonce
                )
            } else {
                finalPrivKey = privateKeyWithNonce.magnitude.serialize().hexString.addLeading0sForLength64()
            }
        }

        var isUpgraded: Bool?
        if typeOfUser == .v2 {
            isUpgraded = metadataNonce == BigInt(0)
        }

        let postboxPrivateKey: String
        let postboxPoint: Point
        if keyType == .ed25519 {
            let scalar = try KeyUtils.getSecpKeyFromEd25519(
                BigInt(oAuthKey, radix: 16) ?? BigInt(0)
            )
            postboxPrivateKey = scalar.magnitude.serialize().hexString.addLeading0sForLength64()
            postboxPoint = try KeyUtils.publicPoint(
                privateKey: postboxPrivateKey,
                keyType: .secp256k1
            )
        } else {
            postboxPrivateKey = oAuthKey
            postboxPoint = oAuthPoint
        }

        return TorusKey(
            finalKeyData: TorusKey.FinalKeyData(
                evmAddress: finalEvmAddress,
                X: finalPubX,
                Y: finalPubY,
                privKey: finalPrivKey),
            oAuthKeyData: TorusKey.OAuthKeyData(
                evmAddress: oAuthKeyAddress,
                X: oAuthPublicKeyX,
                Y: oAuthPublicKeyY,
                privKey: oAuthKey),
            postboxKeyData: TorusKey.PostboxKeyData(
                X: String(postboxPoint.x, radix: 16).addLeading0sForLength64(),
                Y: String(postboxPoint.y, radix: 16).addLeading0sForLength64(),
                privKey: postboxPrivateKey
            ),
            sessionData: TorusKey.SessionData(
                sessionTokenData: sessionTokenDatas,
                sessionAuthKey: sessionAuthKeySerialized),
            metadata: TorusPublicKey.Metadata(
                pubNonce: pubNonce,
                nonce: metadataNonce.magnitude,
                typeOfUser: typeOfUser,
                upgraded: isUpgraded,
                serverTimeOffset: serverTimeOffsetResponse),
            nodesData: TorusKey.NodesData(
                nodeIndexes: nodeIndexes.filter({ $0 != nil }).map({ $0! })
            )
        )
    }

    private static func commitmentRequest(
        idToken: String,
        endpoints: [String],
        indexes: [BigUInt],
        canGenerateShares: Bool,
        keyType: TorusKeyType,
        verifier: String,
        verifierParams: VerifierParams,
        pubKeyX: String,
        pubKeyY: String,
        serverTimeOffset: Int?,
        hasImportedShares: Bool,
        overrideExistingKey: Bool
    ) async throws -> [CommitmentRequestResult] {
        let tokenCommitment = try KeyUtils.keccak256Data(idToken)
        let threeFourthsThreshold = Int(trunc(Double(endpoints.count * 3 / 4) + 1))
        let halfThreshold = Int(trunc(Double((endpoints.count / 2) + 1)))

        var params = CommitmentRequestParams(messageprefix: "mug00", tokencommitment: tokenCommitment, temppubx: pubKeyX, temppuby: pubKeyY, verifieridentifier: verifier, timestamp: String(BigUInt(trunc(Double((serverTimeOffset ?? 0) + Int(Date().timeIntervalSince1970)))), radix: 16))
        params.keytype = keyType
        params.verifier_id = verifierParams.verifier_id
        params.extended_verifier_id = verifierParams.extended_verifier_id

        let jsonRPCRequest = JRPCRequest(
            method: JRPC_METHODS.COMMITMENT_REQUEST,
            params: params
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let rpcdata = try encoder.encode(jsonRPCRequest)

        // the proxy node response is required only when the flow can import shares;
        // without node details there are no indexes to look it up by
        let requiredNodeIndex: String? = hasImportedShares && canGenerateShares
            ? String(indexes[Int(try getProxyCoordinatorEndpointIndex(endpoints: endpoints, verifier: verifier, verifierId: verifierParams.verifier_id))])
            : nil

        let (nodeSigs, satisfied) = try await withThrowingTaskGroup(of: JRPCResponse<CommitmentRequestResult>?.self, returning: ([CommitmentRequestResult], Bool).self) { group -> ([CommitmentRequestResult], Bool) in
            for endpoint in endpoints {
                group.addTask {
                    do {
                        var request = try MetadataUtils.makeUrlRequest(url: endpoint)
                        request.httpBody = rpcdata
                        let val = try await session.data(for: request)
                        return try JSONDecoder().decode(JRPCResponse<CommitmentRequestResult>.self, from: val.0)
                    } catch {
                        return nil
                    }
                }
            }
            var collected = [CommitmentRequestResult]()
            for try await value in group {
                guard let value, value.error == nil, let result = value.result else {
                    continue
                }
                collected.append(result)

                var done = false
                if hasImportedShares {
                    // for new imported keys registration we need to wait for all nodes to agree on commitment
                    // for fetching existing imported keys we can rely on threshold nodes commitment
                    if overrideExistingKey {
                        done = collected.count == endpoints.count
                    } else if collected.count >= threeFourthsThreshold {
                        let existingPubKey = try thresholdSame(
                            arr: collected.compactMap(\.pub_key_x).filter({ !$0.isEmpty }),
                            threshold: halfThreshold
                        )
                        // if not a existing key we need to wait for nodes to agree on commitment
                        if existingPubKey != nil || collected.count == endpoints.count {
                            done = requiredNodeIndex.map({ index in collected.contains(where: { $0.nodeindex == index }) }) ?? true
                        }
                    }
                } else {
                    done = collected.count >= threeFourthsThreshold
                }

                if done {
                    group.cancelAll()
                    return (collected, true)
                }
            }
            return (collected, false)
        }

        if !satisfied {
            throw TorusUtilError.commitmentRequestFailed
        }
        return nodeSigs
    }

    private struct VerifierLookupParams: Codable {
        let verifier: String
        let verifier_id: String
        let key_type: TorusKeyType
        let client_time: String
    }

    private static func hasExistingKey(
        endpoints: [String],
        verifier: String,
        verifierId: String,
        keyType: TorusKeyType
    ) async throws -> Bool {
        let request = JRPCRequest(
            method: "VerifierLookupRequest",
            params: VerifierLookupParams(
                verifier: verifier,
                verifier_id: verifierId,
                key_type: keyType,
                client_time: String(Int(Date().timeIntervalSince1970))
            )
        )
        let body = try JSONEncoder().encode(request)
        let responses = await withTaskGroup(of: JRPCResponse<VerifierLookupResponse>?.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    do {
                        var urlRequest = try MetadataUtils.makeUrlRequest(url: endpoint)
                        urlRequest.httpBody = body
                        let (data, _) = try await session.data(for: urlRequest)
                        return try JSONDecoder().decode(JRPCResponse<VerifierLookupResponse>.self, from: data)
                    } catch {
                        return nil
                    }
                }
            }
            var values = [JRPCResponse<VerifierLookupResponse>]()
            for await response in group {
                if let response {
                    values.append(response)
                }
            }
            return values
        }
        let normalized = responses.compactMap(\.result).map(normalizeKeysResult)
        return try thresholdSame(arr: normalized, threshold: endpoints.count / 2 + 1) != nil
    }
}
