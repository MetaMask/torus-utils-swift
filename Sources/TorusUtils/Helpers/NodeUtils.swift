import BigInt
import FetchNodeDetails
import Foundation
import OSLog
#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

internal class NodeUtils {
    public static func getPubKeyOrKeyAssign(
        endpoints: [String],
        network: Web3AuthNetwork,
        verifier: String,
        verifierId: String,
        legacyMetadataHost: String,
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

        var nonceResult: GetOrSetNonceResult?
        var nodeIndexes: [Int] = []

        let (keyResult, lookupResults, errorResult): (KeyLookupResult.KeyResult?, [JRPCResponse<VerifierLookupResponse>?], ErrorMessage?) = try await withThrowingTaskGroup(of: JRPCResponse?.self, returning: (KeyLookupResult.KeyResult?, [JRPCResponse<VerifierLookupResponse>?], ErrorMessage?).self) { group -> (KeyLookupResult.KeyResult?, [JRPCResponse<VerifierLookupResponse>?], ErrorMessage?) in
            for endpoint in endpoints {
                group.addTask {
                    do {
                        var request = try MetadataUtils.makeUrlRequest(url: endpoint)
                        request.httpBody = rpcdata
                        let val = try await URLSession(configuration: .default).data(for: request)
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
            for try await value in group {
                collected.append(value)

                lookupPubKeys = collected.filter({ $0 != nil && $0?.error == nil })

                errorResult = try thresholdSame(arr: collected.filter({ $0?.error != nil }).map { $0?.error }, threshold: threshold) as? ErrorMessage

                let normalizedKeyResults = lookupPubKeys.map({ normalizeKeysResult(result: ($0!.result)!) })

                keyResult = try thresholdSame(arr: normalizedKeyResults, threshold: threshold)

                if keyResult != nil {
                    group.cancelAll()
                }
            }
            return (keyResult, lookupPubKeys, errorResult)
        }

        let lookupHasUsablePublicNonce = nonceResult?.pubNonce.map {
            !$0.x.isEmpty && !$0.y.isEmpty
        } ?? false
        if keyResult != nil && !lookupHasUsablePublicNonce && extendedVerifierId == nil && !TorusUtils.isLegacyNetworkRouteMap(network: network) {
            for i in 0 ..< lookupResults.count {
                let x1 = lookupResults[i]
                if x1 != nil && x1?.error == nil {
                    let currentNodePubKeyX = x1!.result!.keys[0].pub_key_X.addLeading0sForLength64().lowercased()
                    let thresholdPubKeyX = keyResult!.keys[0].pub_key_X.addLeading0sForLength64().lowercased()
                    let pubNonce: PubNonce? = x1!.result!.keys[0].nonce_data?.pubNonce
                    if let pubNonce,
                       !pubNonce.x.isEmpty,
                       !pubNonce.y.isEmpty,
                       currentNodePubKeyX == thresholdPubKeyX
                    {
                        nonceResult = x1?.result?.keys[0].nonce_data
                        break
                    }
                }
            }

            let foundUsablePublicNonce = nonceResult?.pubNonce.map {
                !$0.x.isEmpty && !$0.y.isEmpty
            } ?? false
            if !foundUsablePublicNonce {
                let metadataNonce = try await MetadataUtils.getOrSetSapphireMetadataNonce(metadataHost: legacyMetadataHost, network: network, X: keyResult!.keys[0].pub_key_X, Y: keyResult!.keys[0].pub_key_Y, keyType: keyType)
                nonceResult = metadataNonce
                if nonceResult!.nonce != nil {
                    nonceResult!.nonce = nil
                }
            }
        }

        var serverTimeOffsets: [Int] = []
        if keyResult != nil && (nonceResult != nil || extendedVerifierId != nil || TorusUtils.isLegacyNetworkRouteMap(network: network) || errorResult != nil) {
            for i in 0 ..< lookupResults.count {
                let x1 = lookupResults[i]
                if x1 != nil && x1?.result != nil {
                    let currentNodePubKey = x1!.result!.keys[0].pub_key_X.lowercased()
                    let thresholdPubKey = keyResult!.keys[0].pub_key_X.lowercased()
                    if currentNodePubKey == thresholdPubKey {
                        let nodeIndex = Int(x1!.result!.node_index)
                        if nodeIndex != nil {
                            nodeIndexes.append(nodeIndex!)
                        }
                    }
                    let serverTimeOffset: Int = Int(x1!.result!.server_time_offset ?? "0")!
                    serverTimeOffsets.append(serverTimeOffset)
                }
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
        legacyMetadataHost: String,
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
        newPrivateKey: String?,
        extraParams: TorusUtilsExtraParams,
        keyType: TorusKeyType,
        useDkg: Bool,
        checkCommitment: Bool,
        recordId: String,
        source: String?
    ) async throws -> TorusKey {
        let threshold = Int(trunc(Double((endpoints.count / 2) + 1)))

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
        let tokenCommitment = try KeyUtils.keccak256Data(idToken)

        let callerImportedShares = !(importedShares?.isEmpty ?? true)
        var finalImportedShares = importedShares ?? []
        var finalPrivateKey = newPrivateKey
        if finalImportedShares.isEmpty && !useDkg {
            guard indexes.count == endpoints.count, nodePubKeys.count == endpoints.count else {
                throw TorusUtilError.runtime("indexes and nodePubKeys must match endpoints when useDkg is false")
            }
            finalPrivateKey = try KeyUtils.generateSecret()
            finalImportedShares = try KeyUtils.generateShares(
                keyType: keyType,
                serverTimeOffset: serverTimeOffset ?? 0,
                nodeIndexes: indexes,
                nodePubKeys: TorusNodePubModelToINodePub(nodes: nodePubKeys),
                privateKey: finalPrivateKey!
            )
        }

        var isImportShareReq = false
        var importedShareCount = 0
        if !finalImportedShares.isEmpty {
            if finalImportedShares.count != endpoints.count {
                throw TorusUtilError.importShareFailed
            }
            isImportShareReq = true
            importedShareCount = finalImportedShares.count
        }

        var nodeSigs: [CommitmentRequestResult] = []
        if checkCommitment {
            var params = CommitmentRequestParams(messageprefix: "mug00", tokencommitment: tokenCommitment, temppubx: pubX, temppuby: pubY, verifieridentifier: verifier, timestamp: String(BigUInt(trunc(Double((serverTimeOffset ?? 0) + Int(Date().timeIntervalSince1970)))), radix: 16))
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

            nodeSigs = try await withThrowingTaskGroup(of: JRPCResponse?.self, returning: [CommitmentRequestResult].self) { group -> [CommitmentRequestResult] in
                let minRequiredCommitmments = Int(trunc(Double(endpoints.count * 3 / 4) + 1))
                var received: Int = 0
                for endpoint in endpoints {
                    group.addTask {
                        do {
                            var request = try MetadataUtils.makeUrlRequest(url: endpoint)
                            request.httpBody = rpcdata
                            let val = try await URLSession(configuration: .default).data(for: request)
                            let decoded = try JSONDecoder().decode(JRPCResponse<CommitmentRequestResult>.self, from: val.0)
                            return decoded
                        } catch {
                            return nil
                        }
                    }
                }
                var collected = [CommitmentRequestResult]()
                for try await value in group {
                    if value != nil && value?.error == nil {
                        collected.append(value!.result!)
                        received += 1
                        if !isImportShareReq, received >= minRequiredCommitmments {
                            group.cancelAll()
                        }
                    } else if isImportShareReq {
                        // cannot continue, all must pass for import
                        group.cancelAll()
                    }
                }
                return collected
            }
        }

        if !callerImportedShares, !useDkg, checkCommitment {
            let existingPublicKey = try thresholdSame(
                arr: nodeSigs.compactMap(\.pub_key_x),
                threshold: threshold
            )
            if existingPublicKey != nil {
                isImportShareReq = false
                importedShareCount = 0
                finalPrivateKey = nil
            }
        } else if !callerImportedShares, !useDkg, !checkCommitment,
                  try await hasExistingKey(
                      endpoints: endpoints,
                      verifier: verifier,
                      verifierId: verifierParams.verifier_id,
                      keyType: keyType
                  )
        {
            isImportShareReq = false
            importedShareCount = 0
            finalPrivateKey = nil
        }

        if checkCommitment && importedShareCount > 0 && nodeSigs.count != endpoints.count {
            throw TorusUtilError.commitmentRequestFailed
        }

        var thresholdNonceData: GetOrSetNonceResult?

        let sessionExpiry = extraParams.session_token_exp_second

        var shareImportSuccess = false

        var shareResponses = [ShareRequestResult]()
        var thresholdPublicKey: KeyAssignment.PublicKey?

        if isImportShareReq {
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
            let val = try await URLSession(configuration: .default).data(for: request)
            let decoded = try JSONDecoder().decode(JRPCResponse<[ShareRequestResult]>.self, from: val.0)
            if decoded.error == nil {
                shareImportSuccess = true
            }

            if isImportShareReq && !shareImportSuccess {
                throw TorusUtilError.importShareFailed
            }

            shareResponses = decoded.result!

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
                            let val = try await URLSession(configuration: .default).data(for: request)
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

                    shareResponses = collected.filter({ $0 != nil && $0!.result != nil }).map({ $0!.result! })

                    let pubkeys = shareResponses.filter({ $0.keys.count > 0 }).map { $0.keys[0].publicKey }

                    thresholdPublicKey = try thresholdSame(arr: pubkeys, threshold: threshold)

                    if thresholdPublicKey != nil {
                        group.cancelAll()
                    }
                }

                return (shareResponses, thresholdPublicKey)
            }
        }

        if thresholdPublicKey == nil {
            throw TorusUtilError.retrieveOrImportShareError("invalid result from nodes, threshold number of public key results are not matching, please check configuration")
        }

        for item in shareResponses {
            if thresholdNonceData == nil && verifierParams.extended_verifier_id == nil {
                let currentPubKeyX = item.keys[0].publicKey.X.addLeading0sForLength64().lowercased()
                let thesholdPubKeyX = thresholdPublicKey!.X.addLeading0sForLength64().lowercased()
                let pubNonce: PubNonce? = item.keys[0].nonceData?.pubNonce
                if pubNonce != nil && currentPubKeyX == thesholdPubKeyX {
                    thresholdNonceData = item.keys[0].nonceData
                }
            }
        }

        var serverTimeOffsets: [String] = []
        for item in shareResponses {
            serverTimeOffsets.append(item.serverTimeOffset)
        }
        let serverOffsetTimes = serverTimeOffsets.map({ Int($0) ?? 0 })

        let serverTimeOffsetResponse: Int = serverTimeOffset ?? calculateMedian(arr: serverOffsetTimes)

        let hasUsablePublicNonce = thresholdNonceData?.pubNonce.map {
            !$0.x.isEmpty && !$0.y.isEmpty
        } ?? false
        if !hasUsablePublicNonce && verifierParams.extended_verifier_id == nil && !TorusUtils.isLegacyNetworkRouteMap(network: network) {
            let metadataNonce = try await MetadataUtils.getOrSetSapphireMetadataNonce(metadataHost: legacyMetadataHost, network: network, X: thresholdPublicKey!.X, Y: thresholdPublicKey!.Y, serverTimeOffset: serverTimeOffsetResponse, getOnly: false, keyType: keyType)
            thresholdNonceData = metadataNonce
        }

        let thresholdReqCount = isImportShareReq ? endpoints.count : threshold

        // Invert comparision to return error early
        if !(shareResponses.count >= thresholdReqCount && thresholdPublicKey != nil && (thresholdNonceData != nil || verifierParams.extended_verifier_id != nil || TorusUtils.isLegacyNetworkRouteMap(network: network))) {
            throw TorusUtilError.retrieveOrImportShareError("invalid result from nodes, threshold number of public key results are not matching")
        }

        var shares: [String?] = []
        var sessionTokenSigs: [String?] = []
        var sessionTokens: [String?] = []
        var nodeIndexes: [Int?] = []
        var sessionTokenDatas: [SessionToken?] = []
        var isNewKeys: [IsNewKeyResponse] = []

        for item in shareResponses {
            isNewKeys.append(IsNewKeyResponse(isNewKey: item.isNewKey == "true", publicKeyX: item.keys.first?.publicKey.X ?? ""))

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
            let thresholdPubKeyX = thresholdPublicKey!.X.addLeading0sForLength64().lowercased()
            let thresholdPubKeyY = thresholdPublicKey!.Y.addLeading0sForLength64().lowercased()
            if decryptedPubKeyX.lowercased() == thresholdPubKeyX && decryptedPubKeyY.lowercased() == thresholdPubKeyY {
                privateKey = derivedPrivateKey
                break
            }
        }

        if privateKey == nil {
            throw TorusUtilError.privateKeyDeriveFailed
        }

        var isNewKey = false;
        for item in isNewKeys {
            if (item.isNewKey && item.publicKeyX.lowercased() == thresholdPublicKey!.X.lowercased()) {
                isNewKey = true
            }
        }

        let oAuthKey = privateKey!
        let oAuthPoint = try KeyUtils.publicPoint(privateKey: oAuthKey, keyType: keyType)
        let oAuthPublicKeyX = String(oAuthPoint.x, radix: 16).addLeading0sForLength64()
        let oAuthPublicKeyY = String(oAuthPoint.y, radix: 16).addLeading0sForLength64()
        var metadataNonce = BigInt(thresholdNonceData?.nonce?.addLeading0sForLength64() ?? "0", radix: 16) ?? BigInt(0)
        var finalPubKey: String?
        var pubNonce: PubNonce?
        var typeOfUser: UserType = .v1
        if verifierParams.extended_verifier_id != nil {
            typeOfUser = .v2
            finalPubKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: oAuthPublicKeyX, pubKeyY: oAuthPublicKeyY)
        } else if TorusUtils.isLegacyNetworkRouteMap(network: network) {
            if enableOneKey {
                let nonce = try await MetadataUtils.getOrSetNonce(legacyMetadataHost: legacyMetadataHost, serverTimeOffset: serverTimeOffsetResponse, X: thresholdPublicKey!.X, Y: thresholdPublicKey!.Y, privateKey: oAuthKey, getOnly: !isNewKey)
                metadataNonce = BigInt(nonce.nonce?.addLeading0sForLength64() ?? "0", radix: 16) ?? BigInt(0)
                typeOfUser = UserType(rawValue: nonce.typeOfUser?.lowercased() ?? "v1")!
                if typeOfUser == .v2 {
                    pubNonce = nonce.pubNonce
                    let publicNonce = KeyUtils.getPublicKeyFromCoords(pubKeyX: pubNonce!.x, pubKeyY: pubNonce!.y)
                    let oAuthPublicKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: oAuthPublicKeyX, pubKeyY: oAuthPublicKeyY)
                    finalPubKey = try KeyUtils.combinePublicKeys(keys: [oAuthPublicKey, publicNonce])
                } else {
                    typeOfUser = .v1
                    metadataNonce = BigInt(try await MetadataUtils.getMetadata(legacyMetadataHost: legacyMetadataHost, params: GetMetadataParams(pub_key_X: oAuthPublicKeyX, pub_key_Y: oAuthPublicKeyY)))
                    let privateKeyWithNonce = (BigInt(oAuthKey.addLeading0sForLength64(), radix: 16)! + BigInt(metadataNonce)).modulus(KeyUtils.getOrderOfCurve())
                    finalPubKey = try SecretKey(hex: privateKeyWithNonce.magnitude.serialize().hexString.addLeading0sForLength64()).toPublic().serialize(compressed: false)
                }
            } else {
                typeOfUser = .v1
                metadataNonce = BigInt(try await MetadataUtils.getMetadata(legacyMetadataHost: legacyMetadataHost, params: GetMetadataParams(pub_key_X: oAuthPublicKeyX, pub_key_Y: oAuthPublicKeyY)))
                let privateKeyWithNonce = (BigInt(oAuthKey.addLeading0sForLength64(), radix: 16)! + BigInt(metadataNonce)).modulus(KeyUtils.getOrderOfCurve())
                finalPubKey = try SecretKey(hex: privateKeyWithNonce.magnitude.serialize().hexString.addLeading0sForLength64()).toPublic().serialize(compressed: false)
            }
        } else {
            typeOfUser = .v2
            let oAuthPubKey = KeyUtils.getPublicKeyFromCoords(pubKeyX: oAuthPublicKeyX, pubKeyY: oAuthPublicKeyY)
            finalPubKey = oAuthPubKey
            if thresholdNonceData!.pubNonce != nil && !(thresholdNonceData!.pubNonce!.x.isEmpty || thresholdNonceData!.pubNonce!.y.isEmpty) {
                let pubNonceKey = thresholdNonceData!.pubNonce!
                let combined = try KeyUtils.combinePublicPoints(
                    keyType: keyType,
                    first: oAuthPoint,
                    second: try Point(x: pubNonceKey.x, y: pubNonceKey.y)
                )
                finalPubKey = KeyUtils.getPublicKeyFromCoords(
                    pubKeyX: String(combined.x, radix: 16),
                    pubKeyY: String(combined.y, radix: 16)
                )
                pubNonce = PubNonce(x: thresholdNonceData!.pubNonce!.x, y: thresholdNonceData!.pubNonce!.y)
            } else {
                throw TorusUtilError.pubNonceMissing
            }
        }

        if finalPubKey == nil {
            throw TorusUtilError.retrieveOrImportShareError("Invalid public key, this might be a bug, please report this to web3auth team")
        }

        let oAuthKeyAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: oAuthPublicKeyX, publicKeyY: oAuthPublicKeyY)

        let (finalPubX, finalPubY) = try KeyUtils.getPublicKeyCoords(pubKey: finalPubKey!)
        let finalEvmAddress = try KeyUtils.generateAddressFromPubKey(keyType: keyType, publicKeyX: finalPubX, publicKeyY: finalPubY)

        var finalPrivKey = ""
        if typeOfUser == .v1 || (typeOfUser == .v2 && metadataNonce > BigInt(0)) {
            let privateKeyWithNonce = (
                (BigInt(oAuthKey.addLeading0sForLength64(), radix: 16) ?? BigInt(0)) + metadataNonce
            ).modulus(KeyUtils.getOrderOfCurve(keyType))
            if keyType == .ed25519 {
                guard let encryptedSeed = thresholdNonceData?.seed else {
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

        // This is a sanity check to make doubly sure we are returning the correct private key after importing a share
        if callerImportedShares {
            if finalPrivateKey == nil {
                throw TorusUtilError.importShareFailed
            } else if finalPrivKey != finalPrivateKey!.addLeading0sForLength64() {
                throw TorusUtilError.importShareFailed
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
                        let (data, _) = try await URLSession.shared.data(for: urlRequest)
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
