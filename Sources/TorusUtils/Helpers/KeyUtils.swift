import BigInt
import Foundation
#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

public enum TorusKeyType: String, Equatable, Hashable, Codable {
    case secp256k1
    case ed25519
}

public class KeyUtils {
    public static func keccak256Data(_ input: String) throws -> String {
        guard let data = input.data(using: .utf8) else { throw TorusUtilError.invalidInput }
        return try keccak256(data: data).toHexString()
    }

    public static func keccak256Data(_ data: Data) throws -> Data {
        return try keccak256(data: data)
    }

    public static func randomNonce() throws -> String {
        return try generateSecret()
    }

    public static func generateSecret() throws -> String {
        let secret = SecretKey()
        return try secret.serialize().addLeading0sForLength64()
    }

    internal static func getOrderOfCurve() -> BigInt {
        let orderHex = CURVE_N
        let order = BigInt(orderHex, radix: 16)!
        return order
    }

    internal static func getOrderOfCurve(_ keyType: TorusKeyType) -> BigInt {
        keyType == .ed25519 ? Ed25519Utils.scalarOrder : getOrderOfCurve()
    }

    internal static func getSecpKeyFromEd25519(_ scalar: BigInt) throws -> BigInt {
        let scalarHex = scalar.magnitude.serialize().hexString.addLeading0sForLength64()
        let hash = try keccak256Data(Data(hex: scalarHex))
        return BigInt(BigUInt(hash)).modulus(getOrderOfCurve())
    }

    internal static func generateAddressFromPubKey(publicKeyX: String, publicKeyY: String) throws -> String {
        let publicKeyHex = KeyUtils.getPublicKeyFromCoords(pubKeyX: publicKeyX, pubKeyY: publicKeyY, prefixed: false)
        let publicKeyData = Data(hex: publicKeyHex)
        let ethAddrData = try keccak256Data(publicKeyData).suffix(20)
        let ethAddrlower = ethAddrData.toHexString().addHexPrefix().lowercased()
        return try toChecksumAddress(hexAddress: ethAddrlower)
    }

    internal static func generateAddressFromPubKey(
        keyType: TorusKeyType,
        publicKeyX: String,
        publicKeyY: String
    ) throws -> String {
        if keyType == .secp256k1 {
            return try generateAddressFromPubKey(publicKeyX: publicKeyX, publicKeyY: publicKeyY)
        }
        return Ed25519Utils.address(try Point(x: publicKeyX, y: publicKeyY))
    }

    internal static func publicPoint(privateKey: String, keyType: TorusKeyType) throws -> Point {
        if keyType == .ed25519 {
            guard let scalar = BigInt(privateKey, radix: 16) else {
                throw TorusUtilError.invalidInput
            }
            return Ed25519Utils.point(fromScalar: scalar)
        }
        let publicKey = try SecretKey(hex: privateKey).toPublic().serialize(compressed: false)
        let (x, y) = try getPublicKeyCoords(pubKey: publicKey)
        return try Point(x: x, y: y)
    }

    internal static func combinePublicPoints(
        keyType: TorusKeyType,
        first: Point,
        second: Point
    ) throws -> Point {
        if keyType == .ed25519 {
            return Ed25519Utils.add(first, second)
        }
        let combined = try combinePublicKeys(keys: [
            getPublicKeyFromCoords(pubKeyX: String(first.x, radix: 16), pubKeyY: String(first.y, radix: 16)),
            getPublicKeyFromCoords(pubKeyX: String(second.x, radix: 16), pubKeyY: String(second.y, radix: 16)),
        ])
        let (x, y) = try getPublicKeyCoords(pubKey: combined)
        return try Point(x: x, y: y)
    }

    internal static func toChecksumAddress(hexAddress: String) throws -> String {
        let lowerCaseAddress = hexAddress.stripHexPrefix().lowercased()
        let arr = Array(lowerCaseAddress)
        let hash = try keccak256Data(lowerCaseAddress.data(using: .utf8) ?? Data()).toHexString()

        var result = String()
        for i in 0 ... lowerCaseAddress.count - 1 {
            let iIndex = hash.index(hash.startIndex, offsetBy: i)
            if let val = hash[iIndex].hexDigitValue, val >= 8 {
                result.append(arr[i].uppercased())
            } else {
                result.append(arr[i])
            }
        }
        return result.addHexPrefix()
    }

    public static func getPublicKeyCoords(pubKey: String) throws -> (String, String) {
        var publicKeyUnprefixed = pubKey
        if publicKeyUnprefixed.count > 128 {
            publicKeyUnprefixed = publicKeyUnprefixed.strip04Prefix()
        }
        

        if (publicKeyUnprefixed.count <= 128) {
            publicKeyUnprefixed = publicKeyUnprefixed.addLeading0sForLength128()
        } else {
            throw TorusUtilError.invalidPubKeySize
        }

        return (String(publicKeyUnprefixed.prefix(64)), String(publicKeyUnprefixed.suffix(64)))
    }

    public static func getPublicKeyFromCoords(pubKeyX: String, pubKeyY: String, prefixed: Bool = true) -> String {
        let X = pubKeyX.addLeading0sForLength64()
        let Y = pubKeyY.addLeading0sForLength64()

        return prefixed ? (X + Y).add04PrefixUnchecked() : X + Y
    }

    internal static func combinePublicKeys(keys: [String], compressed: Bool = false) throws -> String {
        var collection: [PublicKey] = []

        for item in keys {
            try collection.append(PublicKey(hex: item))
        }

        return try combinePublicKeys(keys: collection, compressed: compressed)
    }

    internal static func combinePublicKeys(keys: [PublicKey], compressed: Bool = false) throws -> String {
        let collection = PublicKeyCollection()
        for item in keys {
            try collection.insert(key: item)
        }

        let added = try PublicKey.combine(collection: collection).serialize(compressed: compressed)
        return added
    }

    internal static func generateKeyData(privateKey: String) throws -> PrivateKeyData {
        let scalar = BigInt(privateKey, radix: 16)!

        let randomNonce = BigInt(try SecretKey().serialize().addLeading0sForLength64(), radix: 16)!

        let oAuthKey = (scalar - randomNonce).modulus(KeyUtils.getOrderOfCurve())

        let oAuthPubKeyString = try SecretKey(hex: oAuthKey.magnitude.serialize().hexString.addLeading0sForLength64()).toPublic().serialize(compressed: false)

        let finalUserPubKey = try SecretKey(hex: privateKey).toPublic().serialize(compressed: false)

        return PrivateKeyData(
            oAuthKey: oAuthKey.magnitude.serialize().hexString.addLeading0sForLength64(),
            oAuthPubKey: oAuthPubKeyString,
            nonce: randomNonce.magnitude.serialize().hexString.addLeading0sForLength64(),
            signingKey: oAuthKey.magnitude.serialize().hexString.addLeading0sForLength64(),
            signingPubKey: oAuthPubKeyString,
            finalKey: privateKey,
            finalPubKey: finalUserPubKey,
            encryptedSeed: nil
        )
    }

    private struct EncryptedSeed: Codable {
        let enc_text: String
        let public_key: String
        let metadata: EciesHexOmitCiphertext
    }

    private static func generateEd25519KeyData(seedHex: String) throws -> PrivateKeyData {
        let seed = Data(hex: seedHex.addLeading0sForLength64())
        guard seed.count == 32 else {
            throw TorusUtilError.invalidKeySize
        }
        let finalScalar = try Ed25519Utils.scalar(fromSeed: seed)
        let metadataNonce = try Ed25519Utils.randomScalar()
        let oAuthKey = (finalScalar - metadataNonce).modulus(Ed25519Utils.scalarOrder)
        let oAuthPoint = Ed25519Utils.point(fromScalar: oAuthKey)
        let finalPoint = Ed25519Utils.point(fromScalar: finalScalar)

        let encryptionPrivateKey = try getSecpKeyFromEd25519(finalScalar)
        let encryptionPublicKey = try SecretKey(
            hex: encryptionPrivateKey.magnitude.serialize().hexString.addLeading0sForLength64()
        ).toPublic().serialize(compressed: true)
        let encrypted = try MetadataUtils.encrypt(
            publicKey: encryptionPublicKey,
            msg: seed.hexString
        )
        let encryptedSeed = EncryptedSeed(
            enc_text: encrypted.ciphertext,
            public_key: Ed25519Utils.encode(finalPoint).hexString,
            metadata: EciesHexOmitCiphertext(from: encrypted)
        )
        let encryptedSeedBase64 = try JSONEncoder().encode(encryptedSeed).base64EncodedString()
        let signingKey = try getSecpKeyFromEd25519(oAuthKey)
        let signingPubKey = try SecretKey(
            hex: signingKey.magnitude.serialize().hexString.addLeading0sForLength64()
        ).toPublic().serialize(compressed: false)

        return PrivateKeyData(
            oAuthKey: oAuthKey.magnitude.serialize().hexString.addLeading0sForLength64(),
            oAuthPubKey: pointHex(oAuthPoint),
            nonce: metadataNonce.magnitude.serialize().hexString.addLeading0sForLength64(),
            signingKey: signingKey.magnitude.serialize().hexString.addLeading0sForLength64(),
            signingPubKey: signingPubKey,
            finalKey: seed.hexString,
            finalPubKey: pointHex(finalPoint),
            encryptedSeed: encryptedSeedBase64
        )
    }

    private static func pointHex(_ point: Point) -> String {
        getPublicKeyFromCoords(
            pubKeyX: point.x.magnitude.serialize().hexString,
            pubKeyY: point.y.magnitude.serialize().hexString
        )
    }

    private static func generateNonceMetadataParams(
        operation: String,
        privateKey: BigInt,
        nonce: BigInt?,
        serverTimeOffset: Int?,
        keyType: TorusKeyType,
        seed: String?
    ) throws -> NonceMetadataParams {
        let privKey = try SecretKey(hex: privateKey.magnitude.serialize().hexString.addLeading0sForLength64())

        var setData = SetNonceData(
            operation: operation,
            timestamp: String(BigUInt(trunc(Double((serverTimeOffset ?? 0) + Int(Date().timeIntervalSince1970)))), radix: 16),
            seed: seed
        )

        if nonce != nil {
            setData.data = nonce!.magnitude.serialize().hexString.addLeading0sForLength64()
        }

        let publicKey = try privKey.toPublic().serialize(compressed: false)

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let encodedData = try encoder
            .encode(setData)

        let hash = try KeyUtils.keccak256Data(encodedData).toHexString()
        let sigData = try ECDSA.signRecoverable(key: privKey, hash: hash).serialize()
        _ = try ECDSA.recover(signature: Signature(hex: sigData), hash: hash)
        let (pubKeyX, pubKeyY) = try KeyUtils.getPublicKeyCoords(pubKey: publicKey)
        return .init(
            pub_key_X: pubKeyX,
            pub_key_Y: pubKeyY,
            setData: setData,
            encodedData: encodedData.base64EncodedString(),
            signature: Data(hex: sigData).base64EncodedString(),
            key_type: keyType,
            seed: seed
        )
    }

    internal static func generateShares(keyType: TorusKeyType = .secp256k1, serverTimeOffset: Int, nodeIndexes: [BigUInt], nodePubKeys: [INodePub], privateKey: String) throws -> [ImportedShare] {
        let keyData = try keyType == .ed25519
            ? generateEd25519KeyData(seedHex: privateKey)
            : generateKeyData(privateKey: privateKey)

        let threshold = Int(trunc(Double((nodePubKeys.count / 2) + 1)))
        let degree = threshold - 1
        let nodeIndexesBN = nodeIndexes.map({ BigInt($0) })
        let order = getOrderOfCurve(keyType)
        var coefficients = [BigInt(keyData.oAuthKey, radix: 16)!]
        for _ in 0 ..< degree {
            coefficients.append(keyType == .ed25519 ? try Ed25519Utils.randomScalar() : BigInt(try generateSecret(), radix: 16)!)
        }
        let shares = Dictionary(uniqueKeysWithValues: nodeIndexesBN.map { index in
            var result = BigInt(0)
            var power = BigInt(1)
            for coefficient in coefficients {
                result = (result + coefficient * power).modulus(order)
                power = (power * index).modulus(order)
            }
            return (
                index.magnitude.serialize().hexString.addLeading0sForLength64(),
                Share(shareIndex: index, share: result)
            )
        })
        let nonceParams = try KeyUtils.generateNonceMetadataParams(
            operation: "getOrSetNonce",
            privateKey: BigInt(keyData.signingKey, radix: 16)!,
            nonce: BigInt(keyData.nonce, radix: 16),
            serverTimeOffset: serverTimeOffset,
            keyType: keyType,
            seed: keyData.encryptedSeed
        )

        var encShares: [Ecies] = []
        for i in 0 ..< nodePubKeys.count {
            let shareInfo: Share = shares[nodeIndexes[i].magnitude.serialize().hexString.addLeading0sForLength64()]!

            let nodePub = KeyUtils.getPublicKeyFromCoords(pubKeyX: nodePubKeys[i].X, pubKeyY: nodePubKeys[i].Y)
            let nodePubKey = try PublicKey(hex: nodePub).serialize(compressed: true)
            let encrypted = try MetadataUtils.encrypt(publicKey: nodePubKey, msg: shareInfo.share.magnitude.serialize().hexString.addLeading0sForLength64())
            encShares.append(encrypted)
        }

        var sharesData: [ImportedShare] = []
        for i in 0 ..< nodePubKeys.count {
            let encrypted = encShares[i]
            let (oAuthPubX, oAuthPubY) = keyType == .ed25519
                ? try getPublicKeyCoords(pubKey: keyData.oAuthPubKey)
                : try getPublicKeyCoords(pubKey: try PublicKey(hex: keyData.oAuthPubKey).serialize(compressed: false))
            let (signingPubX, signingPubY) = try getPublicKeyCoords(pubKey: try PublicKey(hex: keyData.signingPubKey).serialize(compressed: false))
            let (finalPubX, finalPubY) = keyType == .ed25519
                ? try getPublicKeyCoords(pubKey: keyData.finalPubKey)
                : try getPublicKeyCoords(pubKey: try PublicKey(hex: keyData.finalPubKey).serialize(compressed: false))
            let finalPoint = try Point(x: finalPubX, y: finalPubY)
            let importShare = ImportedShare(
                oauth_pub_key_x: oAuthPubX,
                oauth_pub_key_y: oAuthPubY,
                final_user_point: finalPoint,
                signing_pub_key_x: signingPubX,
                signing_pub_key_y: signingPubY,
                encryptedShare: encrypted.ciphertext,
                encryptedShareMetadata: EciesHexOmitCiphertext(from: encrypted),
                encryptedSeed: keyData.encryptedSeed,
                node_index: Int(nodeIndexes[i].magnitude.serialize().hexString.addLeading0sForLength64(), radix: 16)!,
                key_type: keyType,
                nonce_data: nonceParams.encodedData,
                nonce_signature: nonceParams.signature)
            sharesData.append(importShare)
        }

        return sharesData
    }
}
