import BigInt
import Foundation

internal struct PrivateKeyData {
    let oAuthKey: String
    let oAuthPubKey: String
    let nonce: String
    let signingKey: String
    let signingPubKey: String
    let finalKey: String
    let finalPubKey: String
    let encryptedSeed: String?
}
