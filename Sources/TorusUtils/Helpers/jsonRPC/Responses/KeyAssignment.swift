import Foundation

internal struct KeyAssignment: Codable {
    let index: String
    let publicKey: PublicKey
    let threshold: Int
    let nodeIndex: Int
    let share: String
    let shareMetadata: EciesHexOmitCiphertext
    let nonceData: GetOrSetNonceResult?

    struct PublicKey: Hashable, Codable {
        let X: String
        let Y: String
        let SignerX: String?
        let SignerY: String?
    }

    enum CodingKeys: CodingKey {
        case index
        case public_key
        case threshold
        case node_index
        case share
        case share_metadata
        case nonce_data
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(index, forKey: .index)
        try container.encode(publicKey, forKey: .public_key)
        try container.encode(threshold, forKey: .threshold)
        try container.encode(nodeIndex, forKey: .node_index)
        try container.encode(share, forKey: .share)
        try container.encode(shareMetadata, forKey: .share_metadata)
        try container.encodeIfPresent(nonceData, forKey: .nonce_data)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        index = try container.decode(String.self, forKey: .index)

        publicKey = try container.decode(PublicKey.self, forKey: .public_key)
        threshold = Int(try container.decode(String.self, forKey: .threshold))!
        nodeIndex = Int(try container.decode(String.self, forKey: .node_index))!
        share = try container.decode(String.self, forKey: .share)
        shareMetadata = try container.decode(EciesHexOmitCiphertext.self, forKey: .share_metadata)
        nonceData = try container.decodeIfPresent(GetOrSetNonceResult.self, forKey: .nonce_data)
    }
}
