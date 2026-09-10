import Foundation

internal struct GetOrSetNonceResult: Codable {
    public var typeOfUser: String?
    public var nonce: String?
    public var pubNonce: PubNonce?
    public var ifps: String?
    public var upgraded: Bool?
    public var seed: String?

    public init(typeOfUser: String, nonce: String? = nil, pubNonce: PubNonce? = nil, ifps: String? = nil, upgraded: Bool? = false, seed: String? = nil) {
        self.typeOfUser = typeOfUser
        self.nonce = nonce
        self.pubNonce = pubNonce
        self.ifps = ifps
        self.upgraded = upgraded
        self.seed = seed
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        typeOfUser = try container.decodeIfPresent(String.self, forKey: .typeOfUser)
        nonce = try container.decodeIfPresent(String.self, forKey: .nonce)
        pubNonce = try container.decodeIfPresent(PubNonce.self, forKey: .pubNonce)
        ifps = try container.decodeIfPresent(String.self, forKey: .ifps)
        upgraded = try container.decodeIfPresent(Bool.self, forKey: .upgraded)
        seed = try container.decodeIfPresent(String.self, forKey: .seed)
    }
}
