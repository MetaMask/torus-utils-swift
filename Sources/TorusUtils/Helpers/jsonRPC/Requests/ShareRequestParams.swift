import Foundation

internal struct ShareRequestParams: Codable {
    public struct ShareRequestItem: Codable {
        public var verifieridentifier: String
        public var verifier_id: String?
        public var extended_verifier_id: String?
        public var idtoken: String
        public var nodesignatures: [CommitmentRequestResult?]
        public var pub_key_x: String?
        public var pub_key_y: String?
        public var signing_pub_key_x: String?
        public var signing_pub_key_y: String?
        public var encrypted_share: String?
        public var encrypted_share_metadata: EciesHexOmitCiphertext?
        public var encrypted_seed: String? = nil
        public var node_index: Int?
        public var key_type: TorusKeyType?
        public var nonce_data: String?
        public var nonce_signature: String?
        public var sub_verifier_ids: [String]?
        public var session_token_exp_second: Int?
        public var verify_params: [VerifyParams?]?
        public var sss_endpoint: String?
        
        // TODO: This is a bit of a mess from here due to legacy reasons and should be cleaned up in future.
        // Note: Nil values by default are excluded from serialization
        var nonce: String? // farcaster
        var message: String? // farcaster
        var signature: String? // farcaster, passkey, webauthn
        var clientDataJson: String? // passkey, webauthn
        var authenticatorData: String? // passkey, webauthn
        var publicKey: String? // passkey, webauthn
        var challenge: String? // passkey, webauthn
        var rpOrigin: String? // passkey, webauthn
        var rpId: String? // passkey, webauthn
        var timestamp: Int? // Signature
    }

    public var encrypted: String = "yes"
    public var item: [ShareRequestItem]
    public var use_temp: Bool = true
    public var distributed_metadata: Bool = true
    public var one_key_flow: Bool = true
    public var client_time: String
    public var verifieridentifier: String? = nil
    public var temppubx: String? = nil
    public var temppuby: String? = nil
    public var key_type: TorusKeyType? = nil
}
