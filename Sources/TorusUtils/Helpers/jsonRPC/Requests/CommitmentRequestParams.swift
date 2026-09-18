import Foundation

internal struct CommitmentRequestParams: Codable {
    public var messageprefix: String
    public var tokencommitment: String
    public var temppubx: String
    public var temppuby: String
    public var verifieridentifier: String
    public var timestamp: String?
    public var keytype: TorusKeyType? = nil
    public var verifier_id: String? = nil
    public var extended_verifier_id: String? = nil
    public var is_import_key_flow: Bool = true
}
