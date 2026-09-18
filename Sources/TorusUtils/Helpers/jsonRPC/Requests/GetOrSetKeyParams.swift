import Foundation

internal struct GetOrSetKeyParams: Codable {
    public var distributed_metadata: Bool
    public var verifier: String
    public var verifier_id: String
    public var extended_verifier_id: String?
    public var one_key_flow: Bool
    public var fetch_node_index: Bool
    public var client_time: String
    public var key_type: TorusKeyType? = nil
}
