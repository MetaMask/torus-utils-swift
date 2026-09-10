import Foundation

internal struct GetNonceSetDataParams: Codable {
    public var data: String
}

internal struct GetNonceParams: Codable {
    public var pub_key_X: String
    public var pub_key_Y: String
    public var set_data: GetNonceSetDataParams
    public var key_type: TorusKeyType? = nil
}
