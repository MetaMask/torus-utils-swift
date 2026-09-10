import Foundation

internal struct CommitmentRequestResult: Codable {
    public var signature: String
    public var data: String
    public var nodepubx: String
    public var nodepuby: String
    public var nodeindex: String
    public var pub_key_x: String?

    public init(data: String, nodepubx: String, nodepuby: String, signature: String, nodeindex: String, pub_key_x: String? = nil) {
        self.data = data
        self.nodepubx = nodepubx
        self.nodepuby = nodepuby
        self.signature = signature
        self.nodeindex = nodeindex
        self.pub_key_x = pub_key_x
    }
}
