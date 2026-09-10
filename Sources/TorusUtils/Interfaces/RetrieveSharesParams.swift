import BigInt
import FetchNodeDetails
import Foundation

public struct RetrieveSharesParams {
    public let endpoints: [String]
    public let indexes: [BigUInt]
    public let nodePubKeys: [TorusNodePubModel]
    public let verifier: String
    public let verifierParams: VerifierParams
    public let idToken: String
    public let extraParams: TorusUtilsExtraParams
    public let useDkg: Bool?
    public let checkCommitment: Bool
    public let recordId: String?
    public let authConnection: String

    public init(
        endpoints: [String],
        indexes: [BigUInt],
        nodePubKeys: [TorusNodePubModel],
        verifier: String,
        verifierParams: VerifierParams,
        idToken: String,
        extraParams: TorusUtilsExtraParams = TorusUtilsExtraParams(),
        useDkg: Bool? = nil,
        checkCommitment: Bool = true,
        recordId: String? = nil,
        authConnection: String = ""
    ) {
        self.endpoints = endpoints
        self.indexes = indexes
        self.nodePubKeys = nodePubKeys
        self.verifier = verifier
        self.verifierParams = verifierParams
        self.idToken = idToken
        self.extraParams = extraParams
        self.useDkg = useDkg
        self.checkCommitment = checkCommitment
        self.recordId = recordId
        self.authConnection = authConnection
    }
}

public struct ImportPrivateKeyParams {
    public let endpoints: [String]
    public let nodeIndexes: [BigUInt]
    public let nodePubKeys: [TorusNodePubModel]
    public let verifier: String
    public let verifierParams: VerifierParams
    public let idToken: String
    public let newPrivateKey: String
    public let extraParams: TorusUtilsExtraParams
    public let checkCommitment: Bool
    public let recordId: String?

    public init(
        endpoints: [String],
        nodeIndexes: [BigUInt],
        nodePubKeys: [TorusNodePubModel],
        verifier: String,
        verifierParams: VerifierParams,
        idToken: String,
        newPrivateKey: String,
        extraParams: TorusUtilsExtraParams = TorusUtilsExtraParams(),
        checkCommitment: Bool = true,
        recordId: String? = nil
    ) {
        self.endpoints = endpoints
        self.nodeIndexes = nodeIndexes
        self.nodePubKeys = nodePubKeys
        self.verifier = verifier
        self.verifierParams = verifierParams
        self.idToken = idToken
        self.newPrivateKey = newPrivateKey
        self.extraParams = extraParams
        self.checkCommitment = checkCommitment
        self.recordId = recordId
    }
}
