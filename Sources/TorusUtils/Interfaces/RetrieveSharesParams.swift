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
        self.checkCommitment = checkCommitment
        self.recordId = recordId
        self.authConnection = authConnection
    }

    @available(*, deprecated, message: "useDkg was removed in v12 and is ignored: new users always get a client-generated, imported key. Use init without it.")
    public init(
        endpoints: [String],
        indexes: [BigUInt],
        nodePubKeys: [TorusNodePubModel],
        verifier: String,
        verifierParams: VerifierParams,
        idToken: String,
        extraParams: TorusUtilsExtraParams = TorusUtilsExtraParams(),
        useDkg: Bool?,
        checkCommitment: Bool = true,
        recordId: String? = nil,
        authConnection: String = ""
    ) {
        self.init(
            endpoints: endpoints,
            indexes: indexes,
            nodePubKeys: nodePubKeys,
            verifier: verifier,
            verifierParams: verifierParams,
            idToken: idToken,
            extraParams: extraParams,
            checkCommitment: checkCommitment,
            recordId: recordId,
            authConnection: authConnection
        )
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
