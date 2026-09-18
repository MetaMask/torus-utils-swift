import BigInt
import Foundation

public class TorusKey: Codable {
    public class FinalKeyData: Codable {
        public let evmAddress: String
        public let X: String
        public let Y: String
        public let privKey: String

        internal init(evmAddress: String, X: String, Y: String, privKey: String) {
            self.evmAddress = evmAddress
            self.X = X
            self.Y = Y
            self.privKey = privKey
        }
    }

    public class OAuthKeyData: Codable {
        public let evmAddress: String
        public let X: String
        public let Y: String
        public let privKey: String

        internal init(evmAddress: String, X: String, Y: String, privKey: String) {
            self.evmAddress = evmAddress
            self.X = X
            self.Y = Y
            self.privKey = privKey
        }
    }

    public class PostboxKeyData: Codable {
        public let X: String
        public let Y: String
        public let privKey: String

        internal init(X: String, Y: String, privKey: String) {
            self.X = X
            self.Y = Y
            self.privKey = privKey
        }
    }

    public class SessionData: Codable {
        public let sessionTokenData: [SessionToken?]
        public let sessionAuthKey: String

        internal init(sessionTokenData: [SessionToken?], sessionAuthKey: String) {
            self.sessionTokenData = sessionTokenData
            self.sessionAuthKey = sessionAuthKey
        }
    }

    public class NodesData: Codable {
        public let nodeIndexes: [Int]

        internal init(nodeIndexes: [Int]) {
            self.nodeIndexes = nodeIndexes
        }
    }

    internal init(finalKeyData: FinalKeyData,
                  oAuthKeyData: OAuthKeyData,
                  postboxKeyData: PostboxKeyData,
                  sessionData: SessionData,
                  metadata: TorusPublicKey.Metadata,
                  nodesData: NodesData) {
        self.finalKeyData = finalKeyData
        self.oAuthKeyData = oAuthKeyData
        self.postboxKeyData = postboxKeyData
        self.sessionData = sessionData
        self.metadata = metadata
        self.nodesData = nodesData
    }

    public let finalKeyData: FinalKeyData
    public let oAuthKeyData: OAuthKeyData
    public let postboxKeyData: PostboxKeyData
    public let sessionData: SessionData
    public let metadata: TorusPublicKey.Metadata
    public let nodesData: NodesData
}
