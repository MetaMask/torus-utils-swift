import FetchNodeDetails
import Foundation

/// TorusOptions is a configuration class that is used to initialize `TorusUtils`.
public class TorusOptions {
    public var enableOneKey: Bool
    public var clientId: String
    public var network: Web3AuthNetwork
    public var buildEnv: BuildEnv
    public var source: String?
    public var keyType: TorusKeyType
    public var serverTimeOffset: Int
    public var legacyMetadataHost: String?

    /// Initializes TorusOptions
    ///
    /// - Parameters:
    ///   - clientId: The client identity.
    ///   - network: `TorusNetwork`. Please note that new users should be using .sapphire(.SAPPHIRE_MAINNET).
    ///   - legacyMetadataHost: The url of the metadata server, this only needs to be supplied if the default is not being used.
    ///   - serverTimeOffset: The offset from Coordinated Universal Time (UCT).
    ///   - enableOneKey: Use the oneKey flow.
    ///
    /// - Returns: `TorusOptions`
    public init(
        clientId: String,
        network: Web3AuthNetwork,
        buildEnv: BuildEnv = .production,
        legacyMetadataHost: String? = nil,
        serverTimeOffset: Int = 0,
        enableOneKey: Bool = false,
        source: String? = nil,
        keyType: TorusKeyType = .secp256k1
    ) {
        self.clientId = clientId
        self.enableOneKey = enableOneKey
        self.network = network
        self.buildEnv = buildEnv
        self.source = source
        self.keyType = keyType
        self.serverTimeOffset = serverTimeOffset
        self.legacyMetadataHost = legacyMetadataHost
    }
}
