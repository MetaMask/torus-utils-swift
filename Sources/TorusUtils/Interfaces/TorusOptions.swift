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

    /// Initializes TorusOptions
    ///
    /// - Parameters:
    ///   - clientId: The client identity.
    ///   - network: `TorusNetwork`. Please note that new users should be using .sapphire(.SAPPHIRE_MAINNET).
    ///   - serverTimeOffset: The offset from Coordinated Universal Time (UCT).
    ///   - enableOneKey: Use the oneKey flow.
    ///
    /// - Returns: `TorusOptions`
    public init(
        clientId: String,
        network: Web3AuthNetwork,
        buildEnv: BuildEnv = .production,
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
    }

    @available(*, deprecated, message: "legacyMetadataHost was removed in v12 and is ignored: the metadata nonce now comes only from the node responses. Use init without it.")
    public convenience init(
        clientId: String,
        network: Web3AuthNetwork,
        buildEnv: BuildEnv = .production,
        legacyMetadataHost: String?,
        serverTimeOffset: Int = 0,
        enableOneKey: Bool = false,
        source: String? = nil,
        keyType: TorusKeyType = .secp256k1
    ) {
        self.init(
            clientId: clientId,
            network: network,
            buildEnv: buildEnv,
            serverTimeOffset: serverTimeOffset,
            enableOneKey: enableOneKey,
            source: source,
            keyType: keyType
        )
    }
}
