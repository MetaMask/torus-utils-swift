import FetchNodeDetails
import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

public enum CitadelAllowParamsSetOrUnsetFlag: Int, Codable {
    case unset = 0
    case set = 1
}

public struct CitadelAuthFlowAuditParams: Codable {
    public var oauthInitiated: Bool?
    public var oauthVerified: Bool?
    public var oauthCompleted: Bool?
    public var oauthVerificationFailed: Bool?
    public var oauthFailed: Bool?

    public init(
        oauthInitiated: Bool? = nil,
        oauthVerified: Bool? = nil,
        oauthCompleted: Bool? = nil,
        oauthVerificationFailed: Bool? = nil,
        oauthFailed: Bool? = nil
    ) {
        self.oauthInitiated = oauthInitiated
        self.oauthVerified = oauthVerified
        self.oauthCompleted = oauthCompleted
        self.oauthVerificationFailed = oauthVerificationFailed
        self.oauthFailed = oauthFailed
    }
}

public struct CitadelAllowParams {
    public let buildEnv: BuildEnv
    public let verifier: String
    public let verifierId: String
    public let network: String
    public let clientId: String
    public let recordId: String
    public let source: String?
    public let oauthInitiated: CitadelAllowParamsSetOrUnsetFlag?
    public let oauthVerified: CitadelAllowParamsSetOrUnsetFlag?
    public let oauthCompleted: CitadelAllowParamsSetOrUnsetFlag?
    public let oauthVerificationFailed: CitadelAllowParamsSetOrUnsetFlag?
    public let oauthFailed: CitadelAllowParamsSetOrUnsetFlag?

    public init(
        buildEnv: BuildEnv,
        verifier: String,
        verifierId: String,
        network: String,
        clientId: String,
        recordId: String,
        source: String? = nil,
        oauthInitiated: CitadelAllowParamsSetOrUnsetFlag? = nil,
        oauthVerified: CitadelAllowParamsSetOrUnsetFlag? = nil,
        oauthCompleted: CitadelAllowParamsSetOrUnsetFlag? = nil,
        oauthVerificationFailed: CitadelAllowParamsSetOrUnsetFlag? = nil,
        oauthFailed: CitadelAllowParamsSetOrUnsetFlag? = nil
    ) {
        self.buildEnv = buildEnv
        self.verifier = verifier
        self.verifierId = verifierId
        self.network = network
        self.clientId = clientId
        self.recordId = recordId
        self.source = source
        self.oauthInitiated = oauthInitiated
        self.oauthVerified = oauthVerified
        self.oauthCompleted = oauthCompleted
        self.oauthVerificationFailed = oauthVerificationFailed
        self.oauthFailed = oauthFailed
    }
}

public struct CitadelAuditParams: Codable {
    public let recordId: String
    public let authConnection: String
    public let authConnectionId: String
    public let groupedAuthConnectionId: String
    public let oAuthUserId: String
    public let web3AuthNetwork: String
    public let web3AuthClientId: String
    public let oauthInitiated: Bool?
    public let oauthVerified: Bool?
    public let oauthCompleted: Bool?
    public let oauthVerificationFailed: Bool?
    public let oauthFailed: Bool?
}

public enum CitadelUtils {
    public static func buildAllowUrl(params: CitadelAllowParams) throws -> URL {
        guard let server = CITADEL_SERVER_MAP[params.buildEnv],
              var components = URLComponents(string: "\(server)/v1/signer/allow")
        else {
            throw TorusUtilError.configurationError
        }

        components.queryItems = [
            URLQueryItem(name: "recordid", value: params.recordId),
            URLQueryItem(name: "verifier", value: params.verifier),
            URLQueryItem(name: "verifierid", value: params.verifierId),
            URLQueryItem(name: "network", value: params.network),
            URLQueryItem(name: "clientid", value: params.clientId),
        ]
        if let source = params.source, !source.isEmpty {
            components.queryItems?.append(URLQueryItem(name: "source", value: source))
        }
        appendFlag("oauthInitiated", params.oauthInitiated, to: &components)
        appendFlag("oauthVerified", params.oauthVerified, to: &components)
        appendFlag("oauthCompleted", params.oauthCompleted, to: &components)
        appendFlag("oauthVerificationFailed", params.oauthVerificationFailed, to: &components)
        appendFlag("oauthFailed", params.oauthFailed, to: &components)

        guard let url = components.url else {
            throw TorusUtilError.configurationError
        }
        return url
    }

    public static func buildAuditPayload(
        network: Web3AuthNetwork,
        clientId: String,
        params: RetrieveSharesParams,
        recordId: String? = nil,
        authFlowAuditParams: CitadelAuthFlowAuditParams
    ) -> CitadelAuditParams {
        CitadelAuditParams(
            recordId: recordId ?? params.recordId ?? generateRecordId(),
            authConnection: params.authConnection,
            authConnectionId: params.verifierParams.sub_verifier_ids?.first ?? "",
            groupedAuthConnectionId: params.verifier,
            oAuthUserId: params.verifierParams.verifier_id,
            web3AuthNetwork: network.name,
            web3AuthClientId: clientId,
            oauthInitiated: authFlowAuditParams.oauthInitiated,
            oauthVerified: authFlowAuditParams.oauthVerified,
            oauthCompleted: authFlowAuditParams.oauthCompleted,
            oauthVerificationFailed: authFlowAuditParams.oauthVerificationFailed,
            oauthFailed: authFlowAuditParams.oauthFailed
        )
    }

    public static func callAllowApi(params: CitadelAllowParams) async throws {
        let (_, response) = try await URLSession.shared.data(from: buildAllowUrl(params: params))
        try validate(response)
    }

    public static func callAuditApi(buildEnv: BuildEnv, params: CitadelAuditParams) async throws {
        guard let server = CITADEL_SERVER_MAP[buildEnv],
              let url = URL(string: "\(server)/v1/auth/audit")
        else {
            throw TorusUtilError.configurationError
        }
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(params)
        let (_, response) = try await URLSession.shared.data(for: request)
        try validate(response)
    }

    public static func generateRecordId() -> String {
        UUID().uuidString.lowercased()
    }

    private static func appendFlag(
        _ name: String,
        _ flag: CitadelAllowParamsSetOrUnsetFlag?,
        to components: inout URLComponents
    ) {
        if let flag {
            components.queryItems?.append(URLQueryItem(name: name, value: String(flag.rawValue)))
        }
    }

    private static func validate(_ response: URLResponse) throws {
        guard let httpResponse = response as? HTTPURLResponse,
              (200 ..< 300).contains(httpResponse.statusCode)
        else {
            throw TorusUtilError.gatingError("Citadel request failed")
        }
    }
}
