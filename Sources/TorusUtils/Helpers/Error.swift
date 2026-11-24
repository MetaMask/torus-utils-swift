import Foundation

public enum TorusUtilError: Error, Equatable {
    case configurationError
    case encodingFailed(String = "")
    case decodingFailed(String = "")
    case commitmentRequestFailed
    case importShareFailed
    case decryptionFailed
    case privateKeyDeriveFailed
    case interpolationFailed
    case invalidKeySize
    case invalidPubKeySize
    case runtime(_ msg: String)
    case retrieveOrImportShareError(_ msg: String)
    case metadataNonceMissing
    case pubNonceMissing
    case gatingError(_ msg: String = "")
    case invalidInput
}

extension TorusUtilError: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self {
        case .configurationError:
            return "SDK Configuration incorrect. Network is probably incorrect"
        case let .decodingFailed(response):
            return "JSON Decoding error" + response
        case .decryptionFailed:
            return "Decryption Failed"
        case .commitmentRequestFailed:
            return "commitment request failed"
        case .importShareFailed:
            return "import share failed"
        case .privateKeyDeriveFailed:
            return "could not derive private key"
        case .interpolationFailed:
            return "lagrange interpolation failed"
        case .invalidInput:
            return "Input was found to be invalid"
        case let .runtime(msg):
            return msg
        case .invalidKeySize:
            return "Invalid key size. Expected 32 bytes"
        case .invalidPubKeySize:
            return "Invalid key size. Expected 64 bytes"
        case let .encodingFailed(msg):
            return "Could not encode data" + msg
        case let .retrieveOrImportShareError(msg):
            return msg
        case .metadataNonceMissing:
            return "Unable to fetch metadata nonce"
        case let .gatingError(msg):
            return "could not process request" + msg
        case .pubNonceMissing:
            return "Public nonce is missing"
        }
    }

    public static func == (lhs: TorusUtilError, rhs: TorusUtilError) -> Bool {
        guard type(of: lhs) == type(of: rhs) else { return false }
        let error1 = lhs as NSError
        let error2 = rhs as NSError
        return error1.debugDescription == error2.debugDescription && "\(lhs)" == "\(rhs)"
    }
}

extension TorusUtilError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .configurationError:
            return "SDK Configuration incorrect. Network is probably incorrect"
        case let .decodingFailed(response):
            return "JSON Decoding error" + response
        case .decryptionFailed:
            return "Decryption Failed"
        case .commitmentRequestFailed:
            return "commitment request failed"
        case .interpolationFailed:
            return "lagrange interpolation failed"
        case .invalidInput:
            return "Input was found to be invalid"
        case let .runtime(msg):
            return msg
        case .invalidKeySize:
            return "Invalid key size. Expected 32 bytes"
        case let .encodingFailed(msg):
            return "Could not encode data " + msg
        case let .gatingError(msg):
            return msg
        default:
            return "default Error msg"
        }
    }
}
