import Foundation
@testable import TorusUtils
import XCTest

/// Answers every request from `handler` and records the requested URLs, so tests run with no network.
final class MockNodeURLProtocol: URLProtocol {
    private static let lock = NSLock()
    private static var _handler: ((URLRequest, [String: Any]) throws -> Any)?
    private static var _requestedURLs: [String] = []

    /// Returns a JSON object for the request and its decoded JSON body.
    static var handler: ((URLRequest, [String: Any]) throws -> Any)? {
        get { lock.lock(); defer { lock.unlock() }; return _handler }
        set { lock.lock(); defer { lock.unlock() }; _handler = newValue }
    }

    static var requestedURLs: [String] {
        lock.lock(); defer { lock.unlock() }
        return _requestedURLs
    }

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        _handler = nil
        _requestedURLs = []
    }

    static func clearRequests() {
        lock.lock(); defer { lock.unlock() }
        _requestedURLs = []
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        MockNodeURLProtocol.lock.lock()
        MockNodeURLProtocol._requestedURLs.append(request.url?.absoluteString ?? "")
        MockNodeURLProtocol.lock.unlock()
        do {
            let requestBody = MockNodeURLProtocol.readBody(request)
            let requestJSON = requestBody.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            let body = try MockNodeURLProtocol.handler?(request, requestJSON) ?? [String: Any]()
            let data = try JSONSerialization.data(withJSONObject: body)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    /// URLSession hands the body to a protocol as a stream, not as `httpBody`.
    private static func readBody(_ request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return nil
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

/// Routes `NodeUtils` and `URLSession.shared` through `MockNodeURLProtocol` for the test case.
class MockNodeTestCase: XCTestCase {
    private var originalSession: URLSession!

    override func setUp() {
        super.setUp()
        MockNodeURLProtocol.reset()
        originalSession = NodeUtils.session
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [MockNodeURLProtocol.self]
        NodeUtils.session = URLSession(configuration: configuration)
        URLProtocol.registerClass(MockNodeURLProtocol.self)
    }

    override func tearDown() {
        URLProtocol.unregisterClass(MockNodeURLProtocol.self)
        NodeUtils.session = originalSession
        MockNodeURLProtocol.reset()
        super.tearDown()
    }
}

enum Secp256k1TestKeys {
    static func hex(_ n: Int) -> String {
        String(n, radix: 16).addLeading0sForLength64()
    }

    /// The public key `scalar·G` as padded hex coordinates.
    static func point(_ scalar: Int) throws -> (x: String, y: String) {
        let point = try KeyUtils.publicPoint(privateKey: hex(scalar), keyType: .secp256k1)
        return (String(point.x, radix: 16).addLeading0sForLength64(), String(point.y, radix: 16).addLeading0sForLength64())
    }
}
