import BigInt
import Foundation
@testable import TorusUtils
import XCTest

final class Ed25519UtilsTests: XCTestCase {
    func testRFC8032SeedDerivesExpectedPublicKey() throws {
        let seed = Data(hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let scalar = try Ed25519Utils.scalar(fromSeed: seed)
        let encoded = Ed25519Utils.encode(Ed25519Utils.point(fromScalar: scalar))

        XCTAssertEqual(
            encoded.hexString,
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
    }

    func testGenerateSharesSupportsEd25519() throws {
        let generator = INodePub(
            X: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            Y: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        let shares = try KeyUtils.generateShares(
            keyType: .ed25519,
            serverTimeOffset: 0,
            nodeIndexes: [1, 2, 3],
            nodePubKeys: [generator, generator, generator],
            privateKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )

        XCTAssertEqual(shares.count, 3)
        XCTAssertTrue(shares.allSatisfy { $0.key_type == .ed25519 })
        XCTAssertTrue(shares.allSatisfy { !($0.encryptedSeed?.isEmpty ?? true) })
    }

    func testLegacyNetworkRejectsEd25519() {
        XCTAssertThrowsError(try TorusUtils(params: TorusOptions(
            clientId: "client-id",
            network: .MAINNET,
            keyType: .ed25519
        )))
    }
}
