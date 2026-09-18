import BigInt
import Foundation
#if canImport(CryptoKit)
    import CryptoKit
#elseif canImport(Crypto)
    import Crypto
#endif

internal enum Ed25519Utils {
    static let fieldOrder = (BigInt(1) << 255) - 19
    static let scalarOrder = (BigInt(1) << 252) + BigInt("27742317777372353535851937790883648493")
    private static let d = (
        -BigInt(121665) * BigInt(121666).inverse(fieldOrder)!
    ).modulus(fieldOrder)
    static let basePoint = Point(
        x: BigInt("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
        y: BigInt("46316835694926478169428394003475163141307993866256225615783033603165251855960")
    )

    static func point(fromScalar scalar: BigInt) -> Point {
        multiply(basePoint, by: scalar.modulus(scalarOrder))
    }

    static func add(_ lhs: Point, _ rhs: Point) -> Point {
        let xProduct = (lhs.x * rhs.x).modulus(fieldOrder)
        let yProduct = (lhs.y * rhs.y).modulus(fieldOrder)
        let dxxyy = (d * xProduct * yProduct).modulus(fieldOrder)
        let xNumerator = (lhs.x * rhs.y + lhs.y * rhs.x).modulus(fieldOrder)
        let yNumerator = (yProduct + xProduct).modulus(fieldOrder)
        let xDenominator = (BigInt(1) + dxxyy).modulus(fieldOrder)
        let yDenominator = (BigInt(1) - dxxyy).modulus(fieldOrder)
        return Point(
            x: (xNumerator * xDenominator.inverse(fieldOrder)!).modulus(fieldOrder),
            y: (yNumerator * yDenominator.inverse(fieldOrder)!).modulus(fieldOrder)
        )
    }

    static func multiply(_ point: Point, by scalar: BigInt) -> Point {
        var value = scalar.modulus(scalarOrder)
        var addend = point
        var result = Point(x: BigInt(0), y: BigInt(1))
        while value > 0 {
            if value & 1 == 1 {
                result = add(result, addend)
            }
            addend = add(addend, addend)
            value >>= 1
        }
        return result
    }

    static func scalar(fromSeed seed: Data) throws -> BigInt {
        guard seed.count == 32 else {
            throw TorusUtilError.invalidKeySize
        }
        var bytes = Array(Data(SHA512.hash(data: seed)).prefix(32))
        bytes[0] &= 248
        bytes[31] &= 63
        bytes[31] |= 64
        return littleEndianInteger(bytes).modulus(scalarOrder)
    }

    static func encode(_ point: Point) -> Data {
        var bytes = littleEndianBytes(point.y.modulus(fieldOrder), count: 32)
        if point.x.modulus(fieldOrder) & 1 == 1 {
            bytes[31] |= 0x80
        }
        return Data(bytes)
    }

    static func address(_ point: Point) -> String {
        base58Encode(encode(point))
    }

    static func randomScalar() throws -> BigInt {
        var scalar = BigInt(try KeyUtils.generateSecret(), radix: 16)!.modulus(scalarOrder)
        while scalar == 0 {
            scalar = BigInt(try KeyUtils.generateSecret(), radix: 16)!.modulus(scalarOrder)
        }
        return scalar
    }

    private static func littleEndianInteger(_ bytes: [UInt8]) -> BigInt {
        BigInt(BigUInt(Data(bytes.reversed())))
    }

    private static func littleEndianBytes(_ value: BigInt, count: Int) -> [UInt8] {
        var bytes = Array(value.magnitude.serialize().reversed())
        if bytes.count < count {
            bytes.append(contentsOf: repeatElement(0, count: count - bytes.count))
        }
        return Array(bytes.prefix(count))
    }

    private static func base58Encode(_ data: Data) -> String {
        let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        let bytes = Array(data)
        let leadingZeroes = bytes.prefix(while: { $0 == 0 }).count
        var value = BigUInt(data)
        var encoded = [Character]()
        while value > 0 {
            encoded.append(alphabet[Int(value % 58)])
            value /= 58
        }
        encoded.append(contentsOf: repeatElement(Character("1"), count: leadingZeroes))
        return String(encoded.reversed())
    }
}
