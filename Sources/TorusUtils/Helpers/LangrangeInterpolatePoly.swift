import BigInt
import Foundation
#if canImport(curveSecp256k1)
    import curveSecp256k1
#endif

internal class Lagrange {
    public static func generatePrivateExcludingIndexes(shareIndexes: [BigInt]) throws -> BigInt {
        let key = BigInt(Data(hex: try SecretKey().serialize().addLeading0sForLength64()))
        if shareIndexes.contains(where: { $0 == key }) {
            return try generatePrivateExcludingIndexes(shareIndexes: shareIndexes)
        }
        return key
    }

    public static func generateEmptyBNArray(length: Int) -> [BigInt] {
        return Array(repeating: BigInt(0), count: length)
    }

    public static func denominator(i: Int, innerPoints: [Point]) -> BigInt {
        var result = BigInt(1)
        let xi = innerPoints[i].x
        for j in (0 ..< innerPoints.count).reversed() {
            if i != j {
                var tmp = xi
                tmp = (tmp - innerPoints[j].x).modulus(KeyUtils.getOrderOfCurve())
                result = (result * tmp).modulus(KeyUtils.getOrderOfCurve())
            }
        }
        return result
    }

    public static func interpolationPoly(i: Int, innerPoints: [Point]) -> [BigInt] {
        var coefficients = generateEmptyBNArray(length: innerPoints.count)
        let d = denominator(i: i, innerPoints: innerPoints)
        if d == BigInt(0) {
            fatalError("Denominator for interpolationPoly is 0")
        }
        coefficients[0] = d.inverse(KeyUtils.getOrderOfCurve())!
        for k in 0 ..< innerPoints.count {
            var newCoefficients = generateEmptyBNArray(length: innerPoints.count)
            if k != i {
                var j: Int
                if k < i {
                    j = k + 1
                } else {
                    j = k
                }
                j -= 1
                while j >= 0 {
                    newCoefficients[j + 1] = (newCoefficients[j + 1] + coefficients[j]).modulus(KeyUtils.getOrderOfCurve())
                    var tmp = BigInt(innerPoints[k].x)
                    tmp = (tmp * coefficients[j]).modulus(KeyUtils.getOrderOfCurve())
                    newCoefficients[j] = (newCoefficients[j] - tmp).modulus(KeyUtils.getOrderOfCurve())
                    j -= 1
                }
                coefficients = newCoefficients
            }
        }
        return coefficients
    }

    public static func pointSort(innerPoints: [Point]) -> [Point] {
        var pointArrClone = innerPoints
        pointArrClone.sort { $0.x < $1.x }
        return pointArrClone
    }

    public static func lagrange(unsortedPoints: [Point]) -> Polynomial {
        let sortedPoints = pointSort(innerPoints: unsortedPoints)
        var polynomial = generateEmptyBNArray(length: sortedPoints.count)
        for i in 0 ..< sortedPoints.count {
            let coefficients = interpolationPoly(i: i, innerPoints: sortedPoints)
            for k in 0 ..< sortedPoints.count {
                var tmp = BigInt(sortedPoints[i].y)
                tmp = (tmp * coefficients[k]).modulus(KeyUtils.getOrderOfCurve())
                polynomial[k] = (polynomial[k] + tmp).modulus(KeyUtils.getOrderOfCurve())
            }
        }
        return Polynomial(polynomial: polynomial)
    }

    public static func lagrangeInterpolatePolynomial(points: [Point]) -> Polynomial {
        return lagrange(unsortedPoints: points)
    }

    public static func lagrangeInterpolation(
        shares: [String],
        nodeIndex: [Int],
        order: BigInt = KeyUtils.getOrderOfCurve()
    ) throws -> String {
        let sharesList: [BigInt] = shares.map({ BigInt($0.addLeading0sForLength64(), radix: 16) }).filter({ $0 != nil }).map({ $0! })
        let indexList: [BigInt] = nodeIndex.map({ BigInt($0) })

        if sharesList.count != indexList.count {
            throw TorusUtilError.runtime("sharesList not equal to indexList length in lagrangeInterpolation")
        }

        var secret = BigUInt("0")
        var sharesDecrypt = 0

        for i in 0 ..< sharesList.count {
            var upper = BigInt(1)
            var lower = BigInt(1)
            for j in 0 ..< sharesList.count {
                if i != j {
                    let negatedJ = indexList[j] * BigInt(-1)
                    upper = upper * negatedJ
                    upper = upper.modulus(order)

                    var temp = indexList[i] - indexList[j]
                    temp = temp.modulus(order)
                    lower = (lower * temp).modulus(order)
                }
            }
            guard
                let inv = lower.inverse(order)
            else {
                throw TorusUtilError.decryptionFailed
            }
            var delta = (upper * inv).modulus(order)
            delta = (delta * sharesList[i]).modulus(order)
            secret = BigUInt((BigInt(secret) + delta).modulus(order))
            sharesDecrypt += 1
        }

        if secret == BigUInt(0) {
            throw TorusUtilError.interpolationFailed
        }

        let secretString = secret.serialize().hexString.addLeading0sForLength64()
        if sharesDecrypt == sharesList.count {
            return secretString
        } else {
            throw TorusUtilError.interpolationFailed
        }
    }

    public static func generateRandomPolynomial(degree: Int, secret: BigInt? = nil, deterministicShares: [Share]? = nil) throws -> Polynomial {
        var actualS = secret
        if secret == nil {
            actualS = try generatePrivateExcludingIndexes(shareIndexes: [BigInt(0)])
        }

        if deterministicShares == nil {
            var poly = [actualS!]
            for _ in 0 ..< degree {
                let share = try generatePrivateExcludingIndexes(shareIndexes: poly)
                poly.append(share)
            }

            return Polynomial(polynomial: poly)
        }

        guard let deterministicShares = deterministicShares else {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Deterministic shares in generateRandomPolynomial should be an array"])
        }

        if deterministicShares.count > degree {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Deterministic shares in generateRandomPolynomial should be less or equal than degree to ensure an element of randomness"])
        }

        var points = [String: Point]()
        for share in deterministicShares {
            points[String(share.shareIndex, radix: 16).addLeading0sForLength64()] =
                Point(x: share.shareIndex, y: share.share)
        }

        let remainingDegree = degree - deterministicShares.count
        for _ in 0 ..< remainingDegree {
            var shareIndex = try generatePrivateExcludingIndexes(shareIndexes: [BigInt(0)])
            while points[shareIndex.magnitude.serialize().hexString.addLeading0sForLength64()] != nil {
                shareIndex = try generatePrivateExcludingIndexes(shareIndexes: [BigInt(0)])
            }
            points[shareIndex.magnitude.serialize().hexString.addLeading0sForLength64()] = Point(x: shareIndex, y: BigInt(Data(hex: try SecretKey().serialize().addLeading0sForLength64())))
        }

        points["0"] = Point(x: BigInt(0), y: actualS!)
        return lagrangeInterpolatePolynomial(points: Array(points.values))
    }
}
