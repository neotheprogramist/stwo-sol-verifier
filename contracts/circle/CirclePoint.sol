// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/QM31Field.sol";
import "../core/KeccakChannelLib.sol";

/// @title CirclePoint
/// @notice A point on the complex circle, treated as an additive group
library CirclePoint {
    using QM31Field for QM31Field.QM31;
    using KeccakChannelLib for KeccakChannelLib.ChannelState;

    /// @notice Represents a point on the circle with coordinates (x, y)
    /// @dev Both x and y are elements of the SecureField (QM31)
    struct Point {
        QM31Field.QM31 x;
        QM31Field.QM31 y;
    }

    /// @notice Returns the zero element (identity) of the circle group
    /// @dev The identity element is (1, 0)
    /// @return The identity point (1, 0)
    function zero() internal pure returns (Point memory) {
        return Point({
            x: QM31Field.one(),
            y: QM31Field.zero()
        });
    }

    /// @notice Doubles a circle point
    /// @param point The point to double
    /// @return The doubled point
    function double(Point memory point) internal pure returns (Point memory) {
        return add(point, point);
    }

    /// @notice Applies the circle's x-coordinate doubling map
    /// @dev For a point (x, y), computes the x-coordinate of 2*(x, y)
    /// @param x The x-coordinate
    /// @return The x-coordinate of the doubled point: 2x² - 1
    function doubleX(QM31Field.QM31 memory x) internal pure returns (QM31Field.QM31 memory) {
        QM31Field.QM31 memory sx = x.square();
        return QM31Field.add(QM31Field.add(sx, sx), QM31Field.neg(QM31Field.one()));
    }

    /// @notice Adds two circle points
    /// @param a First point
    /// @param b Second point  
    /// @return The sum of the two points
    function add(Point memory a, Point memory b) internal pure returns (Point memory) {
        // x = a.x * b.x - a.y * b.y
        QM31Field.QM31 memory x = QM31Field.sub(QM31Field.mul(a.x, b.x), QM31Field.mul(a.y, b.y));
        // y = a.x * b.y + a.y * b.x  
        QM31Field.QM31 memory y = QM31Field.add(QM31Field.mul(a.x, b.y), QM31Field.mul(a.y, b.x));
        
        return Point({x: x, y: y});
    }

    /// @notice Negates a circle point (returns multiplicative inverse for unit circle)
    /// @param point The point to negate
    /// @return The negated point (inverse for multiplication)
    function neg(Point memory point) internal pure returns (Point memory) {
        // For points on unit circle: z^(-1) = conjugate(z) since |z|^2 = 1
        return conjugate(point);
    }

    /// @notice Subtracts two circle points
    /// @param a First point (minuend)
    /// @param b Second point (subtrahend)
    /// @return The difference a - b
    function sub(Point memory a, Point memory b) internal pure returns (Point memory) {
        return add(a, neg(b));
    }

    /// @notice Returns the conjugate of a point
    /// @dev Changes (x, y) to (x, -y)
    /// @param point The point to conjugate
    /// @return The conjugated point
    function conjugate(Point memory point) internal pure returns (Point memory) {
        return Point({
            x: point.x,
            y: QM31Field.neg(point.y)
        });
    }

    function complexConjugate(Point memory point) internal pure returns (Point memory) {
        return Point({
            x: _conjugateQM31(point.x),
            y: _conjugateQM31(point.y)
        });
    }


    /// @notice Scalar multiplication of a circle point
    /// @dev Multiplies a point by a scalar using double-and-add
    /// @param point The point to multiply
    /// @param scalar The scalar multiplier
    /// @return The scaled point
    function mul(Point memory point, uint256 scalar) internal pure returns (Point memory) {
        Point memory result = zero();
        Point memory current = point;
        
        while (scalar > 0) {
            if (scalar & 1 == 1) {
                result = add(result, current);
            }
            current = double(current);
            scalar >>= 1;
        }
        
        return result;
    }

    /// @notice Complex conjugate for QM31 (negates second component)
    /// @param a QM31 element to conjugate
    /// @return Conjugated element (first, -second)
    function _conjugateQM31(QM31Field.QM31 memory a) private pure returns (QM31Field.QM31 memory) {
        return QM31Field.QM31({
            first: a.first,
            second: CM31Field.neg(a.second)
        });
    }



    /// @notice Generates a random point on the circle using channel state directly
    /// @dev Uses Fiat-Shamir transform to generate cryptographically secure random point
    /// @param channelState The channel state providing randomness
    /// @return A random point on the circle
    function getRandomPointFromState(KeccakChannelLib.ChannelState storage channelState) internal returns (Point memory) {
        // Draw random element t from secure field using library
        QM31Field.QM31 memory t;
        t = KeccakChannelLib.drawSecureFelt(channelState);
        
        // Compute t²
        QM31Field.QM31 memory tSquare = QM31Field.square(t);
        
        // Compute (1 + t²)⁻¹
        QM31Field.QM31 memory onePlusTSquaredInv = QM31Field.inverse(QM31Field.add(tSquare, QM31Field.one()));
        
        // x = (1 - t²) / (1 + t²)
        QM31Field.QM31 memory x = QM31Field.mul(QM31Field.sub(QM31Field.one(), tSquare), onePlusTSquaredInv);
        
        // y = 2t / (1 + t²)  
        QM31Field.QM31 memory y = QM31Field.mul(QM31Field.add(t, t), onePlusTSquaredInv);
        
        return Point({x: x, y: y});
    }

    /// @notice Validates that a point lies on the unit circle
    /// @dev Checks that x² + y² = 1
    /// @param point The point to validate
    /// @return True if the point is on the circle
    function isOnCircle(Point memory point) internal pure returns (bool) {
        // Check x² + y² = 1
        QM31Field.QM31 memory xSquared = QM31Field.square(point.x);
        QM31Field.QM31 memory ySquared = QM31Field.square(point.y);
        QM31Field.QM31 memory sum = QM31Field.add(xSquared, ySquared);
        
        return QM31Field.eq(sum, QM31Field.one());
    }

    /// @notice Converts a point to extension field representation  
    /// @dev Helper for field extension operations
    /// @param point The point to convert
    /// @return The point with extended field coordinates
    function intoEF(Point memory point) internal pure returns (Point memory) {
        // Already in QM31 (extension field), so just return as-is
        return point;
    }

    /// @notice Repeated doubling operation
    /// @dev Doubles a point n times efficiently
    /// @param point The point to double repeatedly
    /// @param n Number of doublings to perform
    /// @return The result after n doublings
    function repeatedDouble(Point memory point, uint32 n) internal pure returns (Point memory) {
        Point memory result = point;
        for (uint32 i = 0; i < n; i++) {
            result = double(result);
        }
        return result;
    }
}