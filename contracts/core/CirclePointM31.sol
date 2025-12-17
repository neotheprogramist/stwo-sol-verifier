// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/M31Field.sol";
import "../fields/QM31Field.sol";
import "./CirclePoint.sol";

/// @title CirclePointM31
/// @notice A point on the complex circle using M31 field, treated as an additive group
/// @dev Implements circle group operations for x² + y² = 1 using M31 instead of QM31
library CirclePointM31 {
    using M31Field for uint32;

    /// @notice Represents a point on the circle with M31 coordinates (x, y)
    /// @dev Both x and y are elements of the M31 field (uint32)
    struct Point {
        uint32 x;  // M31 field element
        uint32 y;  // M31 field element
    }

    /// @notice Returns the zero element (identity) of the circle group
    /// @dev The identity element is (1, 0) in M31
    /// @return The identity point (1, 0)
    function zero() internal pure returns (Point memory) {
        return Point({
            x: M31Field.one(),
            y: M31Field.zero()
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
    /// @param x The x-coordinate (M31)
    /// @return The x-coordinate of the doubled point: 2x² - 1
    function doubleX(uint32 x) internal pure returns (uint32) {
        uint32 sx = M31Field.mul(x, x); // x²
        return M31Field.sub(M31Field.add(sx, sx), M31Field.one()); // 2x² - 1
    }

    /// @notice Adds two circle points
    /// @dev Implements complex multiplication: (x₁ + iy₁) * (x₂ + iy₂)
    /// @param a First point
    /// @param b Second point  
    /// @return The sum of the two points
    function add(Point memory a, Point memory b) internal pure returns (Point memory) {
        // x = a.x * b.x - a.y * b.y
        uint32 x = M31Field.sub(M31Field.mul(a.x, b.x), M31Field.mul(a.y, b.y));
        // y = a.x * b.y + a.y * b.x  
        uint32 y = M31Field.add(M31Field.mul(a.x, b.y), M31Field.mul(a.y, b.x));
        
        return Point({x: x, y: y});
    }

    /// @notice Negates a circle point (returns complex conjugate)
    /// @param point The point to negate
    /// @return The negated point (x, -y)
    function neg(Point memory point) internal pure returns (Point memory) {
        return conjugate(point);
    }

    /// @notice Subtracts two circle points
    /// @param a First point (minuend)
    /// @param b Second point (subtrahend)
    /// @return The difference a - b
    function sub(Point memory a, Point memory b) internal pure returns (Point memory) {
        return add(a, neg(b));
    }

    /// @notice Returns the complex conjugate of a point
    /// @dev Changes (x, y) to (x, -y)
    /// @param point The point to conjugate
    /// @return The conjugated point
    function conjugate(Point memory point) internal pure returns (Point memory) {
        return Point({
            x: point.x,
            y: M31Field.neg(point.y)
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

    /// @notice Scalar multiplication with signed offset
    /// @dev Multiplies a point by a signed scalar (for mask point offsets)
    /// @param point The point to multiply
    /// @param signedOffset The signed scalar multiplier
    /// @return The scaled point
    function mulSigned(Point memory point, int32 signedOffset) internal pure returns (Point memory) {
        if (signedOffset >= 0) {
            return mul(point, uint256(uint32(signedOffset)));
        } else {
            // Negative offset: multiply by absolute value then negate
            Point memory result = mul(point, uint256(uint32(-signedOffset)));
            return neg(result);
        }
    }

    /// @notice Validates that a point lies on the unit circle
    /// @dev Checks that x² + y² = 1 in M31
    /// @param point The point to validate
    /// @return True if the point is on the circle
    function isOnCircle(Point memory point) internal pure returns (bool) {
        // Check x² + y² = 1
        uint32 xSquared = M31Field.mul(point.x, point.x);
        uint32 ySquared = M31Field.mul(point.y, point.y);
        uint32 sum = M31Field.add(xSquared, ySquared);
        
        return sum == M31Field.one();
    }

    /// @notice Convert M31 point to QM31 point (extension field)
    /// @dev Converts CirclePointM31.Point to CirclePoint.Point
    /// @param m31Point The M31 point to convert
    /// @return qm31Point The equivalent QM31 point
    function toQM31(Point memory m31Point) internal pure returns (CirclePoint.Point memory qm31Point) {
        // Convert M31 coordinates to QM31 (real parts only, imaginary = 0)
        qm31Point.x = QM31Field.fromM31(m31Point.x, 0, 0, 0);
        qm31Point.y = QM31Field.fromM31(m31Point.y, 0, 0, 0);
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