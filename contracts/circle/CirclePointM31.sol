// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/M31Field.sol";
import "../fields/QM31Field.sol";
import "./CirclePoint.sol";

/// @title CirclePointM31
/// @notice A point on the complex circle using M31 field
library CirclePointM31 {
    using M31Field for uint32;

    /// @notice Represents a point on the circle with M31 coordinates (x, y)
    struct Point {
        uint32 x;
        uint32 y;
    }

    /// @notice Returns the zero element (identity) of the circle group
    function zero() internal pure returns (Point memory) {
        return Point({
            x: M31Field.one(),
            y: M31Field.zero()
        });
    }

    /// @notice Doubles a circle point
    function double(Point memory point) internal pure returns (Point memory) {
        return add(point, point);
    }

    /// @notice Applies the circle's x-coordinate doubling map (2x² - 1)
    function doubleX(uint32 x) internal pure returns (uint32) {
        uint32 sx = M31Field.mul(x, x);
        return M31Field.sub(M31Field.add(sx, sx), M31Field.one());
    }

    /// @notice Adds two circle points using complex multiplication
    function add(Point memory a, Point memory b) internal pure returns (Point memory) {
        uint32 x = M31Field.sub(M31Field.mul(a.x, b.x), M31Field.mul(a.y, b.y));
        uint32 y = M31Field.add(M31Field.mul(a.x, b.y), M31Field.mul(a.y, b.x));
        
        return Point({x: x, y: y});
    }

    /// @notice Negates a circle point (returns complex conjugate)
    function neg(Point memory point) internal pure returns (Point memory) {
        return conjugate(point);
    }

    /// @notice Subtracts two circle points
    function sub(Point memory a, Point memory b) internal pure returns (Point memory) {
        return add(a, neg(b));
    }

    /// @notice Returns the complex conjugate of a point
    function conjugate(Point memory point) internal pure returns (Point memory) {
        return Point({
            x: point.x,
            y: M31Field.neg(point.y)
        });
    }

    /// @notice Scalar multiplication of a circle point
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
    function mulSigned(Point memory point, int32 signedOffset) internal pure returns (Point memory) {
        if (signedOffset >= 0) {
            return mul(point, uint256(uint32(signedOffset)));
        } else {
            Point memory result = mul(point, uint256(uint32(-signedOffset)));
            return neg(result);
        }
    }

    /// @notice Validates that a point lies on the unit circle
    function isOnCircle(Point memory point) internal pure returns (bool) {
        uint32 xSquared = M31Field.mul(point.x, point.x);
        uint32 ySquared = M31Field.mul(point.y, point.y);
        uint32 sum = M31Field.add(xSquared, ySquared);
        
        return sum == M31Field.one();
    }

    /// @notice Convert M31 point to QM31 point
    function toQM31(Point memory m31Point) internal pure returns (CirclePoint.Point memory qm31Point) {
        qm31Point.x = QM31Field.fromM31(m31Point.x, 0, 0, 0);
        qm31Point.y = QM31Field.fromM31(m31Point.y, 0, 0, 0);
    }

    /// @notice Repeated doubling operation
    function repeatedDouble(Point memory point, uint32 n) internal pure returns (Point memory) {
        Point memory result = point;
        for (uint32 i = 0; i < n; i++) {
            result = double(result);
        }
        return result;
    }
}