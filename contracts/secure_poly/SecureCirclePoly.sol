// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../fields/QM31Field.sol";
import "../circle/CirclePoint.sol";
import "./PolyUtils.sol";

/**
 * @title SecureCirclePoly
 * @notice Implementation of secure circle polynomials for STWO
 * @dev Equivalent to Rust SecureCirclePoly<B: ColumnOps<BaseField>> structure
 *      Contains 4 circle polynomials representing a polynomial over SecureField (QM31)
 */
library SecureCirclePoly {
    using QM31Field for QM31Field.QM31;
    using CirclePoint for CirclePoint.Point;
    using PolyUtils for QM31Field.QM31[];

    /**
     * @notice Secure circle polynomial structure
     * @dev Contains coefficients for 4 coordinate polynomials (SECURE_EXTENSION_DEGREE = 4)
     *      Each polynomial stores M31 coefficients in FFT basis (bit-reversed order)
     *      Log size is computed from coefficient length, not stored
     */
    struct SecurePoly {
        uint32[] coeffs0;  // M31 coefficients for polynomial 0
        uint32[] coeffs1;  // M31 coefficients for polynomial 1  
        uint32[] coeffs2;  // M31 coefficients for polynomial 2
        uint32[] coeffs3;  // M31 coefficients for polynomial 3
    }

    /**
     * @notice Creates a new secure circle polynomial
     * @param coeffs0 M31 coefficients for first coordinate polynomial
     * @param coeffs1 M31 coefficients for second coordinate polynomial
     * @param coeffs2 M31 coefficients for third coordinate polynomial
     * @param coeffs3 M31 coefficients for fourth coordinate polynomial
     * @return poly The constructed secure polynomial
     */
    function createSecurePoly(
        uint32[] memory coeffs0,
        uint32[] memory coeffs1,
        uint32[] memory coeffs2,
        uint32[] memory coeffs3
    ) internal pure returns (SecurePoly memory poly) {
        // Each coordinate can have different length, but each must be power of 2
        require(coeffs0.length > 0 && (coeffs0.length & (coeffs0.length - 1)) == 0, "coeffs0 length must be power of 2");
        require(coeffs1.length > 0 && (coeffs1.length & (coeffs1.length - 1)) == 0, "coeffs1 length must be power of 2");
        require(coeffs2.length > 0 && (coeffs2.length & (coeffs2.length - 1)) == 0, "coeffs2 length must be power of 2");
        require(coeffs3.length > 0 && (coeffs3.length & (coeffs3.length - 1)) == 0, "coeffs3 length must be power of 2");
        
        return SecurePoly({
            coeffs0: coeffs0,
            coeffs1: coeffs1,
            coeffs2: coeffs2,
            coeffs3: coeffs3
        });
    }

    /**
     * @notice Evaluates the secure polynomial at a given circle point
     * @dev Equivalent to Rust SecureCirclePoly::eval_at_point()
     *      Evaluates each coordinate polynomial and combines using fromPartialEvals
     * @param poly The secure polynomial to evaluate
     * @param point The circle point to evaluate at
     * @return result The evaluation result as QM31 element
     */
    function evalAtPoint(SecurePoly memory poly, CirclePoint.Point memory point) 
        public pure returns (QM31Field.QM31 memory result) {
        
        // Evaluate each coordinate polynomial at the point
        QM31Field.QM31[4] memory evals = [
            evalCirclePolyAtPoint(poly.coeffs0, point),
            evalCirclePolyAtPoint(poly.coeffs1, point),
            evalCirclePolyAtPoint(poly.coeffs2, point),
            evalCirclePolyAtPoint(poly.coeffs3, point)
        ];
        
        // Combine evaluations using SecureField::from_partial_evals
        return QM31Field.fromPartialEvals(evals);
    }

    /**
     * @notice Evaluates each coordinate polynomial separately
     * @dev Equivalent to Rust SecureCirclePoly::eval_columns_at_point()
     * @param poly The secure polynomial
     * @param point The evaluation point
     * @return evals Array of 4 evaluations
     */
    function evalColumnsAtPoint(SecurePoly memory poly, CirclePoint.Point memory point) 
        public pure returns (QM31Field.QM31[4] memory evals) {
        
        return [
            evalCirclePolyAtPoint(poly.coeffs0, point),
            evalCirclePolyAtPoint(poly.coeffs1, point),
            evalCirclePolyAtPoint(poly.coeffs2, point),
            evalCirclePolyAtPoint(poly.coeffs3, point)
        ];
    }

    /**
     * @notice Evaluates a single circle polynomial at a point
     * @dev Implementation of CpuBackend::eval_at_point for circle polynomials
     *      Uses hierarchical folding with doubling sequence: [y, x, 2x²-1, 2(2x²-1)²-1, ...]
     * @param coeffs The M31 polynomial coefficients in FFT basis
     * @param point The circle point to evaluate at
     * @return The evaluation result as QM31
     */
    function evalCirclePolyAtPoint(
        uint32[] memory coeffs, 
        CirclePoint.Point memory point
    ) public pure returns (QM31Field.QM31 memory) {
        
        // Calculate log size from coefficient length
        uint32 logSizeConst = uint32(_log2(coeffs.length));
        
        if (logSizeConst == 0) {
            require(coeffs.length >= 1, "Empty polynomial");
            return QM31Field.fromM31(coeffs[0], 0, 0, 0);
        }
        
        // Create folding factors: [point.y, x, double_x(x), ...]
        QM31Field.QM31[] memory foldingFactors = PolyUtils.createFoldingFactors(point, logSizeConst);
        
        // Perform hierarchical fold operation
        return PolyUtils.fold(coeffs, foldingFactors);
    }

    /**
     * @notice Returns the maximum log size among all coordinate polynomials
     * @param poly The secure polynomial
     * @return The maximum log size
     */
    function logSize(SecurePoly memory poly) public pure returns (uint32) {
        uint32 logSize0 = uint32(_log2(poly.coeffs0.length));
        uint32 logSize1 = uint32(_log2(poly.coeffs1.length));
        uint32 logSize2 = uint32(_log2(poly.coeffs2.length));
        uint32 logSize3 = uint32(_log2(poly.coeffs3.length));
        
        uint32 maxLogSize = logSize0;
        if (logSize1 > maxLogSize) maxLogSize = logSize1;
        if (logSize2 > maxLogSize) maxLogSize = logSize2;
        if (logSize3 > maxLogSize) maxLogSize = logSize3;
        
        return maxLogSize;
    }

    /**
     * @notice Helper function to compute log2 of a power of 2
     * @param n The input number (must be power of 2)
     * @return The log2 value
     */
    function _log2(uint256 n) private pure returns (uint256) {
        require(n > 0 && (n & (n - 1)) == 0, "Input must be power of 2");
        uint256 result = 0;
        while (n > 1) {
            n >>= 1;
            result++;
        }
        return result;
    }
}