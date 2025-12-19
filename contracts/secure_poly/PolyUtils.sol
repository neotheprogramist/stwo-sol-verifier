// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../fields/QM31Field.sol";
import "../fields/M31Field.sol";
import "../circle/CirclePoint.sol";

/**
 * @title PolyUtils
 * @notice Utility functions for polynomial operations
 * @dev Implements the fold operation for hierarchical polynomial evaluation
 */
library PolyUtils {
    using QM31Field for QM31Field.QM31;
    using M31Field for uint32;

    /**
     * @notice Folds M31 values recursively using QM31 folding factors
     * @dev Implementation of the fold function from Rust core::poly::utils::fold
     *      Coefficients are M31 (BaseField), folding factors are QM31 (SecureField)
     * @param values Array of M31 coefficient values (must be power of 2 length)
     * @param foldingFactors Array of QM31 folding factors for each level
     * @return result The final folded value as QM31
     */
    function fold(uint32[] memory values, QM31Field.QM31[] memory foldingFactors) 
        internal pure returns (QM31Field.QM31 memory result) {
        
        uint256 n = values.length;
        require(n == (1 << foldingFactors.length), "Values length must be 2^(folding factors length)");
        
        if (n == 1) {
            // Convert M31 to QM31 (M31 becomes real part of first CM31)
            return QM31Field.fromM31(values[0], 0, 0, 0);
        }
        
        // Split into left and right halves
        uint256 halfN = n / 2;
        uint32[] memory lhsValues = new uint32[](halfN);
        uint32[] memory rhsValues = new uint32[](halfN);
        QM31Field.QM31[] memory remainingFactors = new QM31Field.QM31[](foldingFactors.length - 1);
        
        // Copy left half
        for (uint256 i = 0; i < halfN; i++) {
            lhsValues[i] = values[i];
        }
        
        // Copy right half
        for (uint256 i = 0; i < halfN; i++) {
            rhsValues[i] = values[halfN + i];
        }
        
        // Copy remaining folding factors (skip first one)
        for (uint256 i = 1; i < foldingFactors.length; i++) {
            remainingFactors[i - 1] = foldingFactors[i];
        }
        
        // Recursive fold
        QM31Field.QM31 memory lhsVal = fold(lhsValues, remainingFactors);
        QM31Field.QM31 memory rhsVal = fold(rhsValues, remainingFactors);
        
        // Return: lhs_val + rhs_val * folding_factor[0]
        return QM31Field.add(lhsVal, QM31Field.mul(rhsVal, foldingFactors[0]));
    }

    /**
     * @notice Creates array of folding factors for circle polynomial evaluation
     * @dev Builds the mappings array: [point.y, x, double_x(x), double_x(double_x(x)), ...]
     *      Then reverses it for proper fold order
     * @param point The circle point to evaluate at
     * @param logSize The log size of the polynomial
     * @return mappings The folding factors in correct order
     */
    function createFoldingFactors(CirclePoint.Point memory point, uint32 logSize) 
        internal pure returns (QM31Field.QM31[] memory mappings) {
        
        if (logSize == 0) {
            return new QM31Field.QM31[](0);
        }
        
        mappings = new QM31Field.QM31[](logSize);
        mappings[0] = point.y;
        
        QM31Field.QM31 memory x = point.x;
        for (uint32 i = 1; i < logSize; i++) {
            mappings[i] = x;
            x = CirclePoint.doubleX(x);
        }
        
        // Reverse the mappings array
        for (uint32 i = 0; i < logSize / 2; i++) {
            QM31Field.QM31 memory temp = mappings[i];
            mappings[i] = mappings[logSize - 1 - i];
            mappings[logSize - 1 - i] = temp;
        }
        
        return mappings;
    }
}