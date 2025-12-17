// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./CM31Field.sol";
import "./M31Field.sol";

/**
 * @title QM31Field
 * @notice Implementation of quaternion extension field over CM31 (QM31: CM31[u]/(u²-(2+i)))
 * @dev This library implements quaternion field operations for QM31 = CM31[u] where u² = 2+i.
 *      Each QM31 element is represented as (first, second) pair of CM31 elements.
 *      Equivalent to CM31[x] over (x² - (2+i)) as the irreducible polynomial.
 *      QM31 is the SecureField used throughout STWO for cryptographic security.
 */
library QM31Field {
    using CM31Field for CM31Field.CM31;
    using M31Field for uint32;

    /// @notice Quaternion representation: first + second*u where u² = 2+i
    struct QM31 {
        CM31Field.CM31 first;   // First CM31 component (a + bi)
        CM31Field.CM31 second;  // Second CM31 component (c + di), multiplied by u
    }

    /// @notice The field size: (2^31 - 1)⁴ for QM31
    uint128 public constant P4 = 21267647892944572736998860269687930881; // (2^31-1)^4

    /// @notice Extension degree: QM31 has 4 M31 components
    uint256 public constant EXTENSION_DEGREE = 4;

    /// @notice The irreducible element R = 2 + i (used in u² = 2 + i)
    function R() internal pure returns (CM31Field.CM31 memory) {
        return CM31Field.fromM31(2, 1);
    }

    /// @notice Additive identity (0 + 0u)
    function zero() internal pure returns (QM31 memory) {
        return QM31(CM31Field.zero(), CM31Field.zero());
    }

    /// @notice Multiplicative identity (1 + 0u)
    function one() internal pure returns (QM31 memory) {
        return QM31(CM31Field.one(), CM31Field.zero());
    }

    /// @notice Create QM31 element from M31 components
    /// @param a Real part of first CM31
    /// @param b Imaginary part of first CM31
    /// @param c Real part of second CM31
    /// @param d Imaginary part of second CM31
    /// @return QM31 element representing (a + bi) + (c + di)u
    function fromM31(uint32 a, uint32 b, uint32 c, uint32 d) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.fromM31(a, b),
            CM31Field.fromM31(c, d)
        );
    }

    /// @notice Create QM31 element from CM31 components
    /// @param first First CM31 component
    /// @param second Second CM31 component
    /// @return QM31 element representing first + second*u
    function fromCM31(CM31Field.CM31 memory first, CM31Field.CM31 memory second) internal pure returns (QM31 memory) {
        return QM31(first, second);
    }

    /// @notice Create QM31 element from real M31 element (other components = 0)
    /// @param real Real part as M31 element
    /// @return QM31 element representing real + 0i + 0u + 0iu
    function fromReal(uint32 real) internal pure returns (QM31 memory) {
        return QM31(CM31Field.fromReal(real), CM31Field.zero());
    }

    /// @notice Create QM31 element from unchecked u32 values
    /// @param a Real part of first CM31
    /// @param b Imaginary part of first CM31
    /// @param c Real part of second CM31
    /// @param d Imaginary part of second CM31
    /// @return QM31 element (components will be reduced mod P)
    function fromU32Unchecked(uint32 a, uint32 b, uint32 c, uint32 d) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.fromU32Unchecked(a, b),
            CM31Field.fromU32Unchecked(c, d)
        );
    }

    /// @notice Combine partial evaluations into single QM31 value
    /// Given evaluations at basis points [1, i, u, iu], combine using:
    /// res = evals[0]*1 + evals[1]*i + evals[2]*u + evals[3]*iu
    /// where i = (0,1,0,0), u = (0,0,1,0), iu = (0,0,0,1)
    /// @param evals Array of 4 QM31 evaluations
    /// @return Combined QM31 value
    function fromPartialEvals(QM31[4] memory evals) internal pure returns (QM31 memory) {
        // Start with evals[0] * 1
        QM31 memory res = evals[0];
        
        // Add evals[1] * i  where i = (0, 1, 0, 0)
        QM31 memory basis_i = fromU32Unchecked(0, 1, 0, 0);
        res = add(res, mul(evals[1], basis_i));
        
        // Add evals[2] * u  where u = (0, 0, 1, 0)
        QM31 memory basis_u = fromU32Unchecked(0, 0, 1, 0);
        res = add(res, mul(evals[2], basis_u));
        
        // Add evals[3] * iu where iu = (0, 0, 0, 1)
        QM31 memory basis_iu = fromU32Unchecked(0, 0, 0, 1);
        res = add(res, mul(evals[3], basis_iu));
        
        return res;
    }

    /// @notice Addition in QM31 field
    /// @param a First operand
    /// @param b Second operand
    /// @return Sum a + b
    function add(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.add(a.first, b.first),
            CM31Field.add(a.second, b.second)
        );
    }

    /// @notice Subtraction in QM31 field
    /// @param a Minuend
    /// @param b Subtrahend
    /// @return Difference a - b
    function sub(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.sub(a.first, b.first),
            CM31Field.sub(a.second, b.second)
        );
    }

    /// @notice Negation in QM31 field
    /// @param a Value to negate
    /// @return Negated value -a
    function neg(QM31 memory a) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.neg(a.first),
            CM31Field.neg(a.second)
        );
    }

    /// @notice Multiplication in QM31 field
    /// @param a First operand
    /// @param b Second operand
    /// @return Product a * b
    /// @dev (a + bu) * (c + du) = (ac + R*bd) + (ad + bc)u where R = 2+i
    function mul(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        // Calculate ac
        CM31Field.CM31 memory ac = CM31Field.mul(a.first, b.first);
        
        // Calculate bd
        CM31Field.CM31 memory bd = CM31Field.mul(a.second, b.second);
        
        // Calculate R * bd where R = 2+i
        CM31Field.CM31 memory Rbd = CM31Field.mul(R(), bd);
        
        // First component: ac + R*bd
        CM31Field.CM31 memory firstComponent = CM31Field.add(ac, Rbd);
        
        // Calculate ad + bc for second component
        CM31Field.CM31 memory ad = CM31Field.mul(a.first, b.second);
        CM31Field.CM31 memory bc = CM31Field.mul(a.second, b.first);
        CM31Field.CM31 memory secondComponent = CM31Field.add(ad, bc);
        
        return QM31(firstComponent, secondComponent);
    }

    /// @notice Square operation in QM31 field
    /// @param a Value to square
    /// @return Square a²
    function square(QM31 memory a) internal pure returns (QM31 memory) {
        return mul(a, a);
    }

    /// @notice Multiplicative inverse in QM31 field
    /// @param a Value to invert (must be non-zero)
    /// @return Inverse a⁻¹ such that a * a⁻¹ = 1
    /// @dev (a + bu)⁻¹ = (a - bu) / (a² - R*b²) where R = 2+i
    function inverse(QM31 memory a) internal pure returns (QM31 memory) {
        if (isZero(a)) {
            revert("QM31Field: division by zero");
        }
        
        // Calculate b² where b is the second component
        CM31Field.CM31 memory b2 = CM31Field.square(a.second);
        
        // Calculate R * b² where R = 2+i
        CM31Field.CM31 memory Rb2 = CM31Field.mul(R(), b2);
        
        // Calculate denominator: a² - R*b²
        CM31Field.CM31 memory a2 = CM31Field.square(a.first);
        CM31Field.CM31 memory denom = CM31Field.sub(a2, Rb2);
        CM31Field.CM31 memory denomInv = CM31Field.inverse(denom);
        
        // Calculate (a - bu) / denom
        return QM31(
            CM31Field.mul(a.first, denomInv),
            CM31Field.mul(CM31Field.neg(a.second), denomInv)
        );
    }

    /// @notice Division in QM31 field
    /// @param a Dividend
    /// @param b Divisor (must be non-zero)
    /// @return Quotient a / b = a * b⁻¹
    function div(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        return mul(a, inverse(b));
    }

    /// @notice Check if QM31 element is zero
    /// @param a Element to check
    /// @return True if a == 0 + 0u
    function isZero(QM31 memory a) internal pure returns (bool) {
        return CM31Field.isZero(a.first) && CM31Field.isZero(a.second);
    }

    /// @notice Check if QM31 element is one
    /// @param a Element to check
    /// @return True if a == 1 + 0u
    function isOne(QM31 memory a) internal pure returns (bool) {
        return CM31Field.isOne(a.first) && CM31Field.isZero(a.second);
    }

    /// @notice Equality comparison
    /// @param a First element
    /// @param b Second element
    /// @return True if a == b
    function eq(QM31 memory a, QM31 memory b) internal pure returns (bool) {
        return CM31Field.eq(a.first, b.first) && CM31Field.eq(a.second, b.second);
    }

    /// @notice Multiplication by CM31 scalar
    /// @param a QM31 element
    /// @param scalar CM31 scalar
    /// @return Product a * scalar
    function mulCM31(QM31 memory a, CM31Field.CM31 memory scalar) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.mul(a.first, scalar),
            CM31Field.mul(a.second, scalar)
        );
    }

    /// @notice Try to convert QM31 to M31 (real number)
    /// @param a QM31 element
    /// @return success True if conversion is possible (all non-real parts are zero)
    /// @return value The real part if conversion is successful
    function tryToReal(QM31 memory a) internal pure returns (bool success, uint32 value) {
        if (!CM31Field.isZero(a.second)) {
            return (false, 0);
        }
        return CM31Field.tryToReal(a.first);
    }

    /// @notice Check if a QM31 element is valid (all components are valid)
    /// @param a Element to check
    /// @return True if all CM31 components are valid
    function isValid(QM31 memory a) internal pure returns (bool) {
        return CM31Field.isValid(a.first) && CM31Field.isValid(a.second);
    }

    /// @notice Convert QM31 to M31 array representation [a, b, c, d]
    /// @param a QM31 element
    /// @return Array with [first.real, first.imag, second.real, second.imag]
    function toM31Array(QM31 memory a) internal pure returns (uint32[4] memory) {
        return [a.first.real, a.first.imag, a.second.real, a.second.imag];
    }

    /// @notice Create QM31 from M31 array representation [a, b, c, d]
    /// @param arr Array with [first.real, first.imag, second.real, second.imag]
    /// @return QM31 element
    function fromM31Array(uint32[4] memory arr) internal pure returns (QM31 memory) {
        return fromM31(arr[0], arr[1], arr[2], arr[3]);
    }

    /// @notice Power function for small exponents
    /// @param base Base element
    /// @param exponent Exponent (should be small for gas efficiency)
    /// @return base^exponent
    function pow(QM31 memory base, uint32 exponent) internal pure returns (QM31 memory) {
        if (exponent == 0) return one();
        if (exponent == 1) return base;
        if (isZero(base)) return zero();

        QM31 memory result = one();
        QM31 memory currentBase = base;

        while (exponent > 0) {
            if (exponent & 1 == 1) {
                result = mul(result, currentBase);
            }
            currentBase = square(currentBase);
            exponent >>= 1;
        }

        return result;
    }
}