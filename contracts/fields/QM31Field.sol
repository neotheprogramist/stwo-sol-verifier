// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./CM31Field.sol";
import "./M31Field.sol";

/**
 * @title QM31Field
 * @notice Implementation of quaternion extension field over CM31 (QM31: CM31[u]/(u²-(2+i)))
 */
library QM31Field {
    using CM31Field for CM31Field.CM31;
    using M31Field for uint32;

    /// @notice Quaternion representation: first + second*u where u² = 2+i
    struct QM31 {
        CM31Field.CM31 first;
        CM31Field.CM31 second;
    }

    /// @notice The field size: (2^31 - 1)⁴ for QM31
    uint128 public constant P4 = 21267647892944572736998860269687930881;

    /// @notice Extension degree: QM31 has 4 M31 components
    uint256 public constant EXTENSION_DEGREE = 4;

    /// @notice The irreducible element R = 2 + i
    function R() internal pure returns (CM31Field.CM31 memory) {
        return CM31Field.fromM31(2, 1);
    }

    /// @notice Additive identity
    function zero() internal pure returns (QM31 memory) {
        return QM31(CM31Field.zero(), CM31Field.zero());
    }

    /// @notice Multiplicative identity
    function one() internal pure returns (QM31 memory) {
        return QM31(CM31Field.one(), CM31Field.zero());
    }

    /// @notice Create QM31 element from M31 components
    function fromM31(uint32 a, uint32 b, uint32 c, uint32 d) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.fromM31(a, b),
            CM31Field.fromM31(c, d)
        );
    }

    /// @notice Create QM31 element from CM31 components
    function fromCM31(CM31Field.CM31 memory first, CM31Field.CM31 memory second) internal pure returns (QM31 memory) {
        return QM31(first, second);
    }

    /// @notice Create QM31 element from real M31 element
    function fromReal(uint32 real) internal pure returns (QM31 memory) {
        return QM31(CM31Field.fromReal(real), CM31Field.zero());
    }

    /// @notice Create QM31 element from unchecked u32 values
    function fromU32Unchecked(uint32 a, uint32 b, uint32 c, uint32 d) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.fromU32Unchecked(a, b),
            CM31Field.fromU32Unchecked(c, d)
        );
    }

    /// @notice Combine partial evaluations into single QM31 value
    function fromPartialEvals(QM31[4] memory evals) internal pure returns (QM31 memory) {
        QM31 memory res = evals[0];
        
        QM31 memory basis_i = fromU32Unchecked(0, 1, 0, 0);
        res = add(res, mul(evals[1], basis_i));
        
        QM31 memory basis_u = fromU32Unchecked(0, 0, 1, 0);
        res = add(res, mul(evals[2], basis_u));
        
        QM31 memory basis_iu = fromU32Unchecked(0, 0, 0, 1);
        res = add(res, mul(evals[3], basis_iu));
        
        return res;
    }

    /// @notice Addition in QM31 field
    function add(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.add(a.first, b.first),
            CM31Field.add(a.second, b.second)
        );
    }

    /// @notice Subtraction in QM31 field
    function sub(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.sub(a.first, b.first),
            CM31Field.sub(a.second, b.second)
        );
    }

    /// @notice Negation in QM31 field
    function neg(QM31 memory a) internal pure returns (QM31 memory) {
        return QM31(
            CM31Field.neg(a.first),
            CM31Field.neg(a.second)
        );
    }

    /// @notice Multiplication in QM31 field: (a + bu) * (c + du) = (ac + R*bd) + (ad + bc)u where R = 2+i
    function mul(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        CM31Field.CM31 memory ac = CM31Field.mul(a.first, b.first);
        CM31Field.CM31 memory bd = CM31Field.mul(a.second, b.second);
        CM31Field.CM31 memory Rbd = CM31Field.mul(R(), bd);
        CM31Field.CM31 memory firstComponent = CM31Field.add(ac, Rbd);
        CM31Field.CM31 memory ad = CM31Field.mul(a.first, b.second);
        CM31Field.CM31 memory bc = CM31Field.mul(a.second, b.first);
        CM31Field.CM31 memory secondComponent = CM31Field.add(ad, bc);
        
        return QM31(firstComponent, secondComponent);
    }

    /// @notice Square operation in QM31 field
    function square(QM31 memory a) internal pure returns (QM31 memory) {
        return mul(a, a);
    }

    /// @notice Multiplicative inverse: (a + bu)⁻¹ = (a - bu) / (a² - R*b²) where R = 2+i
    function inverse(QM31 memory a) internal pure returns (QM31 memory) {
        if (isZero(a)) {
            revert("QM31Field: division by zero");
        }
        
        CM31Field.CM31 memory b2 = CM31Field.square(a.second);
        CM31Field.CM31 memory Rb2 = CM31Field.mul(R(), b2);
        CM31Field.CM31 memory a2 = CM31Field.square(a.first);
        CM31Field.CM31 memory denom = CM31Field.sub(a2, Rb2);
        CM31Field.CM31 memory denomInv = CM31Field.inverse(denom);
        
        return QM31(
            CM31Field.mul(a.first, denomInv),
            CM31Field.mul(CM31Field.neg(a.second), denomInv)
        );
    }

    /// @notice Division in QM31 field
    function div(QM31 memory a, QM31 memory b) internal pure returns (QM31 memory) {
        return mul(a, inverse(b));
    }

    /// @notice Check if QM31 element is zero
    function isZero(QM31 memory a) internal pure returns (bool) {
        return CM31Field.isZero(a.first) && CM31Field.isZero(a.second);
    }

    /// @notice Check if QM31 element is one
    function isOne(QM31 memory a) internal pure returns (bool) {
        return CM31Field.isOne(a.first) && CM31Field.isZero(a.second);
    }

    /// @notice Equality comparison
    function eq(QM31 memory a, QM31 memory b) internal pure returns (bool) {
        return CM31Field.eq(a.first, b.first) && CM31Field.eq(a.second, b.second);
    }

    /// @notice Multiplication by CM31 scalar
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