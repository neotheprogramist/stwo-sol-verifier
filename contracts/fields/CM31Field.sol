// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./M31Field.sol";

/**
 * @title CM31Field
 * @notice Implementation of complex extension field over M31 (CM31: M31[i]/(i²+1))
 */
library CM31Field {
    using M31Field for uint32;

    /// @notice Complex number representation: real + imag*i
    struct CM31 {
        uint32 real;
        uint32 imag;
    }

    /// @notice The field size: (2^31 - 1)² for CM31
    uint64 public constant P2 = 4611686014132420609;

    /// @notice Additive identity
    function zero() internal pure returns (CM31 memory) {
        return CM31(0, 0);
    }

    /// @notice Multiplicative identity
    function one() internal pure returns (CM31 memory) {
        return CM31(1, 0);
    }

    /// @notice Imaginary unit
    function imaginaryUnit() internal pure returns (CM31 memory) {
        return CM31(0, 1);
    }

    /// @notice Create CM31 element from M31 components
    function fromM31(uint32 real, uint32 imag) internal pure returns (CM31 memory) {
        return CM31(real, imag);
    }

    /// @notice Create CM31 element from real M31 element
    function fromReal(uint32 real) internal pure returns (CM31 memory) {
        return CM31(real, 0);
    }

    /// @notice Create CM31 element from unchecked u32 values
    function fromU32Unchecked(uint32 real, uint32 imag) internal pure returns (CM31 memory) {
        return CM31(real % M31Field.MODULUS, imag % M31Field.MODULUS);
    }

    /// @notice Addition in CM31 field
    function add(CM31 memory a, CM31 memory b) internal pure returns (CM31 memory) {
        return CM31(
            M31Field.add(a.real, b.real),
            M31Field.add(a.imag, b.imag)
        );
    }

    /// @notice Subtraction in CM31 field
    function sub(CM31 memory a, CM31 memory b) internal pure returns (CM31 memory) {
        return CM31(
            M31Field.sub(a.real, b.real),
            M31Field.sub(a.imag, b.imag)
        );
    }

    /// @notice Negation in CM31 field
    function neg(CM31 memory a) internal pure returns (CM31 memory) {
        return CM31(
            M31Field.neg(a.real),
            M31Field.neg(a.imag)
        );
    }

    /// @notice Multiplication in CM31 field: (a + bi) * (c + di) = (ac - bd) + (ad + bc)i
    function mul(CM31 memory a, CM31 memory b) internal pure returns (CM31 memory) {
        uint32 realPart = M31Field.sub(
            M31Field.mul(a.real, b.real),
            M31Field.mul(a.imag, b.imag)
        );
        
        uint32 imagPart = M31Field.add(
            M31Field.mul(a.real, b.imag),
            M31Field.mul(a.imag, b.real)
        );
        
        return CM31(realPart, imagPart);
    }

    /// @notice Square operation in CM31 field
    /// @param a Value to square
    /// @return Square a²
    function square(CM31 memory a) internal pure returns (CM31 memory) {
        // (a + bi)² = (a² - b²) + (2ab)i
        uint32 realPart = M31Field.sub(
            M31Field.square(a.real),
            M31Field.square(a.imag)
        );
        
        uint32 imagPart = M31Field.mul(
            M31Field.mul(2, a.real),
            a.imag
        );
        
        return CM31(realPart, imagPart);
    }

    /// @notice Complex conjugate
    /// @param a Complex number
    /// @return Conjugate conj(a) = real - imag*i
    function conjugate(CM31 memory a) internal pure returns (CM31 memory) {
        return CM31(a.real, M31Field.neg(a.imag));
    }

    /// @notice Norm of complex number (a² + b²)
    /// @param a Complex number
    /// @return Norm |a|² = real² + imag²
    function norm(CM31 memory a) internal pure returns (uint32) {
        return M31Field.add(
            M31Field.square(a.real),
            M31Field.square(a.imag)
        );
    }

    /// @notice Multiplicative inverse in CM31 field
    /// @param a Value to invert (must be non-zero)
    /// @return Inverse a⁻¹ such that a * a⁻¹ = 1
    /// @dev 1/(a + bi) = (a - bi)/(a² + b²)
    function inverse(CM31 memory a) internal pure returns (CM31 memory) {
        if (isZero(a)) {
            revert("CM31Field: division by zero");
        }
        
        uint32 normValue = norm(a);
        uint32 normInverse = M31Field.inverse(normValue);
        
        return CM31(
            M31Field.mul(a.real, normInverse),
            M31Field.mul(M31Field.neg(a.imag), normInverse)
        );
    }

    /// @notice Division in CM31 field
    /// @param a Dividend
    /// @param b Divisor (must be non-zero)
    /// @return Quotient a / b = a * b⁻¹
    function div(CM31 memory a, CM31 memory b) internal pure returns (CM31 memory) {
        return mul(a, inverse(b));
    }

    /// @notice Check if CM31 element is zero
    /// @param a Element to check
    /// @return True if a == 0 + 0i
    function isZero(CM31 memory a) internal pure returns (bool) {
        return a.real == 0 && a.imag == 0;
    }

    /// @notice Check if CM31 element is one
    /// @param a Element to check
    /// @return True if a == 1 + 0i
    function isOne(CM31 memory a) internal pure returns (bool) {
        return a.real == 1 && a.imag == 0;
    }

    /// @notice Check if CM31 element is purely real
    /// @param a Element to check
    /// @return True if imaginary part is zero
    function isReal(CM31 memory a) internal pure returns (bool) {
        return a.imag == 0;
    }

    /// @notice Check if CM31 element is purely imaginary
    /// @param a Element to check
    /// @return True if real part is zero
    function isPurelyImaginary(CM31 memory a) internal pure returns (bool) {
        return a.real == 0;
    }

    /// @notice Equality comparison
    /// @param a First element
    /// @param b Second element
    /// @return True if a == b
    function eq(CM31 memory a, CM31 memory b) internal pure returns (bool) {
        return a.real == b.real && a.imag == b.imag;
    }

    /// @notice Addition with M31 element (real number)
    /// @param a CM31 element
    /// @param b M31 element to add to real part
    /// @return Sum a + b
    function addReal(CM31 memory a, uint32 b) internal pure returns (CM31 memory) {
        return CM31(M31Field.add(a.real, b), a.imag);
    }

    /// @notice Subtraction with M31 element (real number)
    /// @param a CM31 element
    /// @param b M31 element to subtract from real part
    /// @return Difference a - b
    function subReal(CM31 memory a, uint32 b) internal pure returns (CM31 memory) {
        return CM31(M31Field.sub(a.real, b), a.imag);
    }

    /// @notice Multiplication with M31 element (scalar multiplication)
    /// @param a CM31 element
    /// @param b M31 scalar
    /// @return Product a * b
    function mulScalar(CM31 memory a, uint32 b) internal pure returns (CM31 memory) {
        return CM31(
            M31Field.mul(a.real, b),
            M31Field.mul(a.imag, b)
        );
    }

    /// @notice Division by M31 element (scalar division)
    /// @param a CM31 element
    /// @param b M31 scalar (must be non-zero)
    /// @return Quotient a / b
    function divScalar(CM31 memory a, uint32 b) internal pure returns (CM31 memory) {
        uint32 bInverse = M31Field.inverse(b);
        return mulScalar(a, bInverse);
    }

    /// @notice Try to convert CM31 to M31 (real number)
    /// @param a CM31 element
    /// @return success True if conversion is possible (imaginary part is zero)
    /// @return value The real part if conversion is successful
    function tryToReal(CM31 memory a) internal pure returns (bool success, uint32 value) {
        if (a.imag == 0) {
            return (true, a.real);
        }
        return (false, 0);
    }

    /// @notice Power function for small exponents
    /// @param base Base element
    /// @param exponent Exponent (should be small for gas efficiency)
    /// @return base^exponent
    function pow(CM31 memory base, uint32 exponent) internal pure returns (CM31 memory) {
        if (exponent == 0) return one();
        if (exponent == 1) return base;
        if (isZero(base)) return zero();

        CM31 memory result = one();
        CM31 memory currentBase = base;

        while (exponent > 0) {
            if (exponent & 1 == 1) {
                result = mul(result, currentBase);
            }
            currentBase = square(currentBase);
            exponent >>= 1;
        }

        return result;
    }

    /// @notice Batch inversion using Montgomery's trick
    /// @param elements Array of CM31 elements to invert
    /// @return inverses Array of inverted elements
    /// @dev More efficient than individual inversions for multiple elements
    function batchInverse(CM31[] memory elements) internal pure returns (CM31[] memory inverses) {
        uint256 n = elements.length;
        if (n == 0) return new CM31[](0);

        inverses = new CM31[](n);
        CM31[] memory products = new CM31[](n);

        // Check for zeros and compute forward products
        if (isZero(elements[0])) {
            revert("CM31Field: division by zero");
        }
        products[0] = elements[0];

        for (uint256 i = 1; i < n; i++) {
            if (isZero(elements[i])) {
                revert("CM31Field: division by zero");
            }
            products[i] = mul(products[i-1], elements[i]);
        }

        // Compute inverse of the product of all elements
        CM31 memory allInverse = inverse(products[n-1]);

        // Compute individual inverses using backward pass
        for (uint256 i = n - 1; i > 0; i--) {
            inverses[i] = mul(allInverse, products[i-1]);
            allInverse = mul(allInverse, elements[i]);
        }
        inverses[0] = allInverse;

        return inverses;
    }

    /// @notice Batch conjugation
    /// @param elements Array of CM31 elements
    /// @return conjugates Array of conjugated elements
    function batchConjugate(CM31[] memory elements) internal pure returns (CM31[] memory conjugates) {
        uint256 n = elements.length;
        conjugates = new CM31[](n);
        
        for (uint256 i = 0; i < n; i++) {
            conjugates[i] = conjugate(elements[i]);
        }
        
        return conjugates;
    }

    /// @notice Check if a CM31 element is valid (components are valid M31 elements)
    /// @param a Element to check
    /// @return True if both real and imaginary parts are valid M31 elements
    function isValid(CM31 memory a) internal pure returns (bool) {
        return M31Field.isValid(a.real) && M31Field.isValid(a.imag);
    }

    /// @notice Convert CM31 to array representation [real, imag]
    /// @param a CM31 element
    /// @return Array with [real, imag] components
    function toArray(CM31 memory a) internal pure returns (uint32[2] memory) {
        return [a.real, a.imag];
    }

    /// @notice Create CM31 from array representation [real, imag]
    /// @param arr Array with [real, imag] components
    /// @return CM31 element
    function fromArray(uint32[2] memory arr) internal pure returns (CM31 memory) {
        return CM31(arr[0], arr[1]);
    }
}