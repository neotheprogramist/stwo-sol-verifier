// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title M31Field
 * @notice Implementation of the Mersenne-31 field arithmetic (M31: Z/(2^31-1)Z)
 * @dev This library implements field operations for the base field used in STWO.
 *      The field modulus is P = 2^31 - 1 = 2147483647 (Mersenne prime)
 */
library M31Field {
    /// @notice The field modulus: 2^31 - 1
    uint32 public constant MODULUS = 2147483647;
    
    /// @notice Number of bits in the modulus
    uint32 public constant MODULUS_BITS = 31;
    
    /// @notice Additive identity
    function zero() internal pure returns (uint32) {
        return 0;
    }
    
    /// @notice Multiplicative identity
    function one() internal pure returns (uint32) {
        return 1;
    }
    
    /**
     * @notice Reduces val modulo P when val is in range [0, 2P)
     * @param val Value to reduce
     * @return Reduced value in range [0, P)
     */
    function partialReduce(uint32 val) internal pure returns (uint32) {
        // If val >= P, return val - P, otherwise return val
        if (val >= MODULUS) {
            return val - MODULUS;
        }
        return val;
    }
    
    /**
     * @notice Reduces val modulo P when val is in range [0, P^2)
     * @param val 64-bit value to reduce
     * @return Reduced value in range [0, P)
     * @dev Uses the optimized reduction algorithm from the Rust implementation
     */
    function reduce(uint64 val) internal pure returns (uint32) {
        uint64 step1 = (val >> MODULUS_BITS) + val + 1;
        uint64 step2 = (step1 >> MODULUS_BITS) + val;
        return uint32(step2 & uint64(MODULUS));
    }
    
    /**
     * @notice Addition in M31 field
     * @param a First operand
     * @param b Second operand
     * @return Sum a + b mod P
     */
    function add(uint32 a, uint32 b) internal pure returns (uint32) {
        return partialReduce(a + b);
    }
    
    /**
     * @notice Subtraction in M31 field
     * @param a Minuend
     * @param b Subtrahend
     * @return Difference a - b mod P
     */
    function sub(uint32 a, uint32 b) internal pure returns (uint32) {
        return partialReduce(a + MODULUS - b);
    }
    
    /**
     * @notice Negation in M31 field
     * @param a Value to negate
     * @return Negated value -a mod P
     */
    function neg(uint32 a) internal pure returns (uint32) {
        if (a == 0) return 0;
        
        return partialReduce(MODULUS - a);
    }
    
    /**
     * @notice Multiplication in M31 field
     * @param a First operand
     * @param b Second operand
     * @return Product a * b mod P
     */
    function mul(uint32 a, uint32 b) internal pure returns (uint32) {
        return reduce(uint64(a) * uint64(b));
    }
    
    /**
     * @notice Square operation in M31 field
     * @param a Value to square
     * @return Square a^2 mod P
     */
    function square(uint32 a) internal pure returns (uint32) {
        return reduce(uint64(a) * uint64(a));
    }
    
    /**
     * @notice Multiplicative inverse in M31 field
     * @param a Value to invert (must be non-zero)
     * @return Inverse a^(-1) mod P such that a * a^(-1) ≡ 1 (mod P)
     * @dev Uses optimized exponentiation algorithm: a^(P-2) mod P
     */
    function inverse(uint32 a) internal pure returns (uint32) {
        if (a == 0) {
            revert("M31Field: division by zero");
        }
        return pow2147483645(a);
    }
    
    /**
     * @notice Convert signed 32-bit integer to M31 field element
     * @param value Signed integer to convert
     * @return Field element equivalent to value mod P
     */
    function fromI32(int32 value) internal pure returns (uint32) {
        if (value < 0) {
            // For negative values: 2*P - |value|, then reduce
            uint64 absValue = uint64(uint32(value >= 0 ? uint32(value) : uint32(-value)));
            uint64 result = (2 * uint64(MODULUS)) - absValue;
            return reduce(result);
        }
        return reduce(uint64(uint32(value)));
    }
    
    /**
     * @notice Batch inversion using Montgomery's trick
     * @param elements Array of field elements to invert
     * @return inverses Array of inverted elements
     * @dev More efficient than individual inversions for multiple elements
     */
    function batchInverse(uint32[] memory elements) internal pure returns (uint32[] memory inverses) {
        uint256 n = elements.length;
        if (n == 0) return new uint32[](0);
        
        inverses = new uint32[](n);
        uint32[] memory products = new uint32[](n);
        
        // Check for zeros and compute forward products
        if (elements[0] == 0) {
            revert("M31Field: division by zero");
        }
        products[0] = elements[0];
        
        for (uint256 i = 1; i < n; i++) {
            if (elements[i] == 0) {
                revert("M31Field: division by zero");
            }
            products[i] = mul(products[i-1], elements[i]);
        }
        
        // Compute inverse of the product of all elements
        uint32 allInverse = inverse(products[n-1]);
        
        // Compute individual inverses using backward pass
        for (uint256 i = n - 1; i > 0; i--) {
            inverses[i] = mul(allInverse, products[i-1]);
            allInverse = mul(allInverse, elements[i]);
        }
        inverses[0] = allInverse;
        
        return inverses;
    }
    
    /**
     * @notice Computes a^(P-2) = a^2147483645 for multiplicative inverse
     * @param a Base value
     * @return a^2147483645 mod P
     * @dev Uses optimized exponentiation chain with 37 multiplications
     *      Exact translation of Rust implementation
     */
    function pow2147483645(uint32 a) internal pure returns (uint32) {
        // sqn<2>(v) * v = v^4 * v = v^5
        uint32 t0 = mul(sqn(sqn(a)), a);
        
        // sqn<1>(t0) * t0 = t0^2 * t0 = t0^3 = v^15
        uint32 t1 = mul(sqn(t0), t0);
        
        // sqn<3>(t1) * t0 = t1^8 * t0 = v^120 * v^5 = v^125
        uint32 t2 = mul(sqn(sqn(sqn(t1))), t0);
        
        // sqn<1>(t2) * t0 = t2^2 * t0 = v^250 * v^5 = v^255
        uint32 t3 = mul(sqn(t2), t0);
        
        // sqn<8>(t3) * t3 = t3^256 * t3 = v^(255*256) * v^255 = v^(255*257)
        uint32 t4 = mul(sqn8(t3), t3);
        
        // sqn<8>(t4) * t3 = t4^256 * t3 = v^(255*257*256) * v^255 = v^(255*(257*256+1))
        uint32 t5 = mul(sqn8(t4), t3);
        
        // sqn<7>(t5) * t2 = t5^128 * t2 = final result
        return mul(sqn7(t5), t2);
    }
    
    /**
     * @notice Square a value once (v^2)
     */
    function sqn(uint32 v) internal pure returns (uint32) {
        return square(v);
    }
    
    /**
     * @notice Square a value 7 times (v^(2^7) = v^128)
     */
    function sqn7(uint32 v) internal pure returns (uint32) {
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        return v;
    }
    
    /**
     * @notice Square a value 8 times (v^(2^8) = v^256)
     */
    function sqn8(uint32 v) internal pure returns (uint32) {
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        v = square(v);
        return v;
    }
    
    /**
     * @notice Check if a value is a valid field element
     * @param a Value to check
     * @return True if a < P, false otherwise
     */
    function isValid(uint32 a) internal pure returns (bool) {
        return a < MODULUS;
    }
    
    /**
     * @notice Power function for small exponents
     * @param base Base value
     * @param exponent Exponent (should be small for gas efficiency)
     * @return base^exponent mod P
     */
    function pow(uint32 base, uint32 exponent) internal pure returns (uint32) {
        if (exponent == 0) return 1;
        if (exponent == 1) return base;
        if (base == 0) return 0;
        
        uint32 result = 1;
        uint32 currentBase = base;
        
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