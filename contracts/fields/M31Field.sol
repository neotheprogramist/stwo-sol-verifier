// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title M31Field
 * @notice Implementation of the Mersenne-31 field arithmetic (M31: Z/(2^31-1)Z)
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
    
    /// @notice Reduces val modulo P when val is in range [0, 2P)
    function partialReduce(uint32 val) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let isGTE := iszero(lt(val, 0x7fffffff))
            result := sub(val, mul(isGTE, 0x7fffffff))
        }
    }
    
    /// @notice Reduces val modulo P when val is in range [0, P^2)
    function reduce(uint64 val) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let step1 := add(add(shr(31, val), val), 1)
            let step2 := add(shr(31, step1), val)
            result := and(step2, 0x7fffffff)
        }
    }
    
    /// @notice Addition in M31 field
    function add(uint32 a, uint32 b) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let sum := add(a, b)
            let isGTE := iszero(lt(sum, 0x7fffffff))
            result := sub(sum, mul(isGTE, 0x7fffffff))
        }
    }
    
    /// @notice Subtraction in M31 field
    function sub(uint32 a, uint32 b) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let diff := add(sub(a, b), 0x7fffffff)
            let isGTE := iszero(lt(diff, 0x7fffffff))
            result := sub(diff, mul(isGTE, 0x7fffffff))
        }
    }
    
    /// @notice Negation in M31 field
    function neg(uint32 a) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let isZero := iszero(a)
            let negValue := sub(0x7fffffff, a)
            let isGTE := iszero(lt(negValue, 0x7fffffff))
            result := mul(iszero(isZero), sub(negValue, mul(isGTE, 0x7fffffff)))
        }
    }
    
    /// @notice Multiplication in M31 field
    function mul(uint32 a, uint32 b) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let product := mul(a, b)
            let step1 := add(add(shr(31, product), product), 1)
            let step2 := add(shr(31, step1), product)
            result := and(step2, 0x7fffffff)
        }
    }
    
    /// @notice Square operation in M31 field
    function square(uint32 a) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let product := mul(a, a)
            let step1 := add(add(shr(31, product), product), 1)
            let step2 := add(shr(31, step1), product)
            result := and(step2, 0x7fffffff)
        }
    }
    
    /// @notice Multiplicative inverse in M31 field using a^(P-2) mod P
    function inverse(uint32 a) internal pure returns (uint32) {
        if (a == 0) {
            revert("M31Field: division by zero");
        }
        return pow2147483645(a);
    }
    
    /// @notice Convert signed 32-bit integer to M31 field element
    function fromI32(int32 value) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            let isNegative := slt(value, 0)
            let absValue := sub(xor(value, sub(0, isNegative)), isNegative)
            let doubleModulus := mul(0x7fffffff, 2)
            let adjustedValue := sub(doubleModulus, mul(isNegative, absValue))
            let finalValue := add(mul(iszero(isNegative), absValue), mul(isNegative, adjustedValue))
            
            let step1 := add(add(shr(31, finalValue), finalValue), 1)
            let step2 := add(shr(31, step1), finalValue)
            result := and(step2, 0x7fffffff)
        }
    }
    
    /// @notice Batch inversion using Montgomery's trick
    function batchInverse(uint32[] memory elements) internal pure returns (uint32[] memory inverses) {
        uint256 n = elements.length;
        if (n == 0) return new uint32[](0);
        
        assembly ("memory-safe") {
            let elementsPtr := add(elements, 0x20)
            
            inverses := mload(0x40)
            mstore(inverses, n)
            let inversesPtr := add(inverses, 0x20)
            mstore(0x40, add(inversesPtr, mul(n, 0x20)))
            
            let products := mload(0x40)
            mstore(products, n)
            let productsPtr := add(products, 0x20)
            mstore(0x40, add(productsPtr, mul(n, 0x20)))
            
            let firstElement := mload(elementsPtr)
            if iszero(firstElement) {
                revert(0, 0)
            }
            mstore(productsPtr, firstElement)
            
            for { let i := 1 } lt(i, n) { i := add(i, 1) } {
                let element := mload(add(elementsPtr, mul(i, 0x20)))
                if iszero(element) {
                    revert(0, 0)
                }
                let prevProduct := mload(add(productsPtr, mul(sub(i, 1), 0x20)))
                
                let product := mul(prevProduct, element)
                let step1 := add(add(shr(31, product), product), 1)
                let step2 := add(shr(31, step1), product)
                let result := and(step2, 0x7fffffff)
                
                mstore(add(productsPtr, mul(i, 0x20)), result)
            }
        }
        
        uint32 lastProduct;
        uint256 elementsPtr;
        uint256 inversesPtr;
        uint256 productsPtr;
        
        assembly ("memory-safe") {
            elementsPtr := add(elements, 0x20)
            inversesPtr := add(inverses, 0x20)
            
            let products := mload(0x40)
            mstore(products, n)
            productsPtr := add(products, 0x20)
            mstore(0x40, add(productsPtr, mul(n, 0x20)))
            
            lastProduct := mload(add(productsPtr, mul(sub(n, 1), 0x20)))
        }
        uint32 allInverse = inverse(lastProduct);
        
        assembly ("memory-safe") {
            for { let i := sub(n, 1) } gt(i, 0) { i := sub(i, 1) } {
                let prevProduct := mload(add(productsPtr, mul(sub(i, 1), 0x20)))
                let element := mload(add(elementsPtr, mul(i, 0x20)))
                
                let product1 := mul(allInverse, prevProduct)
                let step1_1 := add(add(shr(31, product1), product1), 1)
                let step2_1 := add(shr(31, step1_1), product1)
                let invResult := and(step2_1, 0x7fffffff)
                mstore(add(inversesPtr, mul(i, 0x20)), invResult)
                
                let product2 := mul(allInverse, element)
                let step1_2 := add(add(shr(31, product2), product2), 1)
                let step2_2 := add(shr(31, step1_2), product2)
                allInverse := and(step2_2, 0x7fffffff)
            }
            mstore(inversesPtr, allInverse)
        }
        
        return inverses;
    }
    
    /// @notice Computes a^(P-2) = a^2147483645 using optimized exponentiation chain
    function pow2147483645(uint32 a) internal pure returns (uint32) {
        uint32 t0 = mul(sqn(sqn(a)), a);
        uint32 t1 = mul(sqn(t0), t0);
        uint32 t2 = mul(sqn(sqn(sqn(t1))), t0);
        uint32 t3 = mul(sqn(t2), t0);
        uint32 t4 = mul(sqn8(t3), t3);
        uint32 t5 = mul(sqn8(t4), t3);
        return mul(sqn7(t5), t2);
    }
    
    /// @notice Square a value once (v^2)
    function sqn(uint32 v) internal pure returns (uint32) {
        return square(v);
    }
    
    /// @notice Square a value 7 times (v^128)
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
    
    /// @notice Square a value 8 times (v^256)
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
    
    /// @notice Check if a value is a valid field element
    function isValid(uint32 a) internal pure returns (bool) {
        return a < MODULUS;
    }
    
    /// @notice Power function for small exponents
    function pow(uint32 base, uint32 exponent) internal pure returns (uint32 result) {
        assembly ("memory-safe") {
            switch exponent
            case 0 {
                result := 1
            }
            case 1 {
                result := base
            }
            default {
                if iszero(base) {
                    result := 0
                }
                if base {
                    result := 1
                    let currentBase := base
                    
                    for {} gt(exponent, 0) {} {
                        if and(exponent, 1) {
                            let product := mul(result, currentBase)
                            let step1 := add(add(shr(31, product), product), 1)
                            let step2 := add(shr(31, step1), product)
                            result := and(step2, 0x7fffffff)
                        }
                        
                        let squareProduct := mul(currentBase, currentBase)
                        let step1_sq := add(add(shr(31, squareProduct), squareProduct), 1)
                        let step2_sq := add(shr(31, step1_sq), squareProduct)
                        currentBase := and(step2_sq, 0x7fffffff)
                        
                        exponent := shr(1, exponent)
                    }
                }
            }
        }
    }
}