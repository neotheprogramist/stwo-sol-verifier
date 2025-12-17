// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../circle/CirclePointM31.sol";
import "../fields/M31Field.sol";
import "../fields/CM31Field.sol";

/// @title CosetM31
/// @notice Represents a coset in the circle group using M31 points: initial + <step>
/// @dev Implements coset operations equivalent to Rust stwo implementation with M31
library CosetM31 {
    using CirclePointM31 for CirclePointM31.Point;
    using M31Field for uint32;

    /// @notice Circle point index for efficient coset calculations
    struct CirclePointIndex {
        uint32 value;
    }

    /// @notice Coset structure representing initial + <step> with M31 points
    struct CosetStruct {
        CirclePointIndex initialIndex;     // Index of initial point
        CirclePointM31.Point initial;      // Initial M31 point in coset
        CirclePointIndex stepSize;         // Step size as index
        CirclePointM31.Point step;         // Step M31 point for iteration
        uint32 logSize;                    // Log2 of coset size
    }

    /// @notice Circle group constants (same as regular Coset)
    uint32 public constant M31_CIRCLE_LOG_ORDER = 31;
    uint32 public constant M31_CIRCLE_ORDER = uint32(1 << M31_CIRCLE_LOG_ORDER);

    /// @notice Generator of the full circle group
    uint32 public constant M31_CIRCLE_GEN_X = 2;
    uint32 public constant M31_CIRCLE_GEN_Y = 1268011823;

    /// @notice Error thrown when log size exceeds circle order
    error LogSizeTooLarge(uint32 logSizeParam, uint32 maxLogSize);

    /// @notice Error thrown when index is out of bounds
    error IndexOutOfBounds(uint256 index, uint256 maxIndex);

    // =============================================================================
    // CirclePointIndex Operations
    // =============================================================================

    /// @notice Create zero circle point index
    /// @return index Zero index
    function zeroIndex() internal pure returns (CirclePointIndex memory index) {
        index.value = 0;
    }

    /// @notice Create circle point index from value
    /// @param value Index value
    /// @return index Circle point index
    function indexFromValue(uint32 value) internal pure returns (CirclePointIndex memory index) {
        index.value = value;
    }

    /// @notice Create subgroup generator index
    /// @param logSizeParam Log size of subgroup
    /// @return index Generator index
    function subgroupGen(uint32 logSizeParam) internal pure returns (CirclePointIndex memory index) {
        if (logSizeParam > M31_CIRCLE_LOG_ORDER) {
            revert LogSizeTooLarge(logSizeParam, M31_CIRCLE_LOG_ORDER);
        }
        
        if (logSizeParam == M31_CIRCLE_LOG_ORDER) {
            index.value = 1;
        } else {
            index.value = uint32(1 << (M31_CIRCLE_LOG_ORDER - logSizeParam));
        }
    }

    /// @notice Add two circle point indices
    /// @param a First index
    /// @param b Second index
    /// @return sum Sum of indices
    function addIndices(CirclePointIndex memory a, CirclePointIndex memory b) 
        internal 
        pure 
        returns (CirclePointIndex memory sum) 
    {
        sum.value = a.value + b.value;
    }

    /// @notice Multiply circle point index by scalar
    /// @param index Index to multiply
    /// @param scalar Scalar multiplier
    /// @return product Product of index and scalar
    function mulIndex(CirclePointIndex memory index, uint256 scalar) 
        internal 
        pure 
        returns (CirclePointIndex memory product) 
    {
        product.value = uint32((uint256(index.value) * scalar) % M31_CIRCLE_ORDER);
    }

    /// @notice Negate circle point index
    /// @dev Maps to Rust: Self((1 << M31_CIRCLE_LOG_ORDER) - self.0).reduce()
    /// @param index Index to negate
    /// @return negated Negated index
    function negIndex(CirclePointIndex memory index) 
        internal 
        pure 
        returns (CirclePointIndex memory negated) 
    {
        // Rust: Self((1 << M31_CIRCLE_LOG_ORDER) - self.0).reduce()
        // Since M31_CIRCLE_ORDER = 1 << M31_CIRCLE_LOG_ORDER, this is:
        // (M31_CIRCLE_ORDER - index.value) % M31_CIRCLE_ORDER
        if (index.value == 0) {
            negated.value = 0;
        } else {
            negated.value = M31_CIRCLE_ORDER - index.value;
        }
    }

    /// @notice Convert circle point index to actual M31 circle point
    /// @dev Maps to Rust: M31_CIRCLE_GEN.mul(index.value as u128)
    /// @param index Index to convert
    /// @return point M31 circle point at index (generator^index)
    function indexToPoint(CirclePointIndex memory index)
        internal
        pure
        returns (CirclePointM31.Point memory point)
    {
        // Rust: M31_CIRCLE_GEN.mul(self.0 as u128)
        if (index.value == 0) {
            // Identity element: (1, 0) in M31
            return CirclePointM31.Point({
                x: M31Field.one(),
                y: M31Field.zero()
            });
        }
        
        // Use CirclePointM31.mul directly - this should match Rust implementation
        // The generator in Rust is the primitive element that generates the circle group
        CirclePointM31.Point memory generator = CirclePointM31.Point({
            x: M31_CIRCLE_GEN_X,
            y: M31_CIRCLE_GEN_Y
        });
        return CirclePointM31.mul(generator, index.value);
    }

    // =============================================================================
    // Coset Construction
    // =============================================================================

    /// @notice Create new coset from index and log size (main constructor)
    /// @param initialIndex Starting index of coset
    /// @param logSizeParam Log2 of coset size
    /// @return coset New coset structure
    function newCoset(CirclePointIndex memory initialIndex, uint32 logSizeParam)
        internal
        pure
        returns (CosetStruct memory coset)
    {
        if (logSizeParam > M31_CIRCLE_LOG_ORDER) {
            revert LogSizeTooLarge(logSizeParam, M31_CIRCLE_LOG_ORDER);
        }

        CirclePointIndex memory stepSize = subgroupGen(logSizeParam);
        
        coset = CosetStruct({
            initialIndex: initialIndex,
            initial: indexToPoint(initialIndex),
            stepSize: stepSize,
            step: indexToPoint(stepSize),
            logSize: logSizeParam
        });
    }

    /// @notice Create new coset with M31 points (alternative constructor)
    /// @param initial Initial M31 point
    /// @param step Step M31 point
    /// @param logSize Log2 of coset size
    /// @return coset New coset structure
    function newCosetFromPoints(
        CirclePointM31.Point memory initial,
        CirclePointM31.Point memory step,
        uint32 logSize
    ) internal pure returns (CosetStruct memory coset) {
        if (logSize > M31_CIRCLE_LOG_ORDER) {
            revert LogSizeTooLarge(logSize, M31_CIRCLE_LOG_ORDER);
        }

        coset.initial = initial;
        coset.step = step;
        coset.logSize = logSize;
        
        // Set indices (simplified - would need proper point-to-index conversion)
        coset.initialIndex = zeroIndex();
        coset.stepSize = indexFromValue(uint32(1 << (M31_CIRCLE_LOG_ORDER - logSize)));
    }

    /// @notice Create coset from generator and log size
    /// @param logSize Log2 of coset size
    /// @return coset New coset with generator step
    function fromGenerator(uint32 logSize) internal pure returns (CosetStruct memory coset) {
        CirclePointM31.Point memory generator = CirclePointM31.Point({
            x: M31_CIRCLE_GEN_X,
            y: M31_CIRCLE_GEN_Y
        });
        
        CirclePointM31.Point memory initial = CirclePointM31.zero();
        uint32 stepPower = M31_CIRCLE_LOG_ORDER - logSize;
        CirclePointM31.Point memory step = CirclePointM31.mul(generator, 1 << stepPower);
        
        return newCosetFromPoints(initial, step, logSize);
    }

    /// @notice Create a subgroup coset of the form <G_n>
    /// @param logSizeParam Log size of subgroup
    /// @return coset Subgroup coset
    function subgroup(uint32 logSizeParam) internal pure returns (CosetStruct memory coset) {
        CirclePointIndex memory zero = zeroIndex();
        coset = newCoset(zero, logSizeParam);
    }

    /// @notice Create an odds coset of the form G_2n + <G_n>
    /// @param logSizeParam Log size parameter
    /// @return coset Odds coset
    function odds(uint32 logSizeParam) internal pure returns (CosetStruct memory coset) {
        CirclePointIndex memory gen = subgroupGen(logSizeParam + 1);
        coset = newCoset(gen, logSizeParam);
    }

    /// @notice Create a half-odds coset of the form G_4n + <G_n>
    /// @param logSizeParam Log size parameter
    /// @return coset Half-odds coset
    function halfOdds(uint32 logSizeParam) internal pure returns (CosetStruct memory coset) {
        CirclePointIndex memory gen = subgroupGen(logSizeParam + 2);
        coset = newCoset(gen, logSizeParam);
    }

    // =============================================================================
    // Coset Operations
    // =============================================================================

    /// @notice Get M31 point at specific index in coset
    /// @param coset Coset to access
    /// @param index Index within coset
    /// @return point M31 point at index
    function at(CosetStruct memory coset, uint256 index) 
        internal 
        pure 
        returns (CirclePointM31.Point memory point) 
    {
        uint256 maxIndex = 1 << coset.logSize;
        if (index >= maxIndex) {
            revert IndexOutOfBounds(index, maxIndex - 1);
        }
        
        // point = initial + index * step
        CirclePointM31.Point memory indexStep = CirclePointM31.mul(coset.step, index);
        point = CirclePointM31.add(coset.initial, indexStep);
    }

    /// @notice Get circle point index at specific position
    /// @param coset Coset to access
    /// @param index Position within coset
    /// @return pointIndex Index of point at position
    function indexAt(CosetStruct memory coset, uint256 index) 
        internal 
        pure 
        returns (CirclePointIndex memory pointIndex) 
    {
        uint256 maxIndex = 1 << coset.logSize;
        if (index >= maxIndex) {
            revert IndexOutOfBounds(index, maxIndex - 1);
        }
        
        CirclePointIndex memory indexStep = mulIndex(coset.stepSize, index);
        pointIndex = addIndices(coset.initialIndex, indexStep);
    }

    /// @notice Get size of coset
    /// @param coset Coset to measure
    /// @return cosetSize Number of points in coset
    function size(CosetStruct memory coset) internal pure returns (uint256 cosetSize) {
        return 1 << coset.logSize;
    }

    /// @notice Get log size of coset
    /// @dev Direct access to coset.logSize field is preferred
    /// @param coset Coset to measure
    /// @return logSizeValue Log2 of coset size
    function logSizeFunc(CosetStruct memory coset) internal pure returns (uint32 logSizeValue) {
        return coset.logSize;
    }

    /// @notice Get initial M31 point of coset
    /// @param coset Coset to access
    /// @return initialPoint Initial M31 point
    function getInitial(CosetStruct memory coset) internal pure returns (CirclePointM31.Point memory initialPoint) {
        initialPoint = coset.initial;
    }

    /// @notice Get step M31 point of coset
    /// @param coset Coset to access
    /// @return stepPoint Step M31 point
    function getStep(CosetStruct memory coset) internal pure returns (CirclePointM31.Point memory stepPoint) {
        stepPoint = coset.step;
    }

    /// @notice Get initial index of coset
    /// @param coset Coset to access
    /// @return initialIdx Initial point index
    function getInitialIndex(CosetStruct memory coset) internal pure returns (CirclePointIndex memory initialIdx) {
        initialIdx = coset.initialIndex;
    }

    /// @notice Get step size index of coset
    /// @param coset Coset to access
    /// @return stepSizeIdx Step size index
    function getStepSize(CosetStruct memory coset) internal pure returns (CirclePointIndex memory stepSizeIdx) {
        stepSizeIdx = coset.stepSize;
    }

    // =============================================================================
    // Coset Relations
    // =============================================================================

    /// @notice Check if coset contains a specific M31 point
    /// @param coset Coset to check
    /// @param point M31 point to find
    /// @return contains True if point is in coset
    function contains(CosetStruct memory coset, CirclePointM31.Point memory point) 
        internal 
        pure 
        returns (bool) 
    {
        // Simplified implementation - would need proper discrete log
        // For now, check if point equals any coset element
        uint256 cosetSizeValue = size(coset);
        for (uint256 i = 0; i < cosetSizeValue; i++) {
            CirclePointM31.Point memory cosetPoint = at(coset, i);
            if (cosetPoint.x == point.x && cosetPoint.y == point.y) {
                return true;
            }
        }
        return false;
    }

    /// @notice Shift coset by adding an offset to initial index
    /// @dev Maps to Rust: coset.shift(shift_size)
    /// @param coset Original coset
    /// @param shiftSize Amount to shift initial index by
    /// @return shiftedCoset Coset with shifted initial point
    function shift(CosetStruct memory coset, CirclePointIndex memory shiftSize) 
        internal 
        pure 
        returns (CosetStruct memory shiftedCoset) 
    {
        // Rust: let initial_index = self.initial_index + shift_size;
        CirclePointIndex memory newInitialIndex = addIndices(coset.initialIndex, shiftSize);
        
        shiftedCoset = CosetStruct({
            initialIndex: newInitialIndex,
            initial: indexToPoint(newInitialIndex),
            stepSize: coset.stepSize,
            step: coset.step,
            logSize: coset.logSize
        });
    }

    /// @notice Create conjugate coset: -initial -<step>
    /// @dev Maps to Rust: coset.conjugate()
    /// @param coset Original coset
    /// @return conjugateCoset Conjugate coset
    function conjugate(CosetStruct memory coset) 
        internal 
        pure 
        returns (CosetStruct memory conjugateCoset) 
    {
        // Rust: let initial_index = -self.initial_index;
        // Rust: let step_size = -self.step_size;
        CirclePointIndex memory negInitialIndex = negIndex(coset.initialIndex);
        CirclePointIndex memory negStepSize = negIndex(coset.stepSize);
        
        conjugateCoset = CosetStruct({
            initialIndex: negInitialIndex,
            initial: indexToPoint(negInitialIndex),
            stepSize: negStepSize,
            step: indexToPoint(negStepSize),
            logSize: coset.logSize
        });
    }

    /// @notice Check if two cosets are equal
    /// @param a First coset
    /// @param b Second coset
    /// @return isEqual True if cosets are equal
    function equal(CosetStruct memory a, CosetStruct memory b) 
        internal 
        pure 
        returns (bool isEqual) 
    {
        return (a.initialIndex.value == b.initialIndex.value &&
                a.stepSize.value == b.stepSize.value &&
                a.logSize == b.logSize);
    }

    /// @notice Get half-sized coset (every second element)
    /// @param coset Original coset
    /// @return halfCosetResult Coset with half the elements
    function halfCoset(CosetStruct memory coset) internal pure returns (CosetStruct memory halfCosetResult) {
        require(coset.logSize > 0, "Cannot halve coset of size 1");
        
        halfCosetResult.initial = coset.initial;
        halfCosetResult.step = CirclePointM31.double(coset.step); // Double step size
        halfCosetResult.logSize = coset.logSize - 1;
        halfCosetResult.initialIndex = coset.initialIndex;
        halfCosetResult.stepSize = addIndices(coset.stepSize, coset.stepSize); // Double step index
    }

    /// @notice Double all points in coset (Rust: Coset::double)
    /// @dev Returns new coset with all points doubled
    /// @param coset Original coset
    /// @return doubled Coset with doubled points
    function double(CosetStruct memory coset) internal pure returns (CosetStruct memory doubled) {
        require(coset.logSize > 0, "Cannot double coset of size 1");
        
        // Rust: initial_index: self.initial_index * 2
        doubled.initialIndex = mulIndex(coset.initialIndex, 2);
        
        // Rust: initial: self.initial.double()
        doubled.initial = CirclePointM31.double(coset.initial);
        
        // Rust: step: self.step.double()
        doubled.step = CirclePointM31.double(coset.step);
        
        // Rust: step_size: self.step_size * 2
        doubled.stepSize = mulIndex(coset.stepSize, 2);
        
        // Rust: log_size: self.log_size.saturating_sub(1)
        doubled.logSize = coset.logSize - 1;
    }
}
