// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../circle/CirclePointM31.sol";
import "../fields/M31Field.sol";
import "../fields/CM31Field.sol";

/// @title CosetM31
/// @notice Represents a coset in the circle group using M31 points
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

    /// @notice Create zero circle point index
    function zeroIndex() internal pure returns (CirclePointIndex memory index) {
        index.value = 0;
    }

    /// @notice Create circle point index from value
    function indexFromValue(uint32 value) internal pure returns (CirclePointIndex memory index) {
        index.value = value;
    }

    /// @notice Create subgroup generator index
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
    function addIndices(CirclePointIndex memory a, CirclePointIndex memory b) 
        internal 
        pure 
        returns (CirclePointIndex memory sum) 
    {
        sum.value = a.value + b.value;
    }

    /// @notice Multiply circle point index by scalar
    function mulIndex(CirclePointIndex memory index, uint256 scalar) 
        internal 
        pure 
        returns (CirclePointIndex memory product) 
    {
        product.value = uint32((uint256(index.value) * scalar) % M31_CIRCLE_ORDER);
    }

    /// @notice Negate circle point index
    function negIndex(CirclePointIndex memory index) 
        internal 
        pure 
        returns (CirclePointIndex memory negated) 
    {
        if (index.value == 0) {
            negated.value = 0;
        } else {
            negated.value = M31_CIRCLE_ORDER - index.value;
        }
    }

    /// @notice Convert circle point index to actual M31 circle point
    function indexToPoint(CirclePointIndex memory index)
        internal
        pure
        returns (CirclePointM31.Point memory point)
    {
        if (index.value == 0) {
            return CirclePointM31.Point({
                x: M31Field.one(),
                y: M31Field.zero()
            });
        }
        
        CirclePointM31.Point memory generator = CirclePointM31.Point({
            x: M31_CIRCLE_GEN_X,
            y: M31_CIRCLE_GEN_Y
        });
        return CirclePointM31.mul(generator, index.value);
    }

    /// @notice Create new coset from index and log size
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

    /// @notice Create new coset with M31 points
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
        
        coset.initialIndex = zeroIndex();
        coset.stepSize = indexFromValue(uint32(1 << (M31_CIRCLE_LOG_ORDER - logSize)));
    }

    /// @notice Create coset from generator and log size
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
    function subgroup(uint32 logSizeParam) internal pure returns (CosetStruct memory coset) {
        CirclePointIndex memory zero = zeroIndex();
        coset = newCoset(zero, logSizeParam);
    }

    /// @notice Create an odds coset of the form G_2n + <G_n>
    function odds(uint32 logSizeParam) internal pure returns (CosetStruct memory coset) {
        CirclePointIndex memory gen = subgroupGen(logSizeParam + 1);
        coset = newCoset(gen, logSizeParam);
    }

    /// @notice Create a half-odds coset of the form G_4n + <G_n>
    function halfOdds(uint32 logSizeParam) internal pure returns (CosetStruct memory coset) {
        CirclePointIndex memory gen = subgroupGen(logSizeParam + 2);
        coset = newCoset(gen, logSizeParam);
    }

    /// @notice Get M31 point at specific index in coset
    function at(CosetStruct memory coset, uint256 index) 
        internal 
        pure 
        returns (CirclePointM31.Point memory point) 
    {
        uint256 maxIndex = 1 << coset.logSize;
        if (index >= maxIndex) {
            revert IndexOutOfBounds(index, maxIndex - 1);
        }
        
        CirclePointM31.Point memory indexStep = CirclePointM31.mul(coset.step, index);
        point = CirclePointM31.add(coset.initial, indexStep);
    }

    /// @notice Get circle point index at specific position
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
    function size(CosetStruct memory coset) internal pure returns (uint256 cosetSize) {
        return 1 << coset.logSize;
    }

    /// @notice Get log size of coset
    function logSizeFunc(CosetStruct memory coset) internal pure returns (uint32 logSizeValue) {
        return coset.logSize;
    }

    /// @notice Get initial M31 point of coset
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
