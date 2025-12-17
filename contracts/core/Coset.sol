// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./CirclePoint.sol";
import "../fields/QM31Field.sol";
import "../fields/CM31Field.sol";

/// @title Coset
/// @notice Represents a coset in the circle group: initial + <step>
library Coset {
    using CirclePoint for CirclePoint.Point;
    using QM31Field for QM31Field.QM31;

    /// @notice Circle point index for efficient coset calculations
    struct CirclePointIndex {
        uint32 value;
    }

    /// @notice Coset structure representing initial + <step>
    struct CosetStruct {
        CirclePointIndex initialIndex;  // Index of initial point
        CirclePoint.Point initial;      // Initial point in coset
        CirclePointIndex stepSize;      // Step size as index
        CirclePoint.Point step;         // Step point for iteration
        uint32 logSize;                 // Log2 of coset size
    }

    /// @notice Circle group constants
    uint32 public constant M31_CIRCLE_LOG_ORDER = 31;
    uint32 public constant M31_CIRCLE_ORDER = uint32(1 << M31_CIRCLE_LOG_ORDER);

    /// @notice Generator of the full circle group (simplified constant)
    uint32 public constant M31_CIRCLE_GEN_X_REAL = 2;
    uint32 public constant M31_CIRCLE_GEN_Y_REAL = 0;

    /// @notice Error thrown when log size exceeds circle order
    error LogSizeTooLarge(uint32 logSizeParam, uint32 maxLogSize);

    /// @notice Error thrown when index is out of bounds
    error IndexOutOfBounds(uint256 index, uint256 maxIndex);


    /// @notice Create zero circle point index
    /// @return index Zero index
    function zeroIndex() internal pure returns (CirclePointIndex memory index) {
        index.value = 0;
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

    /// @notice Create a new coset with given initial index and log size
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

    /// @notice Convert circle point index to actual circle point
    /// @param index Index to convert
    /// @return point Circle point at index
    function indexToPoint(CirclePointIndex memory index)
        internal
        pure
        returns (CirclePoint.Point memory point)
    {
        // Simplified conversion - in full implementation would use actual circle arithmetic
        if (index.value == 0) {
            // Identity element: (1, 0)
            point = CirclePoint.Point({
                x: QM31Field.QM31({
                    first: CM31Field.CM31({real: 1, imag: 0}),
                    second: CM31Field.CM31({real: 0, imag: 0})
                }),
                y: QM31Field.QM31({
                    first: CM31Field.CM31({real: 0, imag: 0}),
                    second: CM31Field.CM31({real: 0, imag: 0})
                })
            });
        } else {
            // Use simplified mapping - real implementation would compute generator^index
            point = CirclePoint.Point({
                x: QM31Field.QM31({
                    first: CM31Field.CM31({real: uint32(index.value), imag: 0}),
                    second: CM31Field.CM31({real: 0, imag: 0})
                }),
                y: QM31Field.QM31({
                    first: CM31Field.CM31({real: uint32(index.value >> 16), imag: 0}),
                    second: CM31Field.CM31({real: 0, imag: 0})
                })
            });
        }
    }

    // Additional helper functions...
    function addIndices(CirclePointIndex memory a, CirclePointIndex memory b)
        internal
        pure
        returns (CirclePointIndex memory sum)
    {
        sum.value = (a.value + b.value) % M31_CIRCLE_ORDER;
    }

    function mulIndex(CirclePointIndex memory index, uint256 scalar)
        internal
        pure
        returns (CirclePointIndex memory product)
    {
        product.value = uint32((uint256(index.value) * scalar) % M31_CIRCLE_ORDER);
    }

    function size(CosetStruct memory coset) internal pure returns (uint256 cosetSize) {
        cosetSize = 1 << coset.logSize;
    }

    function logSize(CosetStruct memory coset) internal pure returns (uint32 cosetLogSize) {
        cosetLogSize = coset.logSize;
    }

    function at(CosetStruct memory coset, uint256 index)
        internal
        pure
        returns (CirclePoint.Point memory point)
    {
        if (index >= size(coset)) {
            revert IndexOutOfBounds(index, size(coset) - 1);
        }

        CirclePointIndex memory pointIndex = indexAt(coset, index);
        point = indexToPoint(pointIndex);
    }

    function indexAt(CosetStruct memory coset, uint256 index)
        internal
        pure
        returns (CirclePointIndex memory pointIndex)
    {
        if (index >= size(coset)) {
            revert IndexOutOfBounds(index, size(coset) - 1);
        }

        CirclePointIndex memory offset = mulIndex(coset.stepSize, index);
        pointIndex = addIndices(coset.initialIndex, offset);
    }

    function double(CosetStruct memory coset) 
        internal 
        pure 
        returns (CosetStruct memory doubled) 
    {
        require(coset.logSize > 0, "Cannot double coset of size 1");

        CirclePointIndex memory newInitialIndex = mulIndex(coset.initialIndex, 2);
        CirclePointIndex memory newStepSize = mulIndex(coset.stepSize, 2);

        doubled = CosetStruct({
            initialIndex: newInitialIndex,
            initial: indexToPoint(newInitialIndex),
            stepSize: newStepSize,
            step: indexToPoint(newStepSize),
            logSize: coset.logSize - 1
        });
    }

    function repeatedDouble(CosetStruct memory coset, uint32 nDoubles)
        internal
        pure
        returns (CosetStruct memory result)
    {
        result = coset;
        for (uint32 i = 0; i < nDoubles; i++) {
            result = double(result);
        }
    }

    function shift(CosetStruct memory coset, CirclePointIndex memory shiftSize)
        internal
        pure
        returns (CosetStruct memory shifted)
    {
        CirclePointIndex memory newInitialIndex = addIndices(coset.initialIndex, shiftSize);
        
        shifted = CosetStruct({
            initialIndex: newInitialIndex,
            initial: indexToPoint(newInitialIndex),
            stepSize: coset.stepSize,
            step: coset.step,
            logSize: coset.logSize
        });
    }

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

    function conjugate(CosetStruct memory coset)
        internal
        pure
        returns (CosetStruct memory conjugated)
    {
        CirclePointIndex memory newInitialIndex = negIndex(coset.initialIndex);
        CirclePointIndex memory newStepSize = negIndex(coset.stepSize);

        conjugated = CosetStruct({
            initialIndex: newInitialIndex,
            initial: indexToPoint(newInitialIndex),
            stepSize: newStepSize,
            step: indexToPoint(newStepSize),
            logSize: coset.logSize
        });
    }

    function isDoublingOf(CosetStruct memory coset1, CosetStruct memory coset2)
        internal
        pure
        returns (bool isDoubling)
    {
        if (coset1.logSize > coset2.logSize) {
            return false;
        }

        uint32 nDoubles = coset2.logSize - coset1.logSize;
        CosetStruct memory doubled = repeatedDouble(coset2, nDoubles);

        isDoubling = (
            doubled.initialIndex.value == coset1.initialIndex.value &&
            doubled.stepSize.value == coset1.stepSize.value &&
            doubled.logSize == coset1.logSize
        );
    }

    function toArray(CosetStruct memory coset)
        internal
        pure
        returns (CirclePoint.Point[] memory points)
    {
        uint256 cosetSize = size(coset);
        points = new CirclePoint.Point[](cosetSize);

        for (uint256 i = 0; i < cosetSize; i++) {
            points[i] = at(coset, i);
        }
    }

    function equal(CosetStruct memory a, CosetStruct memory b)
        internal
        pure
        returns (bool isEqual)
    {
        isEqual = (
            a.initialIndex.value == b.initialIndex.value &&
            a.stepSize.value == b.stepSize.value &&
            a.logSize == b.logSize
        );
    }
}