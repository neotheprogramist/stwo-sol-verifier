// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./Coset.sol";
import "./CirclePoint.sol";
import "../fields/QM31Field.sol";
import "../fields/CM31Field.sol";

/// @title CanonicCoset
/// @notice A coset of the form G_{2n} + <G_n>, where G_n is the generator of the subgroup of order n
library CanonicCoset {
    using Coset for Coset.CosetStruct;
    using Coset for Coset.CirclePointIndex;
    using CirclePoint for CirclePoint.Point;

    /// @notice Canonic coset structure wrapping a base coset
    /// @param coset The underlying coset of the form G_{2n} + <G_n>
    struct CanonicCosetStruct {
        Coset.CosetStruct coset;
    }

    /// @notice Error thrown when log size is invalid for canonic coset
    error InvalidLogSize(uint32 logSize);

    /// @notice Error thrown when index is out of bounds
    error IndexOutOfBounds(uint256 index, uint256 maxIndex);


    /// @notice Create a new canonic coset
    /// @param logSize Log2 of the coset size (must be > 0)
    /// @return canonicCoset New canonic coset structure
    function newCanonicCoset(uint32 logSize) 
        internal 
        pure 
        returns (CanonicCosetStruct memory canonicCoset) 
    {
        if (logSize == 0) {
            revert InvalidLogSize(logSize);
        }

        Coset.CosetStruct memory baseCoset = Coset.odds(logSize);
        
        canonicCoset = CanonicCosetStruct({
            coset: baseCoset
        });
    }


    /// @notice Get the underlying coset
    /// @param canonicCoset Canonic coset to access
    /// @return cosetResult The underlying coset structure
    function coset(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (Coset.CosetStruct memory cosetResult) 
    {
        cosetResult = canonicCoset.coset;
    }

    /// @notice Get half of the coset (its conjugate complements to the whole coset)
    /// @param canonicCoset Canonic coset to access
    /// @return halfCoset Half coset G_{2n} + <G_{n/2}>
    function halfCoset(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (Coset.CosetStruct memory halfCoset)
    {
        require(Coset.logSize(canonicCoset.coset) > 0, "Cannot create half coset of size 1");
        halfCoset = Coset.halfOdds(Coset.logSize(canonicCoset.coset) - 1);
    }

    /// @notice Get the log size of the canonic coset
    /// @param canonicCoset Canonic coset to measure
    /// @return cosetLogSize Log2 of coset size
    function logSize(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (uint32 cosetLogSize) 
    {
        cosetLogSize = Coset.logSize(canonicCoset.coset);
    }

    /// @notice Get the size of the canonic coset
    /// @param canonicCoset Canonic coset to measure
    /// @return size Number of points in coset
    function size(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (uint256 size) 
    {
        size = Coset.size(canonicCoset.coset);
    }

    /// @notice Get the initial index of the canonic coset
    /// @param canonicCoset Canonic coset to access
    /// @return initialIndex Initial circle point index
    function initialIndex(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (Coset.CirclePointIndex memory initialIndex)
    {
        initialIndex = canonicCoset.coset.initialIndex;
    }

    /// @notice Get the step size of the canonic coset
    /// @param canonicCoset Canonic coset to access
    /// @return stepSize Step size as circle point index
    function stepSize(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (Coset.CirclePointIndex memory stepSize)
    {
        stepSize = canonicCoset.coset.stepSize;
    }

    /// @notice Get the step point of the canonic coset
    /// @param canonicCoset Canonic coset to access
    /// @return step Step point for iteration
    function step(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (CirclePoint.Point memory step)
    {
        step = canonicCoset.coset.step;
    }

    // =============================================================================
    // Point Access Functions
    // =============================================================================

    /// @notice Get circle point index at specific position in canonic coset
    /// @param canonicCoset Canonic coset to access
    /// @param index Index within coset
    /// @return pointIndex Index of point at position
    function indexAt(CanonicCosetStruct memory canonicCoset, uint256 index)
        internal
        pure
        returns (Coset.CirclePointIndex memory pointIndex)
    {
        pointIndex = Coset.indexAt(canonicCoset.coset, index);
    }

    /// @notice Get circle point at specific index in canonic coset
    /// @param canonicCoset Canonic coset to access
    /// @param index Index within coset
    /// @return point Point at index
    function at(CanonicCosetStruct memory canonicCoset, uint256 index)
        internal
        pure
        returns (CirclePoint.Point memory point)
    {
        point = Coset.at(canonicCoset.coset, index);
    }

    // =============================================================================
    // Domain Conversion Functions
    // =============================================================================

    /// @notice Convert canonic coset to circle domain representation
    /// @param canonicCoset Canonic coset to convert
    /// @return domain Circle domain with same points but different ordering
    function circleDomain(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (Coset.CosetStruct memory domain)
    {
        // Return the half coset which can be used to create a CircleDomain
        // The CircleDomain would be created as: CircleDomain.newCircleDomain(halfCoset(canonicCoset))
        domain = halfCoset(canonicCoset);
    }

    // =============================================================================
    // Coset Operations
    // =============================================================================

    /// @notice Double the canonic coset
    /// @param canonicCoset Canonic coset to double
    /// @return doubled Doubled canonic coset
    function double(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (CanonicCosetStruct memory doubled)
    {
        Coset.CosetStruct memory doubledCoset = Coset.double(canonicCoset.coset);
        doubled = CanonicCosetStruct({
            coset: doubledCoset
        });
    }

    /// @notice Apply repeated doubling to canonic coset
    /// @param canonicCoset Canonic coset to double repeatedly
    /// @param nDoubles Number of doubling operations
    /// @return result Repeatedly doubled canonic coset
    function repeatedDouble(CanonicCosetStruct memory canonicCoset, uint32 nDoubles)
        internal
        pure
        returns (CanonicCosetStruct memory result)
    {
        Coset.CosetStruct memory resultCoset = Coset.repeatedDouble(canonicCoset.coset, nDoubles);
        result = CanonicCosetStruct({
            coset: resultCoset
        });
    }

    /// @notice Shift canonic coset by adding offset
    /// @param canonicCoset Canonic coset to shift
    /// @param shiftSize Amount to shift by
    /// @return shifted Shifted canonic coset
    function shift(CanonicCosetStruct memory canonicCoset, Coset.CirclePointIndex memory shiftSize)
        internal
        pure
        returns (CanonicCosetStruct memory shifted)
    {
        Coset.CosetStruct memory shiftedCoset = Coset.shift(canonicCoset.coset, shiftSize);
        shifted = CanonicCosetStruct({
            coset: shiftedCoset
        });
    }

    /// @notice Create conjugate of canonic coset
    /// @param canonicCoset Canonic coset to conjugate
    /// @return conjugated Conjugate canonic coset
    function conjugate(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (CanonicCosetStruct memory conjugated)
    {
        Coset.CosetStruct memory conjugatedCoset = Coset.conjugate(canonicCoset.coset);
        conjugated = CanonicCosetStruct({
            coset: conjugatedCoset
        });
    }

    // =============================================================================
    // Utility Functions
    // =============================================================================

    /// @notice Get all points in canonic coset as array
    /// @param canonicCoset Canonic coset to enumerate
    /// @return points Array of all points in coset
    function toArray(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (CirclePoint.Point[] memory points)
    {
        points = Coset.toArray(canonicCoset.coset);
    }

    /// @notice Check if two canonic cosets are equal
    /// @param a First canonic coset
    /// @param b Second canonic coset
    /// @return isEqual True if cosets are equal
    function equal(CanonicCosetStruct memory a, CanonicCosetStruct memory b)
        internal
        pure
        returns (bool isEqual)
    {
        isEqual = Coset.equal(a.coset, b.coset);
    }

    /// @notice Check if one canonic coset is a doubling of another
    /// @param canonicCoset1 First canonic coset
    /// @param canonicCoset2 Second canonic coset
    /// @return isDoubling True if canonicCoset1 is a doubling of canonicCoset2
    function isDoublingOf(
        CanonicCosetStruct memory canonicCoset1, 
        CanonicCosetStruct memory canonicCoset2
    )
        internal
        pure
        returns (bool isDoubling)
    {
        isDoubling = Coset.isDoublingOf(canonicCoset1.coset, canonicCoset2.coset);
    }

    // =============================================================================
    // Advanced Operations for Mask Points
    // =============================================================================

    /// @notice Apply offset to canonic coset point (for mask point generation)
    /// @param canonicCoset Base canonic coset
    /// @param basePoint Base point to offset from
    /// @param offset Offset to apply
    /// @return offsetPoint Point with offset applied
    function applyOffset(
        CanonicCosetStruct memory canonicCoset,
        CirclePoint.Point memory basePoint,
        int32 offset
    )
        internal
        pure
        returns (CirclePoint.Point memory offsetPoint)
    {
        if (offset == 0) {
            offsetPoint = basePoint;
            return offsetPoint;
        }

        // Get step point for applying offset
        CirclePoint.Point memory stepPoint = canonicCoset.coset.step;
        
        if (offset > 0) {
            // Apply positive offset by adding step points
            offsetPoint = basePoint;
            for (uint32 i = 0; i < uint32(offset); i++) {
                offsetPoint = offsetPoint.add(stepPoint);
            }
        } else {
            // Apply negative offset by subtracting step points
            offsetPoint = basePoint;
            for (uint32 i = 0; i < uint32(-offset); i++) {
                offsetPoint = offsetPoint.sub(stepPoint);
            }
        }
    }

    /// @notice Generate mask points for given coset and offsets
    /// @param canonicCoset Base canonic coset
    /// @param basePoint Base point for mask generation
    /// @param offsets Array of offsets to apply
    /// @return maskPoints Array of points with offsets applied
    function generateMaskPoints(
        CanonicCosetStruct memory canonicCoset,
        CirclePoint.Point memory basePoint,
        int32[] memory offsets
    )
        internal
        pure
        returns (CirclePoint.Point[] memory maskPoints)
    {
        maskPoints = new CirclePoint.Point[](offsets.length);
        
        for (uint256 i = 0; i < offsets.length; i++) {
            maskPoints[i] = applyOffset(canonicCoset, basePoint, offsets[i]);
        }
    }

    // =============================================================================
    // Validation Functions
    // =============================================================================

    /// @notice Validate that canonic coset is properly formed
    /// @param canonicCoset Canonic coset to validate
    /// @return isValid True if coset is valid
    /// @return errorMessage Error description if invalid
    function validate(CanonicCosetStruct memory canonicCoset)
        internal
        pure
        returns (bool isValid, string memory errorMessage)
    {
        // Check log size is reasonable
        if (Coset.logSize(canonicCoset.coset) == 0) {
            return (false, "Log size cannot be zero");
        }
        
        if (Coset.logSize(canonicCoset.coset) > Coset.M31_CIRCLE_LOG_ORDER) {
            return (false, "Log size exceeds circle order");
        }

        // Check that this is indeed an odds coset (canonic form)
        Coset.CosetStruct memory expectedOdds = Coset.odds(Coset.logSize(canonicCoset.coset));
        if (!Coset.equal(canonicCoset.coset, expectedOdds)) {
            return (false, "Not a valid canonic coset (should be odds coset)");
        }

        return (true, "Valid canonic coset");
    }
}