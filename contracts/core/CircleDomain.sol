// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./CosetM31.sol";
import "./CirclePointM31.sol";
import "../fields/QM31Field.sol";

/// @title CircleDomain
/// @notice A valid domain for circle polynomial interpolation and evaluation
/// @dev Valid domains are a disjoint union of two conjugate cosets: +-C + <G_n>
/// @dev The ordering defined on this domain is C + iG_n, and then -C - iG_n
library CircleDomain {
    using CosetM31 for CosetM31.CosetStruct;
    using CosetM31 for CosetM31.CirclePointIndex;
    using CirclePointM31 for CirclePointM31.Point;

    /// @notice Maximum log size for circle domain
    uint32 public constant MAX_CIRCLE_DOMAIN_LOG_SIZE = CosetM31.M31_CIRCLE_LOG_ORDER - 1;

    /// @notice Circle domain structure representing +-C + <G_n>
    /// @param halfCoset The coset C that defines the domain +-C + <G_n>
    struct CircleDomainStruct {
        CosetM31.CosetStruct halfCoset;
    }

    /// @notice Error thrown when log size exceeds maximum
    error LogSizeTooLarge(uint32 logSizeParam, uint32 maxLogSize);

    /// @notice Error thrown when index is out of bounds
    error IndexOutOfBounds(uint256 index, uint256 maxIndex);


    /// @notice Create a new circle domain from a half coset
    /// @dev Given a coset C + <G_n>, constructs the circle domain +-C + <G_n>
    /// @param halfCoset The coset that defines half of the domain
    /// @return domain New circle domain structure
    function newCircleDomain(CosetM31.CosetStruct memory halfCoset)
        internal
        pure
        returns (CircleDomainStruct memory domain)
    {
        if (halfCoset.logSize >= MAX_CIRCLE_DOMAIN_LOG_SIZE) {
            revert LogSizeTooLarge(halfCoset.logSize, MAX_CIRCLE_DOMAIN_LOG_SIZE);
        }

        domain = CircleDomainStruct({
            halfCoset: halfCoset
        });
    }


    /// @notice Get the half coset that defines the domain
    /// @param domain Circle domain to access
    /// @return halfCoset The half coset structure
    function halfCoset(CircleDomainStruct memory domain)
        internal
        pure
        returns (CosetM31.CosetStruct memory halfCoset)
    {
        halfCoset = domain.halfCoset;
    }

    /// @notice Get the size of the circle domain
    /// @param domain Circle domain to measure
    /// @return domainSize Number of points in domain (2 * half coset size)
    function size(CircleDomainStruct memory domain)
        internal
        pure
        returns (uint256 domainSize)
    {
        domainSize = 1 << logSize(domain);
    }

    /// @notice Get the log size of the circle domain
    /// @param domain Circle domain to measure
    /// @return domainLogSize Log2 of domain size
    function logSize(CircleDomainStruct memory domain)
        internal
        pure
        returns (uint32 domainLogSize)
    {
        domainLogSize = domain.halfCoset.logSize + 1;
    }


    /// @notice Get circle point at specific index in domain
    /// @dev For i < half_coset_size: returns half_coset[i]
    /// @dev For i >= half_coset_size: returns -half_coset[i - half_coset_size]
    /// @param domain Circle domain to access
    /// @param index Index within domain
    /// @return point Point at index
    function at(CircleDomainStruct memory domain, uint256 index)
        internal
        pure
        returns (CirclePointM31.Point memory point)
    {
        CosetM31.CirclePointIndex memory pointIndex = indexAt(domain, index);
        point = CosetM31.indexToPoint(pointIndex);
    }

    /// @notice Get circle point index at specific position in domain
    /// @param domain Circle domain to access
    /// @param index Index within domain
    /// @return pointIndex Index of point at position
    function indexAt(CircleDomainStruct memory domain, uint256 index)
        internal
        pure
        returns (CosetM31.CirclePointIndex memory pointIndex)
    {
        uint256 halfCosetSize = CosetM31.size(domain.halfCoset);
        
        if (index >= size(domain)) {
            revert IndexOutOfBounds(index, size(domain) - 1);
        }

        if (index < halfCosetSize) {
            // First half: return half_coset[index]
            pointIndex = CosetM31.indexAt(domain.halfCoset, index);
        } else {
            // Second half: return -half_coset[index - half_coset_size]
            CosetM31.CirclePointIndex memory halfCosetIndex = CosetM31.indexAt(
                domain.halfCoset, 
                index - halfCosetSize
            );
            pointIndex = CosetM31.negIndex(halfCosetIndex);
        }
    }

    // =============================================================================
    // Domain Properties
    // =============================================================================

    /// @notice Check if the domain is canonic
    /// @dev Canonic domains are domains with elements that are the entire set of points
    /// @dev defined by G_2n + <G_n> where G_n and G_2n are obtained by repeatedly
    /// @dev doubling the circle generator
    /// @param domain Circle domain to check
    /// @return isCanonic True if domain is canonic
    function isCanonic(CircleDomainStruct memory domain)
        internal
        pure
        returns (bool isCanonic)
    {
        // Check if half_CosetM31.initial_index * 4 == half_CosetM31.step_size
        CosetM31.CirclePointIndex memory initialTimes4 = CosetM31.mulIndex(
            domain.halfCoset.initialIndex,
            4
        );
        isCanonic = (initialTimes4.value == domain.halfCoset.stepSize.value);
    }

    // =============================================================================
    // Domain Operations
    // =============================================================================

    /// @notice Shift circle domain by adding offset
    /// @param domain Circle domain to shift
    /// @param shiftSize Amount to shift by
    /// @return shifted Shifted circle domain
    function shift(CircleDomainStruct memory domain, CosetM31.CirclePointIndex memory shiftSize)
        internal
        pure
        returns (CircleDomainStruct memory shifted)
    {
        CosetM31.CosetStruct memory shiftedHalfCoset = CosetM31.shift(domain.halfCoset, shiftSize);
        shifted = CircleDomainStruct({
            halfCoset: shiftedHalfCoset
        });
    }

    /// @notice Split a circle domain into smaller domains with offsets
    /// @param domain Circle domain to split
    /// @param logParts Log2 of number of parts to split into
    /// @return subdomain The smaller domain
    /// @return shifts Array of shift indices for each part
    function split(CircleDomainStruct memory domain, uint32 logParts)
        internal
        pure
        returns (CircleDomainStruct memory subdomain, CosetM31.CirclePointIndex[] memory shifts)
    {
        require(logParts <= domain.halfCoset.logSize, "logParts too large");

        // Create subdomain with reduced log size
        CosetM31.CosetStruct memory newHalfCoset = CosetM31.newCoset(
            domain.halfCoset.initialIndex,
            domain.halfCoset.logSize - logParts
        );
        subdomain = CircleDomainStruct({
            halfCoset: newHalfCoset
        });

        // Generate shift indices
        uint256 numShifts = 1 << logParts;
        shifts = new CosetM31.CirclePointIndex[](numShifts);
        for (uint256 i = 0; i < numShifts; i++) {
            shifts[i] = CosetM31.mulIndex(domain.halfCoset.stepSize, i);
        }
    }

    // =============================================================================
    // Utility Functions
    // =============================================================================

    /// @notice Get all points in circle domain as array
    /// @dev Returns first the half coset, then its conjugate
    /// @param domain Circle domain to enumerate
    /// @return points Array of all points in domain
    function toArray(CircleDomainStruct memory domain)
        internal
        pure
        returns (CirclePointM31.Point[] memory points)
    {
        uint256 domainSize = size(domain);
        points = new CirclePointM31.Point[](domainSize);

        for (uint256 i = 0; i < domainSize; i++) {
            points[i] = at(domain, i);
        }
    }

    /// @notice Check if two circle domains are equal
    /// @param a First circle domain
    /// @param b Second circle domain
    /// @return isEqual True if domains are equal
    function equal(CircleDomainStruct memory a, CircleDomainStruct memory b)
        internal
        pure
        returns (bool isEqual)
    {
        isEqual = CosetM31.equal(a.halfCoset, b.halfCoset);
    }

    // =============================================================================
    // Validation Functions
    // =============================================================================

    /// @notice Validate that circle domain is properly formed
    /// @param domain Circle domain to validate
    /// @return isValid True if domain is valid
    /// @return errorMessage Error description if invalid
    function validate(CircleDomainStruct memory domain)
        internal
        pure
        returns (bool isValid, string memory errorMessage)
    {
        // Check log size is reasonable
        if (domain.halfCoset.logSize == 0) {
            return (false, "Half coset log size cannot be zero");
        }
        
        if (domain.halfCoset.logSize >= MAX_CIRCLE_DOMAIN_LOG_SIZE) {
            return (false, "Half coset log size exceeds maximum circle domain size");
        }

        // Validate the underlying half coset
        // Additional validation could be added here

        return (true, "Valid circle domain");
    }

    // =============================================================================
    // Iterator Helpers (for future extension)
    // =============================================================================

    /// @notice Get conjugate of the half coset
    /// @param domain Circle domain to access
    /// @return conjugateCoset Conjugate of the half coset
    function getConjugateHalfCoset(CircleDomainStruct memory domain)
        internal
        pure
        returns (CosetM31.CosetStruct memory conjugateCoset)
    {
        conjugateCoset = CosetM31.conjugate(domain.halfCoset);
    }

    /// @notice Check if index is in first half (half coset) or second half (conjugate)
    /// @param domain Circle domain to check
    /// @param index Index to check
    /// @return inFirstHalf True if index is in first half
    function isIndexInFirstHalf(CircleDomainStruct memory domain, uint256 index)
        internal
        pure
        returns (bool inFirstHalf)
    {
        uint256 halfCosetSize = CosetM31.size(domain.halfCoset);
        inFirstHalf = index < halfCosetSize;
    }
}