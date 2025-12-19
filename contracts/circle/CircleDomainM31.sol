// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../cosets/CosetM31.sol";
import "./CirclePointM31.sol";
import "../fields/QM31Field.sol";

/// @title CircleDomain
/// @notice A valid domain for circle polynomial interpolation and evaluation
library CircleDomain {
    using CosetM31 for CosetM31.CosetStruct;
    using CosetM31 for CosetM31.CirclePointIndex;
    using CirclePointM31 for CirclePointM31.Point;

    /// @notice Maximum log size for circle domain
    uint32 public constant MAX_CIRCLE_DOMAIN_LOG_SIZE = CosetM31.M31_CIRCLE_LOG_ORDER - 1;

    /// @notice Circle domain structure representing +-C + <G_n>
    struct CircleDomainStruct {
        CosetM31.CosetStruct halfCoset;
    }

    /// @notice Error thrown when log size exceeds maximum
    error LogSizeTooLarge(uint32 logSizeParam, uint32 maxLogSize);

    /// @notice Error thrown when index is out of bounds
    error IndexOutOfBounds(uint256 index, uint256 maxIndex);


    /// @notice Create a new circle domain from a half coset
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
    function halfCoset(CircleDomainStruct memory domain)
        internal
        pure
        returns (CosetM31.CosetStruct memory halfCoset)
    {
        halfCoset = domain.halfCoset;
    }

    /// @notice Get the size of the circle domain
    function size(CircleDomainStruct memory domain)
        internal
        pure
        returns (uint256 domainSize)
    {
        domainSize = 1 << logSize(domain);
    }

    /// @notice Get the log size of the circle domain
    function logSize(CircleDomainStruct memory domain)
        internal
        pure
        returns (uint32 domainLogSize)
    {
        domainLogSize = domain.halfCoset.logSize + 1;
    }


    /// @notice Get circle point at specific index in domain
    function at(CircleDomainStruct memory domain, uint256 index)
        internal
        pure
        returns (CirclePointM31.Point memory point)
    {
        CosetM31.CirclePointIndex memory pointIndex = indexAt(domain, index);
        point = CosetM31.indexToPoint(pointIndex);
    }

    /// @notice Get circle point index at specific position in domain
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
            pointIndex = CosetM31.indexAt(domain.halfCoset, index);
        } else {
            CosetM31.CirclePointIndex memory halfCosetIndex = CosetM31.indexAt(
                domain.halfCoset, 
                index - halfCosetSize
            );
            pointIndex = CosetM31.negIndex(halfCosetIndex);
        }
    }

    /// @notice Check if the domain is canonic
    function isCanonic(CircleDomainStruct memory domain)
        internal
        pure
        returns (bool isCanonic)
    {
        CosetM31.CirclePointIndex memory initialTimes4 = CosetM31.mulIndex(
            domain.halfCoset.initialIndex,
            4
        );
        isCanonic = (initialTimes4.value == domain.halfCoset.stepSize.value);
    }

    /// @notice Shift circle domain by adding offset
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
    function split(CircleDomainStruct memory domain, uint32 logParts)
        internal
        pure
        returns (CircleDomainStruct memory subdomain, CosetM31.CirclePointIndex[] memory shifts)
    {
        require(logParts <= domain.halfCoset.logSize, "logParts too large");
        CosetM31.CosetStruct memory newHalfCoset = CosetM31.newCoset(
            domain.halfCoset.initialIndex,
            domain.halfCoset.logSize - logParts
        );
        subdomain = CircleDomainStruct({
            halfCoset: newHalfCoset
        });

        uint256 numShifts = 1 << logParts;
        shifts = new CosetM31.CirclePointIndex[](numShifts);
        for (uint256 i = 0; i < numShifts; i++) {
            shifts[i] = CosetM31.mulIndex(domain.halfCoset.stepSize, i);
        }
    }

    /// @notice Get all points in circle domain as array
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
    function equal(CircleDomainStruct memory a, CircleDomainStruct memory b)
        internal
        pure
        returns (bool isEqual)
    {
        isEqual = CosetM31.equal(a.halfCoset, b.halfCoset);
    }

    /// @notice Validate that circle domain is properly formed
    function validate(CircleDomainStruct memory domain)
        internal
        pure
        returns (bool isValid, string memory errorMessage)
    {
        if (domain.halfCoset.logSize == 0) {
            return (false, "Half coset log size cannot be zero");
        }
        
        if (domain.halfCoset.logSize >= MAX_CIRCLE_DOMAIN_LOG_SIZE) {
            return (false, "Half coset log size exceeds maximum circle domain size");
        }

        return (true, "Valid circle domain");
    }

    /// @notice Get conjugate of the half coset
    function getConjugateHalfCoset(CircleDomainStruct memory domain)
        internal
        pure
        returns (CosetM31.CosetStruct memory conjugateCoset)
    {
        conjugateCoset = CosetM31.conjugate(domain.halfCoset);
    }

    /// @notice Check if index is in first half (half coset) or second half (conjugate)
    function isIndexInFirstHalf(CircleDomainStruct memory domain, uint256 index)
        internal
        pure
        returns (bool inFirstHalf)
    {
        uint256 halfCosetSize = CosetM31.size(domain.halfCoset);
        inFirstHalf = index < halfCosetSize;
    }
}