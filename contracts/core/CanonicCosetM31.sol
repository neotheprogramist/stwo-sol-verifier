// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./CosetM31.sol";
import "./CirclePointM31.sol";

/// @title CanonicCosetM31
/// @notice Canonical coset implementation using M31 points
/// @dev Wraps CosetM31 to provide canonical coset functionality matching Rust implementation
library CanonicCosetM31 {
    using CosetM31 for CosetM31.CosetStruct;
    using CirclePointM31 for CirclePointM31.Point;

    /// @notice Canonical coset structure using M31
    struct CanonicCosetStruct {
        CosetM31.CosetStruct coset;  // Underlying M31 coset
    }

    /// @notice Error thrown when log size is invalid
    error InvalidLogSize(uint32 logSize);

    // =============================================================================
    // Constructor Functions
    // =============================================================================

    /// @notice Create new canonical coset with M31 points
    /// @param logSize Log2 of coset size
    /// @return canonicCoset New canonical coset
    function newCanonicCoset(uint32 logSize) 
        internal 
        pure 
        returns (CanonicCosetStruct memory canonicCoset) 
    {
        if (logSize == 0 || logSize > CosetM31.M31_CIRCLE_LOG_ORDER) {
            revert InvalidLogSize(logSize);
        }
        
        canonicCoset.coset = CosetM31.odds(logSize);
    }

    // =============================================================================
    // Access Functions
    // =============================================================================

    /// @notice Get underlying M31 coset
    /// @param canonicCoset Canonical coset to access
    /// @return coset Underlying M31 coset
    function coset(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (CosetM31.CosetStruct memory coset) 
    {
        coset = canonicCoset.coset;
    }

    /// @notice Get half-sized canonical coset
    /// @dev Rust: Coset::half_odds(self.log_size() - 1)
    /// @param canonicCoset Canonical coset to halve
    /// @return halfCosetResult Half-sized coset (G_4n + <G_n>)
    function halfCoset(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (CosetM31.CosetStruct memory halfCosetResult) 
    {
        // Rust: Coset::half_odds(self.log_size() - 1)
        uint32 logSize = canonicCoset.coset.logSize;
        require(logSize > 0, "Cannot halve coset of size 1");
        halfCosetResult = CosetM31.halfOdds(logSize - 1);
    }

    /// @notice Get log size of canonical coset
    /// @param canonicCoset Canonical coset to measure
    /// @return logSizeValue Log2 of coset size
    function logSize(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (uint32 logSizeValue) 
    {
        logSizeValue = canonicCoset.coset.logSizeFunc();
    }

    /// @notice Get size of canonical coset
    /// @param canonicCoset Canonical coset to measure
    /// @return size Number of points in coset
    function size(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (uint256 size) 
    {
        size = 1 << canonicCoset.coset.logSize;
    }

    /// @notice Get initial index of canonical coset
    /// @param canonicCoset Canonical coset to access
    /// @return initialIndex Initial point index
    function initialIndex(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (CosetM31.CirclePointIndex memory initialIndex) 
    {
        initialIndex = canonicCoset.coset.initialIndex;
    }

    /// @notice Get step size index of canonical coset
    /// @param canonicCoset Canonical coset to access
    /// @return stepSize Step size index
    function stepSize(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (CosetM31.CirclePointIndex memory stepSize) 
    {
        stepSize = canonicCoset.coset.stepSize;
    }

    /// @notice Get step M31 point of canonical coset
    /// @param canonicCoset Canonical coset to access
    /// @return step Step M31 point for iteration
    function step(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (CirclePointM31.Point memory step) 
    {
        step = canonicCoset.coset.step;
    }

    // =============================================================================
    // Point Access Functions
    // =============================================================================

    /// @notice Get circle point index at specific position in canonical coset
    /// @param canonicCoset Canonical coset to access
    /// @param index Index within coset
    /// @return pointIndex Index of point at position
    function indexAt(CanonicCosetStruct memory canonicCoset, uint256 index) 
        internal 
        pure 
        returns (CosetM31.CirclePointIndex memory pointIndex) 
    {
        pointIndex = CosetM31.indexAt(canonicCoset.coset, index);
    }

    /// @notice Get M31 point at specific index in canonical coset
    /// @param canonicCoset Canonical coset to access
    /// @param index Index within coset
    /// @return point M31 point at index
    function at(CanonicCosetStruct memory canonicCoset, uint256 index) 
        internal 
        pure 
        returns (CirclePointM31.Point memory point) 
    {
        point = CosetM31.at(canonicCoset.coset, index);
    }

    // =============================================================================
    // Utility Functions
    // =============================================================================

    /// @notice Check if canonical coset is canonic (always true by definition)
    /// @param canonicCoset Canonical coset to check
    /// @return isCanonic Always true for canonical cosets
    function isCanonic(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (bool isCanonic) 
    {
        canonicCoset; // Silence unused parameter warning
        isCanonic = true;
    }

    /// @notice Convert canonical coset to string representation for debugging
    /// @param canonicCoset Canonical coset to represent
    /// @return representation String representation
    function toString(CanonicCosetStruct memory canonicCoset) 
        internal 
        pure 
        returns (string memory representation) 
    {
        uint32 logSizeValue = logSize(canonicCoset);
        uint256 sizeValue = size(canonicCoset);
        
        representation = string(abi.encodePacked(
            "CanonicCosetM31(logSize=",
            _uint32ToString(logSizeValue),
            ", size=",
            _uint256ToString(sizeValue),
            ")"
        ));
    }

    // =============================================================================
    // Internal Helper Functions
    // =============================================================================

    /// @notice Convert uint32 to string
    /// @param value Value to convert
    /// @return str String representation
    function _uint32ToString(uint32 value) private pure returns (string memory str) {
        if (value == 0) {
            return "0";
        }
        
        uint32 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint32(value % 10)));
            value /= 10;
        }
        
        str = string(buffer);
    }

    /// @notice Convert uint256 to string
    /// @param value Value to convert
    /// @return str String representation
    function _uint256ToString(uint256 value) private pure returns (string memory str) {
        if (value == 0) {
            return "0";
        }
        
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        
        str = string(buffer);
    }
}