// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title CirclePolyDegreeBound
/// @notice Degree bound for circle polynomials in polynomial commitment scheme
library CirclePolyDegreeBound {
    
    /// @notice Circle polynomial degree bound structure
    struct Bound {
        uint32 logDegreeBound;  // Log2 of the degree bound
    }

    /// @notice Create new CirclePolyDegreeBound
    /// @param logDegreeBound Log2 of the degree bound
    /// @return bound New CirclePolyDegreeBound instance
    function create(uint32 logDegreeBound) internal pure returns (Bound memory bound) {
        bound.logDegreeBound = logDegreeBound;
    }

    /// @notice Create array of bounds from log degree values
    /// @dev Helper function to map array of log sizes to bounds
    /// @param logDegrees Array of log degree values
    /// @return bounds Array of CirclePolyDegreeBound instances
    function createBoundsArray(uint32[] memory logDegrees) 
        internal 
        pure 
        returns (Bound[] memory bounds) 
    {
        bounds = new Bound[](logDegrees.length);
        for (uint256 i = 0; i < logDegrees.length; i++) {
            bounds[i] = create(logDegrees[i]);
        }
    }

    /// @notice Get log degree bound value
    /// @param bound The bound to query
    /// @return logDegreeBound The log degree bound value
    function logDegree(Bound memory bound) internal pure returns (uint32 logDegreeBound) {
        return bound.logDegreeBound;
    }

    /// @notice Check if bound is valid (non-negative)
    /// @param bound The bound to validate
    /// @return isValid True if bound is valid
    function isValid(Bound memory bound) internal pure returns (bool isValid) {
        return true;
    }

    /// @notice Compare two bounds for equality
    /// @param a First bound
    /// @param b Second bound
    /// @return equal True if bounds are equal
    function equal(Bound memory a, Bound memory b) internal pure returns (bool equal) {
        return a.logDegreeBound == b.logDegreeBound;
    }

    /// @notice Compare if bound a is less than bound b
    /// @param a First bound
    /// @param b Second bound
    /// @return less True if a < b
    function lessThan(Bound memory a, Bound memory b) internal pure returns (bool less) {
        return a.logDegreeBound < b.logDegreeBound;
    }

    /// @notice Get the actual degree (2^logDegreeBound)
    /// @param bound The bound to query
    /// @return degree The actual degree value
    function degree(Bound memory bound) internal pure returns (uint256 degree) {
        return 1 << bound.logDegreeBound;
    }

    /// @notice Convert bound to string representation for debugging
    /// @param bound The bound to convert
    /// @return str String representation
    function toString(Bound memory bound) internal pure returns (string memory str) {
        return string(abi.encodePacked(
            "CirclePolyDegreeBound(logDegreeBound=",
            _uint32ToString(bound.logDegreeBound),
            ", degree=",
            _uint256ToString(degree(bound)),
            ")"
        ));
    }

    /// @notice Convert bounds array to log degree array
    /// @param bounds Array of bounds
    /// @return logDegrees Array of log degree values
    function toLogDegreeArray(Bound[] memory bounds) 
        internal 
        pure 
        returns (uint32[] memory logDegrees) 
    {
        logDegrees = new uint32[](bounds.length);
        for (uint256 i = 0; i < bounds.length; i++) {
            logDegrees[i] = bounds[i].logDegreeBound;
        }
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