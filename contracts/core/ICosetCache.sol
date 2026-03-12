// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../cosets/CosetM31.sol";

/// @title ICosetCache
/// @notice Interface for coset caching functionality
interface ICosetCache {
    /// @notice Get or compute cached coset
    /// @param initialIndex Initial circle point index
    /// @param logSize Log2 of coset size
    /// @return coset Cached or newly computed coset
    function getCachedCoset(
        CosetM31.CirclePointIndex memory initialIndex,
        uint32 logSize
    ) external returns (CosetM31.CosetStruct memory coset);
}
