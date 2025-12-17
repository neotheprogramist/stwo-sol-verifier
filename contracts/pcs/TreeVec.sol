// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title TreeVec
/// @notice Dynamic array wrapper for tree-indexed data in commitment schemes
/// @dev Provides type-safe indexing for commitment trees and utilities for batch operations
library TreeVec {
    
    /// @notice Error thrown when accessing invalid tree index
    error InvalidTreeIndex(uint256 index, uint256 length);
    
    /// @notice Error thrown when arrays have mismatched lengths
    error LengthMismatch(uint256 expected, uint256 actual);

    /// @notice Generic TreeVec for bytes32 data (used for commitment roots)
    struct Bytes32TreeVec {
        bytes32[] data;
    }

    /// @notice Generic TreeVec for uint32 arrays (used for column log sizes)
    struct Uint32ArrayTreeVec {
        uint32[][] data;
    }

    /// @notice Generic TreeVec for uint256 data (used for counters/indices)
    struct Uint256TreeVec {
        uint256[] data;
    }

    // Bytes32TreeVec Operations

    /// @notice Create new empty TreeVec for bytes32
    /// @return Empty TreeVec
    function newBytes32() internal pure returns (Bytes32TreeVec memory) {
        return Bytes32TreeVec(new bytes32[](0));
    }

    /// @notice Create TreeVec from array of bytes32
    /// @param data Array of bytes32 values
    /// @return TreeVec containing the data
    function fromBytes32Array(bytes32[] memory data) internal pure returns (Bytes32TreeVec memory) {
        return Bytes32TreeVec(data);
    }

    /// @notice Get element at tree index
    /// @param treeVec TreeVec to access
    /// @param index Tree index
    /// @return Element at index
    function get(Bytes32TreeVec memory treeVec, uint256 index) internal pure returns (bytes32) {
        if (index >= treeVec.data.length) {
            revert InvalidTreeIndex(index, treeVec.data.length);
        }
        return treeVec.data[index];
    }

    /// @notice Set element at tree index
    /// @param treeVec TreeVec to modify
    /// @param index Tree index
    /// @param value New value
    function set(Bytes32TreeVec memory treeVec, uint256 index, bytes32 value) internal pure {
        if (index >= treeVec.data.length) {
            revert InvalidTreeIndex(index, treeVec.data.length);
        }
        treeVec.data[index] = value;
    }

    /// @notice Push new element to TreeVec
    /// @param treeVec TreeVec to modify
    /// @param value Value to append
    /// @return New TreeVec with appended element
    function push(Bytes32TreeVec memory treeVec, bytes32 value) internal pure returns (Bytes32TreeVec memory) {
        bytes32[] memory newData = new bytes32[](treeVec.data.length + 1);
        for (uint256 i = 0; i < treeVec.data.length; i++) {
            newData[i] = treeVec.data[i];
        }
        newData[treeVec.data.length] = value;
        return Bytes32TreeVec(newData);
    }

    /// @notice Get length of TreeVec
    /// @param treeVec TreeVec to query
    /// @return Number of elements
    function length(Bytes32TreeVec memory treeVec) internal pure returns (uint256) {
        return treeVec.data.length;
    }

    /// @notice Check if TreeVec is empty
    /// @param treeVec TreeVec to check
    /// @return True if empty
    function isEmpty(Bytes32TreeVec memory treeVec) internal pure returns (bool) {
        return treeVec.data.length == 0;
    }

    // Uint32ArrayTreeVec Operations  

    /// @notice Create new empty TreeVec for uint32 arrays
    /// @return Empty TreeVec
    function newUint32Array() internal pure returns (Uint32ArrayTreeVec memory) {
        return Uint32ArrayTreeVec(new uint32[][](0));
    }

    /// @notice Get element at tree index
    /// @param treeVec TreeVec to access
    /// @param index Tree index
    /// @return Array at index
    function get(Uint32ArrayTreeVec memory treeVec, uint256 index) internal pure returns (uint32[] memory) {
        if (index >= treeVec.data.length) {
            revert InvalidTreeIndex(index, treeVec.data.length);
        }
        return treeVec.data[index];
    }

    /// @notice Push new array to TreeVec
    /// @param treeVec TreeVec to modify
    /// @param value Array to append
    /// @return New TreeVec with appended array
    function push(Uint32ArrayTreeVec memory treeVec, uint32[] memory value) internal pure returns (Uint32ArrayTreeVec memory) {
        uint32[][] memory newData = new uint32[][](treeVec.data.length + 1);
        for (uint256 i = 0; i < treeVec.data.length; i++) {
            newData[i] = treeVec.data[i];
        }
        newData[treeVec.data.length] = value;
        return Uint32ArrayTreeVec(newData);
    }

    /// @notice Get length of TreeVec
    /// @param treeVec TreeVec to query
    /// @return Number of arrays
    function length(Uint32ArrayTreeVec memory treeVec) internal pure returns (uint256) {
        return treeVec.data.length;
    }

    // Uint256TreeVec Operations

    /// @notice Create new empty TreeVec for uint256
    /// @return Empty TreeVec
    function newUint256() internal pure returns (Uint256TreeVec memory) {
        return Uint256TreeVec(new uint256[](0));
    }

    /// @notice Get element at tree index
    /// @param treeVec TreeVec to access
    /// @param index Tree index
    /// @return Element at index
    function get(Uint256TreeVec memory treeVec, uint256 index) internal pure returns (uint256) {
        if (index >= treeVec.data.length) {
            revert InvalidTreeIndex(index, treeVec.data.length);
        }
        return treeVec.data[index];
    }

    /// @notice Push new element to TreeVec
    /// @param treeVec TreeVec to modify
    /// @param value Value to append
    /// @return New TreeVec with appended element
    function push(Uint256TreeVec memory treeVec, uint256 value) internal pure returns (Uint256TreeVec memory) {
        uint256[] memory newData = new uint256[](treeVec.data.length + 1);
        for (uint256 i = 0; i < treeVec.data.length; i++) {
            newData[i] = treeVec.data[i];
        }
        newData[treeVec.data.length] = value;
        return Uint256TreeVec(newData);
    }

    /// @notice Get length of TreeVec
    /// @param treeVec TreeVec to query
    /// @return Number of elements
    function length(Uint256TreeVec memory treeVec) internal pure returns (uint256) {
        return treeVec.data.length;
    }

    // Utility Functions

    /// @notice Map function over bytes32 TreeVec
    /// @dev Helper for batch operations
    /// @param treeVec Source TreeVec
    /// @param func Function to apply to each element
    /// @return New TreeVec with mapped values
    function map(
        Bytes32TreeVec memory treeVec,
        function(bytes32) internal pure returns (bytes32) func
    ) internal pure returns (Bytes32TreeVec memory) {
        bytes32[] memory newData = new bytes32[](treeVec.data.length);
        for (uint256 i = 0; i < treeVec.data.length; i++) {
            newData[i] = func(treeVec.data[i]);
        }
        return Bytes32TreeVec(newData);
    }

    /// @notice Iterate through TreeVec with index
    /// @param treeVec TreeVec to iterate
    /// @param func Function to call for each element
    function enumerate(
        Bytes32TreeVec memory treeVec,
        function(uint256, bytes32) internal pure func
    ) internal pure {
        for (uint256 i = 0; i < treeVec.data.length; i++) {
            func(i, treeVec.data[i]);
        }
    }

    /// @notice Flatten TreeVec to regular array
    /// @param treeVec TreeVec to flatten
    /// @return Regular array containing all elements
    function flatten(Bytes32TreeVec memory treeVec) internal pure returns (bytes32[] memory) {
        return treeVec.data;
    }

    /// @notice Create TreeVec with specific capacity
    /// @param capacity Initial capacity
    /// @return TreeVec with specified capacity
    function withCapacity(uint256 capacity) internal pure returns (Bytes32TreeVec memory) {
        return Bytes32TreeVec(new bytes32[](capacity));
    }
}