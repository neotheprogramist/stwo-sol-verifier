// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../pcs/TreeVec.sol";

/// @title ArrayUtils
/// @notice Utility functions for array operations needed for bounds calculation
library ArrayUtils {
    using TreeVec for TreeVec.Uint32ArrayTreeVec;

    /// @notice Flatten TreeVec<uint32[][]> to single uint32[] array
    /// @param treeVec TreeVec containing arrays of uint32 values
    /// @return flattened Single array with all values from all trees
    function flatten(TreeVec.Uint32ArrayTreeVec memory treeVec) 
        internal 
        pure 
        returns (uint32[] memory flattened) 
    {
        // Count total elements across all trees
        uint256 totalLength = 0;
        for (uint256 treeIdx = 0; treeIdx < treeVec.data.length; treeIdx++) {
            totalLength += treeVec.data[treeIdx].length;
        }
        
        // Create flattened array
        flattened = new uint32[](totalLength);
        uint256 currentIndex = 0;
        
        // Copy all elements
        for (uint256 treeIdx = 0; treeIdx < treeVec.data.length; treeIdx++) {
            for (uint256 elemIdx = 0; elemIdx < treeVec.data[treeIdx].length; elemIdx++) {
                flattened[currentIndex] = treeVec.data[treeIdx][elemIdx];
                currentIndex++;
            }
        }
    }

    /// @notice Sort uint32 array in ascending order
    /// @dev Uses bubble sort (simple but inefficient - can be optimized later)
    /// @param arr Array to sort
    /// @return sorted Sorted array in ascending order
    function sort(uint32[] memory arr) internal pure returns (uint32[] memory sorted) {
        sorted = new uint32[](arr.length);
        
        // Copy array
        for (uint256 i = 0; i < arr.length; i++) {
            sorted[i] = arr[i];
        }
        
        // Bubble sort
        for (uint256 i = 0; i < sorted.length; i++) {
            for (uint256 j = 0; j < sorted.length - i - 1; j++) {
                if (sorted[j] > sorted[j + 1]) {
                    uint32 temp = sorted[j];
                    sorted[j] = sorted[j + 1];
                    sorted[j + 1] = temp;
                }
            }
        }
    }

    /// @notice Reverse uint32 array
    /// @param arr Array to reverse
    /// @return reversed Reversed array
    function reverse(uint32[] memory arr) internal pure returns (uint32[] memory reversed) {
        reversed = new uint32[](arr.length);
        
        for (uint256 i = 0; i < arr.length; i++) {
            reversed[i] = arr[arr.length - 1 - i];
        }
    }

    /// @notice Remove consecutive duplicate elements from sorted array
    /// @param arr Sorted array to deduplicate
    /// @return deduplicated Array with consecutive duplicates removed
    function removeDuplicates(uint32[] memory arr) 
        internal 
        pure 
        returns (uint32[] memory deduplicated) 
    {
        if (arr.length == 0) {
            return new uint32[](0);
        }
        
        // Count unique elements
        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i - 1]) {
                uniqueCount++;
            }
        }
        
        // Create deduplicated array
        deduplicated = new uint32[](uniqueCount);
        deduplicated[0] = arr[0];
        uint256 currentIndex = 1;
        
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i - 1]) {
                deduplicated[currentIndex] = arr[i];
                currentIndex++;
            }
        }
    }

    /// @notice Complete Rust-equivalent processing pipeline
    /// @param treeVec TreeVec to process
    /// @return processed Final processed array
    function flattenSortReverseDedup(TreeVec.Uint32ArrayTreeVec memory treeVec)
        external
        pure
        returns (uint32[] memory processed)
    {
        uint32[] memory flattened = flatten(treeVec);
        uint32[] memory sorted = sort(flattened);
        uint32[] memory reversed = reverse(sorted);
        processed = removeDuplicates(reversed);
    }

    /// @notice Helper function to create a single-element TreeVec for testing
    /// @param values Array of uint32 values
    /// @return treeVec TreeVec with single tree containing the values
    function createSingleTreeVec(uint32[] memory values) 
        internal 
        pure 
        returns (TreeVec.Uint32ArrayTreeVec memory treeVec) 
    {
        treeVec.data = new uint32[][](1);
        treeVec.data[0] = values;
    }

    /// @notice Helper function to create multi-tree TreeVec for testing
    /// @param tree0 Values for tree 0
    /// @param tree1 Values for tree 1
    /// @return treeVec TreeVec with two trees
    function createMultiTreeVec(uint32[] memory tree0, uint32[] memory tree1)
        internal
        pure
        returns (TreeVec.Uint32ArrayTreeVec memory treeVec)
    {
        treeVec.data = new uint32[][](2);
        treeVec.data[0] = tree0;
        treeVec.data[1] = tree1;
    }
}