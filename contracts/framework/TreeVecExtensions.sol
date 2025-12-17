// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/QM31Field.sol";
import "./TreeSubspan.sol";

/// @title TreeVecExtensions
/// @notice Extensions for TreeVec to support constraint framework operations
library TreeVecExtensions {
    using TreeSubspan for TreeSubspan.Subspan;

    // Error Types

    error InvalidTreeIndex(uint256 index, uint256 maxIndex);
    error InvalidColumnRange(uint256 start, uint256 end, uint256 maxColumns);
    error IncompatibleTreeStructure();

    // QM31 TreeVec (TreeVec<ColumnVec<Vec<QM31Field.QM31>>>)

    /// @notice Extract sub-tree using TreeSubspan locations
    /// @param sourceTree Source TreeVec with mask values
    /// @param traceLocations Array of TreeSubspan defining extraction locations
    /// @return subTree Extracted sub-tree with same structure as locations
    function subTree(
        QM31Field.QM31[][][] memory sourceTree,
        TreeSubspan.Subspan[] memory traceLocations
    ) internal pure returns (QM31Field.QM31[][][] memory subTree) {
        
        // Create sub-tree with same number of trees as trace locations
        subTree = new QM31Field.QM31[][][](traceLocations.length);
        
        for (uint256 i = 0; i < traceLocations.length; i++) {
            TreeSubspan.Subspan memory location = traceLocations[i];
            
            // Validate tree index
            if (location.treeIndex >= sourceTree.length) {
                revert InvalidTreeIndex(location.treeIndex, sourceTree.length);
            }
            
            // Validate column range
            if (location.colEnd > sourceTree[location.treeIndex].length) {
                revert InvalidColumnRange(
                    location.colStart, 
                    location.colEnd, 
                    sourceTree[location.treeIndex].length
                );
            }
            
            // Extract columns from specified range
            uint256 numCols = location.colEnd - location.colStart;
            subTree[i] = new QM31Field.QM31[][](numCols);
            
            for (uint256 j = 0; j < numCols; j++) {
                uint256 sourceColIndex = location.colStart + j;
                subTree[i][j] = sourceTree[location.treeIndex][sourceColIndex];
            }
        }
        
        return subTree;
    }

    /// @notice Set preprocessed mask in sub-tree
    /// @param subTree Sub-tree to modify
    /// @param preprocessedMask New preprocessed mask values
    /// @param preprocessedTraceIdx Index for preprocessed trace (usually 0)
    /// @return modifiedSubTree Modified sub-tree with new preprocessed mask
    function setPreprocessedMask(
        QM31Field.QM31[][][] memory subTree,
        QM31Field.QM31[][] memory preprocessedMask,
        uint256 preprocessedTraceIdx
    ) internal pure returns (QM31Field.QM31[][][] memory modifiedSubTree) {
        require(preprocessedTraceIdx < subTree.length, "Invalid preprocessed trace index");
        
        // Create a copy of the sub-tree
        modifiedSubTree = new QM31Field.QM31[][][](subTree.length);
        for (uint256 i = 0; i < subTree.length; i++) {
            if (i == preprocessedTraceIdx) {
                // Replace with preprocessed mask
                modifiedSubTree[i] = preprocessedMask;
            } else {
                // Copy existing data
                modifiedSubTree[i] = subTree[i];
            }
        }
        
        return modifiedSubTree;
    }

    /// @notice Extract preprocessed mask from source TreeVec
    /// @param sourceTree Source TreeVec containing all mask values
    /// @param preprocessedColumnIndices Indices of preprocessed columns to extract
    /// @param preprocessedTraceIdx Index of preprocessed trace in source tree
    /// @return preprocessedMask Extracted preprocessed mask
    function extractPreprocessedMask(
        QM31Field.QM31[][][] memory sourceTree,
        uint256[] memory preprocessedColumnIndices,
        uint256 preprocessedTraceIdx
    ) internal pure returns (QM31Field.QM31[][] memory preprocessedMask) {
        require(preprocessedTraceIdx < sourceTree.length, "Invalid preprocessed trace index");
        
        preprocessedMask = new QM31Field.QM31[][](preprocessedColumnIndices.length);
        
        for (uint256 i = 0; i < preprocessedColumnIndices.length; i++) {
            uint256 colIdx = preprocessedColumnIndices[i];
            require(
                colIdx < sourceTree[preprocessedTraceIdx].length, 
                "Invalid preprocessed column index"
            );
            
            preprocessedMask[i] = sourceTree[preprocessedTraceIdx][colIdx];
        }
        
        return preprocessedMask;
    }

    // Tree Structure Validation

    /// @notice Validate tree structure compatibility
    /// @param tree TreeVec to validate
    /// @param expectedTrees Expected number of trees
    /// @return isValid True if structure is valid
    /// @return errorMessage Error description if invalid
    function validateTreeStructure(
        QM31Field.QM31[][][] memory tree,
        uint256 expectedTrees
    ) internal pure returns (bool isValid, string memory errorMessage) {
        
        if (tree.length != expectedTrees) {
            return (false, "Incorrect number of trees");
        }
        
        // Check that all trees have valid structure
        for (uint256 i = 0; i < tree.length; i++) {
            if (tree[i].length == 0) {
                return (false, "Tree has no columns");
            }
            
            // Check that all columns in a tree have the same length
            uint256 expectedLength = tree[i][0].length;
            for (uint256 j = 1; j < tree[i].length; j++) {
                if (tree[i][j].length != expectedLength) {
                    return (false, "Inconsistent column lengths within tree");
                }
            }
        }
        
        return (true, "Valid tree structure");
    }

    /// @notice Get tree dimensions for debugging
    /// @param tree TreeVec to analyze
    /// @return nTrees Number of trees
    /// @return nColumns Number of columns per tree
    /// @return nValues Number of values per column (for first column of each tree)
    function getTreeDimensions(QM31Field.QM31[][][] memory tree)
        internal
        pure
        returns (
            uint256 nTrees,
            uint256[] memory nColumns,
            uint256[] memory nValues
        )
    {
        nTrees = tree.length;
        nColumns = new uint256[](nTrees);
        nValues = new uint256[](nTrees);
        
        for (uint256 i = 0; i < nTrees; i++) {
            nColumns[i] = tree[i].length;
            if (tree[i].length > 0) {
                nValues[i] = tree[i][0].length;
            } else {
                nValues[i] = 0;
            }
        }
    }

    // Tree Manipulation Utilities

    /// @notice Create empty TreeVec with specified structure
    /// @param treeSizes Array specifying number of columns per tree
    /// @param valuesPerColumn Number of values per column
    /// @return emptyTree Empty TreeVec with specified structure
    function createEmptyTree(
        uint256[] memory treeSizes,
        uint256 valuesPerColumn
    ) internal pure returns (QM31Field.QM31[][][] memory emptyTree) {
        
        emptyTree = new QM31Field.QM31[][][](treeSizes.length);
        
        for (uint256 i = 0; i < treeSizes.length; i++) {
            emptyTree[i] = new QM31Field.QM31[][](treeSizes[i]);
            
            for (uint256 j = 0; j < treeSizes[i]; j++) {
                emptyTree[i][j] = new QM31Field.QM31[](valuesPerColumn);
                
                // Initialize with zero values
                for (uint256 k = 0; k < valuesPerColumn; k++) {
                    emptyTree[i][j][k] = QM31Field.zero();
                }
            }
        }
        
        return emptyTree;
    }

    /// @notice Clone TreeVec structure
    /// @param source Source TreeVec to clone
    /// @return cloned Cloned TreeVec with same values
    function cloneTree(QM31Field.QM31[][][] memory source)
        internal
        pure
        returns (QM31Field.QM31[][][] memory cloned)
    {
        cloned = new QM31Field.QM31[][][](source.length);
        
        for (uint256 i = 0; i < source.length; i++) {
            cloned[i] = new QM31Field.QM31[][](source[i].length);
            
            for (uint256 j = 0; j < source[i].length; j++) {
                cloned[i][j] = new QM31Field.QM31[](source[i][j].length);
                
                for (uint256 k = 0; k < source[i][j].length; k++) {
                    cloned[i][j][k] = source[i][j][k];
                }
            }
        }
        
        return cloned;
    }
}