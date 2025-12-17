// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title TreeSubspan
/// @notice Represents a subspan within a tree structure for trace location allocation
library TreeSubspan {
    
    /// @param treeIndex Index of the tree this subspan belongs to
    /// @param colStart Starting column index (inclusive)
    /// @param colEnd Ending column index (exclusive)
    struct Subspan {
        uint256 treeIndex;
        uint256 colStart;
        uint256 colEnd;
    }

    // TreeSubspan Operations

    /// @notice Create new TreeSubspan
    /// @param treeIndex Tree index
    /// @param colStart Starting column (inclusive)
    /// @param colEnd Ending column (exclusive)
    /// @return subspan New TreeSubspan
    function newSubspan(
        uint256 treeIndex,
        uint256 colStart,
        uint256 colEnd
    ) internal pure returns (Subspan memory subspan) {
        require(colEnd >= colStart, "Invalid column range");
        
        subspan = Subspan({
            treeIndex: treeIndex,
            colStart: colStart,
            colEnd: colEnd
        });
    }

    /// @notice Get the size of the subspan (number of columns)
    /// @param subspan TreeSubspan to measure
    /// @return size Number of columns in subspan
    function size(Subspan memory subspan) internal pure returns (uint256 size) {
        return subspan.colEnd - subspan.colStart;
    }

    /// @notice Check if subspan contains a specific column
    /// @param subspan TreeSubspan to check
    /// @param colIndex Column index to check
    /// @return contains True if column is within subspan
    function contains(Subspan memory subspan, uint256 colIndex) 
        internal 
        pure 
        returns (bool contains)
    {
        return colIndex >= subspan.colStart && colIndex < subspan.colEnd;
    }

    /// @notice Get relative column index within subspan
    /// @param subspan TreeSubspan to check
    /// @param absoluteColIndex Absolute column index
    /// @return relativeIndex Column index relative to subspan start
    function getRelativeIndex(Subspan memory subspan, uint256 absoluteColIndex)
        internal
        pure
        returns (uint256 relativeIndex)
    {
        require(contains(subspan, absoluteColIndex), "Column not in subspan");
        return absoluteColIndex - subspan.colStart;
    }

    /// @notice Check if two subspans are equal
    /// @param a First subspan
    /// @param b Second subspan  
    /// @return isEqual True if subspans are equal
    function equal(Subspan memory a, Subspan memory b)
        internal
        pure
        returns (bool isEqual)
    {
        return a.treeIndex == b.treeIndex && 
               a.colStart == b.colStart && 
               a.colEnd == b.colEnd;
    }

    /// @notice Check if two subspans overlap
    /// @param a First subspan
    /// @param b Second subspan
    /// @return overlaps True if subspans overlap
    function overlaps(Subspan memory a, Subspan memory b)
        internal
        pure
        returns (bool overlaps)
    {
        if (a.treeIndex != b.treeIndex) {
            return false;
        }
        
        return !(a.colEnd <= b.colStart || b.colEnd <= a.colStart);
    }

    /// @notice Split subspan into smaller subspans
    /// @param subspan Subspan to split
    /// @param numParts Number of parts to split into
    /// @return parts Array of split subspans
    function split(Subspan memory subspan, uint256 numParts)
        internal
        pure
        returns (Subspan[] memory parts)
    {
        require(numParts > 0, "Cannot split into zero parts");
        
        uint256 totalCols = size(subspan);
        require(totalCols >= numParts, "Not enough columns to split");
        
        parts = new Subspan[](numParts);
        uint256 colsPerPart = totalCols / numParts;
        uint256 remainderCols = totalCols % numParts;
        
        uint256 currentStart = subspan.colStart;
        
        for (uint256 i = 0; i < numParts; i++) {
            uint256 partSize = colsPerPart + (i < remainderCols ? 1 : 0);
            
            parts[i] = Subspan({
                treeIndex: subspan.treeIndex,
                colStart: currentStart,
                colEnd: currentStart + partSize
            });
            
            currentStart += partSize;
        }
    }

    // Array Operations for TreeVec<TreeSubspan>

    /// @notice TreeVec wrapper for TreeSubspan arrays
    struct TreeSubspanVec {
        Subspan[] data;
    }

    /// @notice Create new empty TreeSubspanVec
    /// @return vec Empty TreeSubspanVec
    function newTreeSubspanVec() internal pure returns (TreeSubspanVec memory vec) {
        return TreeSubspanVec(new Subspan[](0));
    }

    /// @notice Create TreeSubspanVec from array
    /// @param subspans Array of TreeSubspans
    /// @return vec TreeSubspanVec containing the data
    function fromArray(Subspan[] memory subspans) 
        internal 
        pure 
        returns (TreeSubspanVec memory vec) 
    {
        return TreeSubspanVec(subspans);
    }

    /// @notice Get element at index
    /// @param vec TreeSubspanVec to access
    /// @param index Index to access
    /// @return subspan TreeSubspan at index
    function get(TreeSubspanVec memory vec, uint256 index) 
        internal 
        pure 
        returns (Subspan memory subspan) 
    {
        require(index < vec.data.length, "Index out of bounds");
        return vec.data[index];
    }

    /// @notice Get length of TreeSubspanVec
    /// @param vec TreeSubspanVec to measure
    /// @return length Number of elements
    function length(TreeSubspanVec memory vec) internal pure returns (uint256 length) {
        return vec.data.length;
    }

    /// @notice Push element to TreeSubspanVec
    /// @param vec TreeSubspanVec to modify
    /// @param subspan TreeSubspan to add
    /// @return newVec New TreeSubspanVec with added element
    function push(TreeSubspanVec memory vec, Subspan memory subspan)
        internal
        pure
        returns (TreeSubspanVec memory newVec)
    {
        Subspan[] memory newData = new Subspan[](vec.data.length + 1);
        for (uint256 i = 0; i < vec.data.length; i++) {
            newData[i] = vec.data[i];
        }
        newData[vec.data.length] = subspan;
        return TreeSubspanVec(newData);
    }
}