// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../utils/TreeSubspan.sol";

/// @title TraceLocationAllocatorLib
/// @notice Library for allocating trace locations for constraint framework components
/// @dev Stateless library version of TraceLocationAllocator contract
library TraceLocationAllocatorLib {
    using TreeSubspan for TreeSubspan.Subspan;


    /// @notice Preprocessed column allocation modes
    enum PreprocessedColumnsAllocationMode {
        Dynamic,
        Static
    }

    /// @notice Preprocessed column identifier
    struct PreProcessedColumnId {
        string id;
        uint32 logSize;
        string description;
    }

    /// @notice Allocator state structure
    struct AllocatorState {
        /// @notice Mapping of tree index to next available column offset
        mapping(uint256 => uint256) nextTreeOffsets;
        
        /// @notice Number of trees currently tracked
        uint256 numTrees;
        
        /// @notice Array of preprocessed columns
        PreProcessedColumnId[] preprocessedColumns;
        
        /// @notice Controls whether preprocessed columns are dynamic or static
        PreprocessedColumnsAllocationMode preprocessedColumnsAllocationMode;
        
        /// @notice Whether the allocator has been initialized
        bool isInitialized;
    }


    /// @notice Initialize allocator with dynamic preprocessed columns
    /// @param state The allocator state to initialize
    function initialize(AllocatorState storage state) internal {
        require(!state.isInitialized, "Allocator already initialized");
        
        state.preprocessedColumnsAllocationMode = PreprocessedColumnsAllocationMode.Dynamic;
        state.numTrees = 0;
        state.isInitialized = true;
    }

    /// @notice Initialize allocator with fixed preprocessed columns
    /// @param state The allocator state to initialize
    /// @param _preprocessedColumns Array of preprocessed column definitions
    function initializeWithPreprocessedColumns(
        AllocatorState storage state,
        PreProcessedColumnId[] memory _preprocessedColumns
    ) internal {
        require(!state.isInitialized, "Allocator already initialized");
        require(
            state.preprocessedColumns.length == 0, 
            "Preprocessed columns already initialized"
        );
        
        for (uint256 i = 0; i < _preprocessedColumns.length; i++) {
            for (uint256 j = i + 1; j < _preprocessedColumns.length; j++) {
                require(
                    keccak256(bytes(_preprocessedColumns[i].id)) != 
                    keccak256(bytes(_preprocessedColumns[j].id)),
                    "Duplicate preprocessed columns are not allowed"
                );
            }
        }

        for (uint256 i = 0; i < _preprocessedColumns.length; i++) {
            state.preprocessedColumns.push(_preprocessedColumns[i]);
        }

        state.preprocessedColumnsAllocationMode = PreprocessedColumnsAllocationMode.Static;
        state.numTrees = 0;
        state.isInitialized = true;
    }

    /// @notice Allocate trace locations for component structure
    /// @param state The allocator state
    /// @param treeSizes Array representing structure as TreeVec<ColumnVec<T>>
    // / @param componentId Unique identifier for the component (for logging only)
    /// @return traceLocations Array of TreeSubspan for allocated locations
    function nextForStructure(
        AllocatorState storage state,
        uint256[] memory treeSizes,
        uint256 /* componentId */
    ) internal returns (TreeSubspan.Subspan[] memory traceLocations) {
        require(state.isInitialized, "Allocator not initialized");
        
        uint256 requiredTrees = treeSizes.length;
        if (requiredTrees > state.numTrees) {
            state.numTrees = requiredTrees;
        }

        traceLocations = new TreeSubspan.Subspan[](treeSizes.length);

        for (uint256 treeIndex = 0; treeIndex < treeSizes.length; treeIndex++) {
            uint256 colStart = state.nextTreeOffsets[treeIndex];
            uint256 colEnd = colStart + treeSizes[treeIndex];
            
            traceLocations[treeIndex] = TreeSubspan.newSubspan(
                treeIndex,
                colStart,
                colEnd
            );

            state.nextTreeOffsets[treeIndex] = colEnd;
        }

        return traceLocations;
    }

    /// @notice Get or add preprocessed column index
    /// @param state The allocator state
    /// @param columnId Preprocessed column to get/add
    /// @return columnIndex Index of the preprocessed column
    function getPreprocessedColumnIndex(
        AllocatorState storage state,
        PreProcessedColumnId memory columnId
    ) internal returns (uint256 columnIndex) {
        require(state.isInitialized, "Allocator not initialized");
        
        // Look for existing column
        for (uint256 i = 0; i < state.preprocessedColumns.length; i++) {
            if (keccak256(bytes(state.preprocessedColumns[i].id)) == keccak256(bytes(columnId.id))) {
                return i;
            }
        }

        // If not found, add new column (only in dynamic mode)
        if (state.preprocessedColumnsAllocationMode == PreprocessedColumnsAllocationMode.Static) {
            revert("Preprocessed column missing from static allocation");
        }

        // Add new column
        uint256 newIndex = state.preprocessedColumns.length;
        state.preprocessedColumns.push(columnId);
        
        return newIndex;
    }

    /// @notice Get multiple preprocessed column indices
    /// @param state The allocator state
    /// @param columnIds Array of preprocessed columns to get/add
    /// @return columnIndices Array of indices for the preprocessed columns
    function getPreprocessedColumnIndices(
        AllocatorState storage state,
        PreProcessedColumnId[] memory columnIds
    ) internal returns (uint256[] memory columnIndices) {
        require(state.isInitialized, "Allocator not initialized");
        
        columnIndices = new uint256[](columnIds.length);
        
        for (uint256 i = 0; i < columnIds.length; i++) {
            // Inline the logic from getPreprocessedColumnIndex since core can't call their own internal functions
            PreProcessedColumnId memory columnId = columnIds[i];
            
            // Look for existing column
            bool found = false;
            for (uint256 j = 0; j < state.preprocessedColumns.length; j++) {
                if (keccak256(bytes(state.preprocessedColumns[j].id)) == keccak256(bytes(columnId.id))) {
                    columnIndices[i] = j;
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                // If not found, add new column (only in dynamic mode)
                if (state.preprocessedColumnsAllocationMode == PreprocessedColumnsAllocationMode.Static) {
                    revert("Preprocessed column missing from static allocation");
                }

                // Add new column
                uint256 newIndex = state.preprocessedColumns.length;
                state.preprocessedColumns.push(columnId);
                columnIndices[i] = newIndex;
            }
        }
        
        return columnIndices;
    }


    /// @notice Get all preprocessed columns
    /// @param state The allocator state
    /// @return columns Array of all preprocessed columns
    function getPreprocessedColumns(AllocatorState storage state) 
        internal 
        view 
        returns (PreProcessedColumnId[] memory columns) 
    {
        require(state.isInitialized, "Allocator not initialized");
        return state.preprocessedColumns;
    }

    /// @notice Get specific preprocessed column
    /// @param state The allocator state
    /// @param index Index of the preprocessed column
    /// @return column Preprocessed column at index
    function getPreprocessedColumn(
        AllocatorState storage state,
        uint256 index
    ) internal view returns (PreProcessedColumnId memory column) {
        require(state.isInitialized, "Allocator not initialized");
        require(index < state.preprocessedColumns.length, "Index out of bounds");
        return state.preprocessedColumns[index];
    }

    /// @notice Get next available offset for a tree
    /// @param state The allocator state
    /// @param treeIndex Index of the tree
    /// @return nextOffset Next available column offset
    function getNextTreeOffset(
        AllocatorState storage state,
        uint256 treeIndex
    ) internal view returns (uint256 nextOffset) {
        require(state.isInitialized, "Allocator not initialized");
        return state.nextTreeOffsets[treeIndex];
    }

    /// @notice Get number of preprocessed columns
    /// @param state The allocator state
    /// @return count Number of preprocessed columns
    function getPreprocessedColumnsCount(AllocatorState storage state) 
        internal 
        view 
        returns (uint256 count) 
    {
        require(state.isInitialized, "Allocator not initialized");
        return state.preprocessedColumns.length;
    }

    /// @notice Get allocation mode
    /// @param state The allocator state
    /// @return mode Current allocation mode
    function getAllocationMode(AllocatorState storage state) 
        internal 
        view 
        returns (PreprocessedColumnsAllocationMode mode) 
    {
        require(state.isInitialized, "Allocator not initialized");
        return state.preprocessedColumnsAllocationMode;
    }

    /// @notice Get current allocation summary
    /// @param state The allocator state
    /// @return totalTrees Number of trees being tracked
    /// @return treeOffsets Current offsets for each tree
    /// @return totalPreprocessedColumns Number of preprocessed columns
    function getAllocationSummary(AllocatorState storage state)
        internal
        view
        returns (
            uint256 totalTrees,
            uint256[] memory treeOffsets,
            uint256 totalPreprocessedColumns
        )
    {
        require(state.isInitialized, "Allocator not initialized");
        
        totalTrees = state.numTrees;
        treeOffsets = new uint256[](state.numTrees);
        
        for (uint256 i = 0; i < state.numTrees; i++) {
            treeOffsets[i] = state.nextTreeOffsets[i];
        }
        
        totalPreprocessedColumns = state.preprocessedColumns.length;
    }


    /// @notice Validate preprocessed columns against expected set
    /// @param state The allocator state
    /// @param expectedColumns Expected preprocessed columns
    /// @return isValid True if current columns match expected
    /// @return errorMessage Error description if validation fails
    function validatePreprocessedColumns(
        AllocatorState storage state,
        PreProcessedColumnId[] memory expectedColumns
    ) internal view returns (bool isValid, string memory errorMessage) {
        require(state.isInitialized, "Allocator not initialized");
        
        if (state.preprocessedColumns.length != expectedColumns.length) {
            return (false, "Preprocessed columns count mismatch");
        }

        string[] memory currentIds = new string[](state.preprocessedColumns.length);
        string[] memory expectedIds = new string[](expectedColumns.length);

        for (uint256 i = 0; i < state.preprocessedColumns.length; i++) {
            currentIds[i] = state.preprocessedColumns[i].id;
        }

        for (uint256 i = 0; i < expectedColumns.length; i++) {
            expectedIds[i] = expectedColumns[i].id;
        }

        for (uint256 i = 0; i < currentIds.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < expectedIds.length; j++) {
                if (keccak256(bytes(currentIds[i])) == keccak256(bytes(expectedIds[j]))) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return (false, "Preprocessed columns are not a permutation");
            }
        }

        return (true, "Preprocessed columns validation passed");
    }


    /// @notice Reset allocator state (for testing)
    /// @param state The allocator state
    function reset(AllocatorState storage state) internal {
        require(state.isInitialized, "Allocator not initialized");
        
        for (uint256 i = 0; i < state.numTrees; i++) {
            state.nextTreeOffsets[i] = 0;
        }
        state.numTrees = 0;

        if (state.preprocessedColumnsAllocationMode == PreprocessedColumnsAllocationMode.Dynamic) {
            delete state.preprocessedColumns;
        }
        state.isInitialized = false;
    }

    /// @notice Check if allocator is initialized
    /// @param state The allocator state
    /// @return initialized True if allocator is initialized
    function isInitialized(AllocatorState storage state) internal view returns (bool initialized) {
        return state.isInitialized;
    }

    /// @notice Get number of preprocessed columns
    /// @param state The allocator state
    /// @return length Number of preprocessed columns
    function getPreprocessedColumnsLength(AllocatorState storage state) 
        internal view returns (uint256 length) {
        return state.preprocessedColumns.length;
    }

    /// @notice Find preprocessed column by ID
    /// @dev Rust: location_allocator.preprocessed_columns.iter().position(|x| x.id == col.id)
    /// @param state The allocator state
    /// @param columnId The column ID to find
    /// @return found Whether column was found
    /// @return position Position/index of the column if found
    function findPreprocessedColumn(AllocatorState storage state, uint256 columnId) 
        internal view returns (bool found, uint256 position) {
        string memory columnIdStr = _uint256ToString(columnId);
        
        for (uint256 i = 0; i < state.preprocessedColumns.length; i++) {
            if (keccak256(bytes(state.preprocessedColumns[i].id)) == keccak256(bytes(columnIdStr))) {
                return (true, i);
            }
        }
        return (false, 0);
    }

    /// @notice Check if allocator is in static allocation mode
    /// @dev Rust: matches!(location_allocator.preprocessed_columns_allocation_mode, Static)
    /// @param state The allocator state
    /// @return isStatic True if in static mode
    function isStaticAllocationMode(AllocatorState storage state) 
        internal view returns (bool isStatic) {
        return state.preprocessedColumnsAllocationMode == PreprocessedColumnsAllocationMode.Static;
    }

    /// @notice Add preprocessed column
    /// @dev Rust: location_allocator.preprocessed_columns.push(col.clone())
    /// @param state The allocator state
    /// @param columnId The column ID to add
    function addPreprocessedColumn(AllocatorState storage state, uint256 columnId) internal {
        require(state.isInitialized, "Allocator not initialized");
        require(
            state.preprocessedColumnsAllocationMode == PreprocessedColumnsAllocationMode.Dynamic,
            "Cannot add columns in static allocation mode"
        );

        string memory columnIdStr = _uint256ToString(columnId);
        
        // Check for duplicates
        for (uint256 i = 0; i < state.preprocessedColumns.length; i++) {
            require(
                keccak256(bytes(state.preprocessedColumns[i].id)) != keccak256(bytes(columnIdStr)),
                "Duplicate preprocessed column not allowed"
            );
        }

        state.preprocessedColumns.push(PreProcessedColumnId({
            id: columnIdStr,
            logSize: 0, // Default log size
            description: string(abi.encodePacked("Column ", columnIdStr))
        }));
    }

    /// @notice Create allocator with static preprocessed columns
    /// @dev Rust: TraceLocationAllocator::new_with_preprocessed_columns
    /// @param state The allocator state to initialize
    /// @param columnIds Array of column IDs
    function initializeWithPreprocessedColumns(
        AllocatorState storage state, 
        uint256[] memory columnIds
    ) internal {
        require(!state.isInitialized, "Allocator already initialized");

        // Check for duplicates
        for (uint256 i = 0; i < columnIds.length; i++) {
            for (uint256 j = i + 1; j < columnIds.length; j++) {
                require(columnIds[i] != columnIds[j], "Duplicate preprocessed columns not allowed");
            }
        }

        state.preprocessedColumnsAllocationMode = PreprocessedColumnsAllocationMode.Static;
        
        for (uint256 i = 0; i < columnIds.length; i++) {
            string memory columnIdStr = _uint256ToString(columnIds[i]);
            state.preprocessedColumns.push(PreProcessedColumnId({
                id: columnIdStr,
                logSize: 0,
                description: string(abi.encodePacked("Static column ", columnIdStr))
            }));
        }

        state.isInitialized = true;
    }

    /// @notice Convert uint256 to string
    function _uint256ToString(uint256 value) private pure returns (string memory) {
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
        return string(buffer);
    }
}