// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../circle/CirclePoint.sol";
import "../fields/QM31Field.sol";
import "./FrameworkComponentLib.sol";


/// @title ComponentsLib
/// @notice Library implementing Components functionality
library ComponentsLib {
    using QM31Field for QM31Field.QM31;
    using FrameworkComponentLib for FrameworkComponentLib.ComponentState;


    uint256 public constant PREPROCESSED_TRACE_IDX = 0;
    uint256 public constant ORIGINAL_TRACE_IDX = 1;
    uint256 public constant INTERACTION_TRACE_IDX = 2;


    struct Components {
        FrameworkComponentLib.ComponentState[] components;
        uint256 nPreprocessedColumns;
        bool isInitialized;
    }

    /// @notice TreeVec structure for mask points
    struct TreeVecMaskPoints {
        CirclePoint.Point[][][] points;
        uint256[] nColumnsPerTree;
        uint256 totalPoints;
    }


    event ComponentsInitialized(uint256 nComponents, uint256 nPreprocessedColumns);
    event CompositionLogDegreeBoundCalculated(uint32 maxBound);
    event MaskPointsGenerated(uint256 totalPoints, uint256 nTrees);

    /// @notice Reset components to uninitialized state
    /// @param components_ The components struct to reset
    function reset(Components storage components_) internal {
        delete components_.components;
        components_.nPreprocessedColumns = 0;
        components_.isInitialized = false;
    }

    /// @notice Initialize components structure
    /// @param components_ The components struct to initialize
    /// @param componentStates Array of component states
    /// @param nPreprocessedColumns_ Number of preprocessed columns
    function initialize(
        Components storage components_,
        FrameworkComponentLib.ComponentState[] memory componentStates,
        uint256 nPreprocessedColumns_
    ) internal {  
        require(!components_.isInitialized, "Components already initialized");

        require(componentStates.length > 0, "No components provided");

        delete components_.components;
        for (uint256 i = 0; i < componentStates.length; i++) {
            components_.components.push();
            FrameworkComponentLib.ComponentState storage dest = components_.components[i];
            FrameworkComponentLib.ComponentState memory src = componentStates[i];
            
            dest.logSize = src.logSize;
            dest.claimedSum = src.claimedSum;
            dest.info = src.info;
            dest.isInitialized = src.isInitialized;

            // Copy trace locations
            for (uint256 j = 0; j < src.traceLocations.length; j++) {
                dest.traceLocations.push(src.traceLocations[j]);
            }

        }


        components_.nPreprocessedColumns = nPreprocessedColumns_;
        components_.isInitialized = true;

        emit ComponentsInitialized(componentStates.length, nPreprocessedColumns_);

    }

    /// @notice Get composition log degree bound
    /// @param components_ The components struct
    /// @return maxBound Maximum constraint log degree bound across all components
    function compositionLogDegreeBound(
        Components storage components_
    ) internal view returns (uint32 maxBound) {
        require(components_.isInitialized, "Components not initialized");
        require(components_.components.length > 0, "No components available");

        maxBound = 0;
        
        for (uint256 i = 0; i < components_.components.length; i++) {
            uint32 componentBound = FrameworkComponentLib.maxConstraintLogDegreeBound(
                components_.components[i]
            );
            
            if (componentBound > maxBound) {
                maxBound = componentBound;
            }
        }

        require(maxBound > 0, "No valid constraint bounds found");
        
        return maxBound;
    }

    /// @notice Generate mask points for all components
    /// @param components_ The components struct
    /// @param point The circle point to generate mask points for
    /// @return componentMaskPoints Array containing mask points for each component
    function maskPoints(
        Components storage components_,
        CirclePoint.Point memory point
    ) internal view returns (FrameworkComponentLib.SamplePoints[] memory componentMaskPoints) {

        require(components_.isInitialized, "Components not initialized");

        require(components_.components.length > 0, "No components available");

        componentMaskPoints = new FrameworkComponentLib.SamplePoints[](components_.components.length);

        for (uint256 i = 0; i < components_.components.length; i++) {
            componentMaskPoints[i] = FrameworkComponentLib.maskPoints(
                components_.components[i],
                point
            );
        }

        return componentMaskPoints;
    }

    /// @notice Get number of components
    /// @param components_ The components struct
    /// @return count Number of components
    function getComponentCount(
        Components storage components_
    ) internal view returns (uint256 count) {
        require(components_.isInitialized, "Components not initialized");
        return components_.components.length;
    }

    /// @notice Get component state by index
    /// @param components_ The components struct
    /// @param index Component index
    /// @return componentState The component state
    function getComponent(
        Components storage components_,
        uint256 index
    ) internal view returns (FrameworkComponentLib.ComponentState memory componentState) {
        require(components_.isInitialized, "Components not initialized");
        require(index < components_.components.length, "Component index out of bounds");
        
        return components_.components[index];
    }

    /// @notice Get number of preprocessed columns
    /// @param components_ The components struct
    /// @return count Number of preprocessed columns
    function getPreprocessedColumnCount(
        Components storage components_
    ) internal view returns (uint256 count) {
        require(components_.isInitialized, "Components not initialized");
        return components_.nPreprocessedColumns;
    }


    /// @notice Clear components structure
    /// @param components_ The components struct to clear
    function clear(Components storage components_) internal {
        require(components_.isInitialized, "Components not initialized");
        
        // Clear all component states
        for (uint256 i = 0; i < components_.components.length; i++) {
            FrameworkComponentLib.clearState(components_.components[i]);
        }
        
        delete components_.components;
        components_.nPreprocessedColumns = 0;
        components_.isInitialized = false;
    }


    /// @notice Concatenate columns from multiple component mask points
    /// @param componentMaskPoints Array of mask points from each component
    /// @return concatenated TreeVec with concatenated columns
    function _concatCols(
        FrameworkComponentLib.SamplePoints[] memory componentMaskPoints
    ) private pure returns (TreeVecMaskPoints memory concatenated) {
        if (componentMaskPoints.length == 0) {
            concatenated.nColumnsPerTree = new uint256[](3); // 3 trees
            concatenated.points = new CirclePoint.Point[][][](3);
            concatenated.totalPoints = 0;
            return concatenated;
        }

        uint256 nTrees = 3;
        concatenated.nColumnsPerTree = new uint256[](nTrees);
        concatenated.totalPoints = 0;

        for (uint256 compIdx = 0; compIdx < componentMaskPoints.length; compIdx++) {
            FrameworkComponentLib.SamplePoints memory compPoints = componentMaskPoints[compIdx];
            
            for (uint256 treeIdx = 0; treeIdx < nTrees && treeIdx < compPoints.nColumns.length; treeIdx++) {
                concatenated.nColumnsPerTree[treeIdx] += compPoints.nColumns[treeIdx];
            }
            concatenated.totalPoints += compPoints.totalPoints;
        }

        concatenated.points = new CirclePoint.Point[][][](nTrees);
        for (uint256 treeIdx = 0; treeIdx < nTrees; treeIdx++) {
            concatenated.points[treeIdx] = new CirclePoint.Point[][](concatenated.nColumnsPerTree[treeIdx]);
        }

        uint256[] memory currentColIndex = new uint256[](nTrees);
        
        for (uint256 compIdx = 0; compIdx < componentMaskPoints.length; compIdx++) {
            FrameworkComponentLib.SamplePoints memory compPoints = componentMaskPoints[compIdx];
            
            for (uint256 treeIdx = 0; treeIdx < nTrees && treeIdx < compPoints.points.length; treeIdx++) {
                for (uint256 colIdx = 0; colIdx < compPoints.points[treeIdx].length; colIdx++) {
                    uint256 targetColIdx = currentColIndex[treeIdx];
                    
                    if (targetColIdx < concatenated.points[treeIdx].length) {
                        concatenated.points[treeIdx][targetColIdx] = compPoints.points[treeIdx][colIdx];
                        currentColIndex[treeIdx]++;
                    }
                }
            }
        }

        return concatenated;
    }

    /// @notice Convert uint256 to string
    /// @param value The value to convert
    /// @return str String representation
    function _toString(uint256 value) private pure returns (string memory str) {
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