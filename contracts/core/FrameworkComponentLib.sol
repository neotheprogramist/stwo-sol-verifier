// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../circle/CirclePoint.sol";
import "../circle/CirclePointM31.sol";
import "../cosets/CanonicCosetM31.sol";
import "../cosets/CosetM31.sol";
import "../fields/QM31Field.sol";
import "../utils/TreeSubspan.sol";
import "./TraceLocationAllocatorLib.sol";

/// @title FrameworkComponentLib
/// @notice Library implementing FrameworkComponent functionality for gas optimization
/// @dev Converts contract to library to reduce deployment gas from 4M to ~400k
library FrameworkComponentLib {
    using QM31Field for QM31Field.QM31;
    using TreeSubspan for TreeSubspan.Subspan;
    using TraceLocationAllocatorLib for TraceLocationAllocatorLib.AllocatorState;
    using CanonicCosetM31 for CanonicCosetM31.CanonicCosetStruct;
    using CirclePointM31 for CirclePointM31.Point;


    uint256 public constant PREPROCESSED_TRACE_IDX = 0;
    uint256 public constant ORIGINAL_TRACE_IDX = 1;
    uint256 public constant INTERACTION_TRACE_IDX = 2;


    /// @notice Sample points structure for mask points generation
    struct SamplePoints {
        CirclePoint.Point[][][] points; // [tree][column][mask_point]
        uint256[] nColumns; // Number of columns per tree
        uint256 totalPoints; // Total number of mask points
        CirclePoint.Point[][] preprocessed; // Convenient access to preprocessed points (tree 0)
    }

    /// @notice Component information structure
    struct ComponentInfo {
        uint32 maxConstraintLogDegreeBound;
        uint32 logSize;
        int32[][][] maskOffsets; // Mask offsets: [tree][column][offset_values] from InfoEvaluator
        uint256[] preprocessedColumns; // Preprocessed column IDs
    }

    /// @notice Framework component state
    struct ComponentState {
        uint32 logSize;
        /// @notice Trace locations allocated for this component
        TreeSubspan.Subspan[] traceLocations;
        /// @notice Preprocessed column indices
        uint256[] preprocessedColumnIndices;
        /// @notice Claimed sum for logup constraints
        QM31Field.QM31 claimedSum;
        /// @notice Component metadata
        ComponentInfo info;
        /// @notice Whether the component is initialized
        bool isInitialized;
    }


    function createComponent(
        TraceLocationAllocatorLib.AllocatorState storage allocator,
        uint32 logSize,
        QM31Field.QM31 memory claimedSum,
        ComponentInfo memory info
    )
        internal
        returns (
            ComponentState memory stateUpdated
        )
    {
        uint256[] memory treeStructure = new uint256[](info.maskOffsets.length);
        for (uint256 i = 0; i < info.maskOffsets.length; i++) {
            treeStructure[i] = info.maskOffsets[i].length;
        }

        
        TreeSubspan.Subspan[] memory traceLocations = allocator.nextForStructure(
            treeStructure,
            ORIGINAL_TRACE_IDX
        );

        uint256[] memory preprocessedColumnIndicesCompute = _getPreprocessedColumnIndices(
            allocator,
            info.preprocessedColumns
        );

        require(!stateUpdated.isInitialized, "Component already initialized");
        require(traceLocations.length > 0, "No trace locations provided");
        require(info.logSize > 0, "Invalid log size");

        stateUpdated.logSize = logSize;
        stateUpdated.claimedSum = claimedSum;
        stateUpdated.info = info;
        stateUpdated.isInitialized = true;

        stateUpdated.traceLocations = traceLocations;

        stateUpdated.preprocessedColumnIndices = preprocessedColumnIndicesCompute;

    }

    /// @notice Get preprocessed column indices
    /// @dev Maps Rust logic: allocator mapping preprocessed columns to their indices
    /// Rust: info.preprocessed_columns.iter().map(|col| { let next_column = ...; if let Some(pos) = ... })
    function _getPreprocessedColumnIndices(
        TraceLocationAllocatorLib.AllocatorState storage allocator,
        uint256[] memory preprocessedColumns
    ) private returns (uint256[] memory indices) {
        indices = new uint256[](preprocessedColumns.length);

        for (uint256 i = 0; i < preprocessedColumns.length; i++) {
            uint256 columnId = preprocessedColumns[i];
            
            uint256 nextColumn = TraceLocationAllocatorLib.getPreprocessedColumnsLength(allocator);
            
            (bool found, uint256 position) = TraceLocationAllocatorLib.findPreprocessedColumn(allocator, columnId);
            
            if (found) {
                indices[i] = position;
            } else {
                require(!TraceLocationAllocatorLib.isStaticAllocationMode(allocator), 
                    string(abi.encodePacked("Preprocessed column ", _toString(columnId), " is missing from static allocation")));
                
                TraceLocationAllocatorLib.addPreprocessedColumn(allocator, columnId);
                indices[i] = nextColumn;
            }
        }
    }

    /// @notice Convert uint256 to string for error messages
    function _toString(uint256 value) private pure returns (string memory) {
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

    /// @notice Initialize framework component state
    /// @param state The component state to initialize
    /// @param logSize Log size of the trace
    /// @param _traceLocations Allocated trace locations
    /// @param _preprocessedColumnIndices Indices of preprocessed columns
    /// @param _claimedSum Claimed sum for logup constraints
    /// @param _componentInfo Component metadata
    function initialize(
        ComponentState storage state,
        uint32 logSize,
        TreeSubspan.Subspan[] memory _traceLocations,
        uint256[] memory _preprocessedColumnIndices,
        QM31Field.QM31 memory _claimedSum,
        ComponentInfo memory _componentInfo
    ) internal {
        require(!state.isInitialized, "Component already initialized");
        require(_traceLocations.length > 0, "No trace locations provided");
        require(_componentInfo.logSize > 0, "Invalid log size");

        state.logSize = logSize;
        state.claimedSum = _claimedSum;
        state.info = _componentInfo;
        state.isInitialized = true;

        delete state.traceLocations;
        for (uint256 i = 0; i < _traceLocations.length; i++) {
            state.traceLocations.push(_traceLocations[i]);
        }

        delete state.preprocessedColumnIndices;
        for (uint256 i = 0; i < _preprocessedColumnIndices.length; i++) {
            state.preprocessedColumnIndices.push(_preprocessedColumnIndices[i]);
        }
    }

    /// @notice Get maximum constraint log degree bound
    /// @param state The component state
    /// @return maxLogDegreeBound Maximum constraint log degree bound
    function maxConstraintLogDegreeBound(
        ComponentState storage state
    ) internal view returns (uint32 maxLogDegreeBound) {
        require(state.isInitialized, "Component not initialized");
        return state.info.maxConstraintLogDegreeBound;
    }

    /// @notice Get trace log degree bounds
    /// @param state The component state
    /// @return bounds Trace log degree bounds for each tree
    function traceLogDegreeBounds(
        ComponentState storage state
    ) internal view returns (uint32[][] memory bounds) {
        require(state.isInitialized, "Component not initialized");

        bounds = new uint32[][](state.traceLocations.length);

        for (uint256 i = 0; i < state.traceLocations.length; i++) {
            uint256 numCols = state.traceLocations[i].size();
            bounds[i] = new uint32[](numCols);

            for (uint256 j = 0; j < numCols; j++) {
                bounds[i][j] = state.info.logSize;
            }
        }

        if (bounds.length > 0 && state.preprocessedColumnIndices.length > 0) {
            for (
                uint256 i = 0;
                i < state.preprocessedColumnIndices.length;
                i++
            ) {
                if (i < bounds[0].length) {
                    bounds[0][i] = state.info.logSize;
                }
            }
        }

        return bounds;
    }

    function maskPoints(
        ComponentState storage state,
        CirclePoint.Point memory point
    ) internal view returns (SamplePoints memory samplePoints) {
        require(state.isInitialized, "Component not initialized");

        CirclePointM31.Point memory traceStepM31 = _getTraceStep(state.logSize);
        samplePoints = _initializeSamplePoints();
        samplePoints = _processTraceLocations(state, point, traceStepM31, samplePoints);
        samplePoints = _processPreprocessedColumns(state, point, samplePoints);
        
        return samplePoints;
    }

    function _getTraceStep(uint32 logSize) private pure returns (CirclePointM31.Point memory) {
        CanonicCosetM31.CanonicCosetStruct memory canonicCosetM31 = CanonicCosetM31.newCanonicCoset(logSize);
        return CanonicCosetM31.step(canonicCosetM31);
    }

    function _initializeSamplePoints() private pure returns (SamplePoints memory samplePoints) {
        uint256 nTrees = 3;
        samplePoints.points = new CirclePoint.Point[][][](nTrees);
        samplePoints.nColumns = new uint256[](nTrees);
        samplePoints.totalPoints = 0;

        for (uint256 treeIdx = 0; treeIdx < nTrees; treeIdx++) {
            samplePoints.nColumns[treeIdx] = 0;
            samplePoints.points[treeIdx] = new CirclePoint.Point[][](0);
        }
    }

    function _processTraceLocations(
        ComponentState storage state,
        CirclePoint.Point memory point,
        CirclePointM31.Point memory traceStepM31,
        SamplePoints memory samplePoints
    ) private view returns (SamplePoints memory) {
        uint256 nTrees = 3;
        
        for (uint256 locationIdx = 0; locationIdx < state.traceLocations.length; locationIdx++) {
            TreeSubspan.Subspan memory location = state.traceLocations[locationIdx];
            uint256 treeIdx = location.treeIndex;

            if (treeIdx < nTrees) {
                samplePoints = _ensureTreeCapacity(samplePoints, treeIdx, location.colEnd);
                samplePoints = _processLocationColumns(state, point, traceStepM31, samplePoints, location, treeIdx);
            }
        }
        return samplePoints;
    }

    function _ensureTreeCapacity(
        SamplePoints memory samplePoints,
        uint256 treeIdx,
        uint256 requiredSize
    ) private pure returns (SamplePoints memory) {
        if (samplePoints.points[treeIdx].length < requiredSize) {
            CirclePoint.Point[][] memory newTree = new CirclePoint.Point[][](requiredSize);
            for (uint256 i = 0; i < samplePoints.points[treeIdx].length; i++) {
                newTree[i] = samplePoints.points[treeIdx][i];
            }
            samplePoints.points[treeIdx] = newTree;
            samplePoints.nColumns[treeIdx] = requiredSize;
        }
        return samplePoints;
    }

    function _processLocationColumns(
        ComponentState storage state,
        CirclePoint.Point memory point,
        CirclePointM31.Point memory traceStepM31,
        SamplePoints memory samplePoints,
        TreeSubspan.Subspan memory location,
        uint256 treeIdx
    ) private view returns (SamplePoints memory) {
        uint256 numCols = location.size();
        
        for (uint256 colOffset = 0; colOffset < numCols; colOffset++) {
            uint256 colIdx = location.colStart + colOffset;
            if (colIdx < samplePoints.points[treeIdx].length) {
                samplePoints = _processColumn(state, point, traceStepM31, samplePoints, treeIdx, colIdx);
            }
        }
        return samplePoints;
    }

    function _processColumn(
        ComponentState storage state,
        CirclePoint.Point memory point,
        CirclePointM31.Point memory traceStepM31,
        SamplePoints memory samplePoints,
        uint256 treeIdx,
        uint256 colIdx
    ) private view returns (SamplePoints memory) {
        int32[] memory maskOffsets = _getMaskOffsets(state, treeIdx, colIdx);
        samplePoints.points[treeIdx][colIdx] = new CirclePoint.Point[](maskOffsets.length);

        for (uint256 offsetIdx = 0; offsetIdx < maskOffsets.length; offsetIdx++) {
            samplePoints.points[treeIdx][colIdx][offsetIdx] = _computeMaskPoint(
                point, traceStepM31, maskOffsets[offsetIdx]
            );
            samplePoints.totalPoints++;
        }
        return samplePoints;
    }

    function _getMaskOffsets(
        ComponentState storage state,
        uint256 treeIdx,
        uint256 colIdx
    ) private view returns (int32[] memory) {
        if (treeIdx < state.info.maskOffsets.length && colIdx < state.info.maskOffsets[treeIdx].length) {
            return state.info.maskOffsets[treeIdx][colIdx];
        } else {
            return new int32[](0);
        }
    }

    function _computeMaskPoint(
        CirclePoint.Point memory point,
        CirclePointM31.Point memory traceStepM31,
        int32 offset
    ) private pure returns (CirclePoint.Point memory) {
        CirclePointM31.Point memory offsetPoint = CirclePointM31.mulSigned(traceStepM31, offset);
        
        CirclePoint.Point memory offsetPointQM31 = CirclePoint.Point({
            x: QM31Field.fromM31(offsetPoint.x, 0, 0, 0),
            y: QM31Field.fromM31(offsetPoint.y, 0, 0, 0)
        });

        return CirclePoint.add(point, offsetPointQM31);
    }

    function _processPreprocessedColumns(
        ComponentState storage state,
        CirclePoint.Point memory point,
        SamplePoints memory samplePoints
    ) private view returns (SamplePoints memory) {
        for (uint256 i = 0; i < state.preprocessedColumnIndices.length; i++) {
            uint256 colIdx = state.preprocessedColumnIndices[i];
            if (colIdx < samplePoints.points[PREPROCESSED_TRACE_IDX].length) {
                samplePoints.points[PREPROCESSED_TRACE_IDX][colIdx] = new CirclePoint.Point[](1);
                samplePoints.points[PREPROCESSED_TRACE_IDX][colIdx][0] = point;
                samplePoints.totalPoints++;
            }
        }
        
        samplePoints.preprocessed = samplePoints.points[PREPROCESSED_TRACE_IDX];
        return samplePoints;
    }

    /// @notice Get preprocessed column indices
    /// @param state The component state
    /// @return indices Preprocessed column indices
    function preprocessedColumnIndices(
        ComponentState storage state
    ) internal view returns (uint256[] memory indices) {
        require(state.isInitialized, "Component not initialized");
        return state.preprocessedColumnIndices;
    }


    /// @notice Get trace locations
    /// @param state The component state
    /// @return locations Array of trace locations
    function getTraceLocations(
        ComponentState storage state
    ) internal view returns (TreeSubspan.Subspan[] memory locations) {
        require(state.isInitialized, "Component not initialized");
        return state.traceLocations;
    }

    /// @notice Get preprocessed column indices
    /// @param state The component state
    /// @return indices Array of preprocessed column indices
    function getPreprocessedColumnIndices(
        ComponentState storage state
    ) internal view returns (uint256[] memory indices) {
        require(state.isInitialized, "Component not initialized");
        return state.preprocessedColumnIndices;
    }

    /// @notice Get claimed sum
    /// @param state The component state
    /// @return sum Claimed sum for logup constraints
    function getClaimedSum(
        ComponentState storage state
    ) internal view returns (QM31Field.QM31 memory sum) {
        require(state.isInitialized, "Component not initialized");
        return state.claimedSum;
    }

    /// @notice Get component info
    /// @param state The component state
    /// @return componentInfo Complete component information
    function getInfo(
        ComponentState storage state
    ) internal view returns (ComponentInfo memory componentInfo) {
        require(state.isInitialized, "Component not initialized");
        return state.info;
    }

    /// @notice Clear component state after use
    /// @param state The component state to clear
    function clearState(ComponentState storage state) internal {
        require(state.isInitialized, "Component not initialized");

        delete state.traceLocations;
        delete state.preprocessedColumnIndices;

        state.logSize = 0;
        state.claimedSum = QM31Field.zero();
        delete state.info;
        state.isInitialized = false;
    }

    function _calculateVanishingInverse(
        CosetM31.CosetStruct memory coset,
        CirclePoint.Point memory point
    ) internal pure returns (QM31Field.QM31 memory inverse) {
        // Implementation of coset vanishing polynomial based on Rust coset_vanishing function
        // pub fn coset_vanishing<F: ExtensionOf<BaseField>>(coset: Coset, mut p: CirclePoint<F>) -> F

        CirclePoint.Point memory rotatedPoint = _rotatePointToCanonic(
            coset,
            point
        );

        QM31Field.QM31 memory x = rotatedPoint.x;

        for (uint32 i = 1; i < coset.logSize; i++) {
            x = CirclePoint.doubleX(x);
        }

        if (QM31Field.isZero(x)) {
            revert("Point is on coset - vanishing polynomial is zero");
        }

        return QM31Field.inverse(x);
    }

    /**
     * @notice Helper function to rotate point to canonical coset form
     * @dev Implements: p - coset.initial + coset.step_size.half().to_point()
     * @param coset The coset structure
     * @param point The original point
     * @return rotatedPoint The point after canonical rotation
     */
    function _rotatePointToCanonic(
        CosetM31.CosetStruct memory coset,
        CirclePoint.Point memory point
    ) private pure returns (CirclePoint.Point memory rotatedPoint) {
        CirclePoint.Point memory initialPoint = _m31ToQM31Point(coset.initial);

        CirclePoint.Point memory halfStep = _getHalfStepPoint(coset);

        rotatedPoint = CirclePoint.add(
            CirclePoint.sub(point, initialPoint),
            halfStep
        );

        return rotatedPoint;
    }

    /**
     * @notice Convert M31 CirclePoint to QM31 CirclePoint
     * @dev Convert CirclePointM31.Point to CirclePoint.Point
     * @param m31Point The M31 circle point
     * @return qm31Point The corresponding QM31 circle point
     */
    function _m31ToQM31Point(
        CirclePointM31.Point memory m31Point
    ) private pure returns (CirclePoint.Point memory qm31Point) {
        qm31Point = CirclePoint.Point({
            x: QM31Field.fromM31(m31Point.x, 0, 0, 0),
            y: QM31Field.fromM31(m31Point.y, 0, 0, 0)
        });

        return qm31Point;
    }

    /**
     * @notice Get step_size.half().to_point() equivalent
     * @dev Gets half of the step as a circle point
     * @param coset The coset structure containing step information
     * @return halfStepPoint The half-step as a circle point
     */
    function _getHalfStepPoint(
        CosetM31.CosetStruct memory coset
    ) private pure returns (CirclePoint.Point memory halfStepPoint) {
        uint256 stepIndex = coset.stepSize.value;

        uint256 halfStepIndex = stepIndex >> 1;

        CirclePointM31.Point memory pointIndex = _indexToPoint(halfStepIndex);
        halfStepPoint = _m31ToQM31Point(pointIndex);

        return halfStepPoint;
    }

    /**
     * @notice Convert circle point index to actual circle point
     * @dev Implements M31_CIRCLE_GEN.mul(index) from Rust
     * @param index The circle point index
     * @return point The corresponding circle point
     */
    function _indexToPoint(
        uint256 index
    ) private pure returns (CirclePointM31.Point memory point) {
        CirclePointM31.Point memory generator = CirclePointM31.Point({
            x: 2,
            y: 1268011823
        });

        point = CirclePointM31.mul(generator, index);
        return point;
    }
}
