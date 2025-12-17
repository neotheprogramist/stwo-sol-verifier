// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../core/PointEvaluationAccumulator.sol";
import "../fields/QM31Field.sol";
import "../pcs/TreeVec.sol";

/// @title PointEvaluatorLib
/// @notice Library for evaluating expressions at a point out of domain
library PointEvaluatorLib {
    using QM31Field for QM31Field.QM31;
    using PointEvaluationAccumulator for PointEvaluationAccumulator.Accumulator;


    uint256 internal constant PREPROCESSED_TRACE_IDX = 0;
    uint256 internal constant ORIGINAL_TRACE_IDX = 1;
    uint256 internal constant INTERACTION_TRACE_IDX = 2;
    uint256 internal constant SECURE_EXTENSION_DEGREE = 4;


    /// @notice Point evaluator state struct
    struct PointEvaluator {
        /// @notice Mask values organized as TreeVec<ColumnVec<Vec<SecureField>>>
        QM31Field.QM31[][][] mask;

        /// @notice Point evaluation accumulator
        PointEvaluationAccumulator.Accumulator evaluationAccumulator;

        /// @notice Current column indices for each interaction
        uint256[] colIndex;

        /// @notice Denominator inverse for constraint quotients
        QM31Field.QM31 denomInverse;

        /// @notice Log size of the trace
        uint32 logSize;

        /// @notice Claimed sum for logup constraints
        QM31Field.QM31 claimedSum;

        // Evaluation state tracking
        uint256 currentInteraction;
        uint256 currentColumn;
        uint256 constraintsAdded;
        bool evaluationComplete;
    }

    // Constructor & Initialization Functions

    /// @notice Create new PointEvaluator
    /// @param _mask Mask values as TreeVec<ColumnVec<Vec<SecureField>>>
    /// @param _evaluationAccumulator Point evaluation accumulator
    /// @param _denomInverse Denominator inverse for quotients
    /// @param _logSize Log size of the trace
    /// @param _claimedSum Claimed sum for logup constraints
    /// @return evaluator Initialized PointEvaluator struct
    function create(
        QM31Field.QM31[][][] memory _mask,
        PointEvaluationAccumulator.Accumulator memory _evaluationAccumulator,
        QM31Field.QM31 memory _denomInverse,
        uint32 _logSize,
        QM31Field.QM31 memory _claimedSum
    ) internal pure returns (PointEvaluator memory evaluator) {
        evaluator.mask = _mask;
        evaluator.evaluationAccumulator = _evaluationAccumulator;
        evaluator.denomInverse = _denomInverse;
        evaluator.logSize = _logSize;
        evaluator.claimedSum = _claimedSum;

        // Initialize column indices for each interaction
        evaluator.colIndex = new uint256[](_mask.length);
        for (uint256 i = 0; i < _mask.length; i++) {
            evaluator.colIndex[i] = 0;
        }

        // Initialize evaluation state
        evaluator.currentInteraction = 0;
        evaluator.currentColumn = 0;
        evaluator.constraintsAdded = 0;
        evaluator.evaluationComplete = false;

        return evaluator;
    }

    // Core EvalAtRow Implementation Functions

    /// @notice Get next interaction mask values
    /// @param self The PointEvaluator struct
    /// @param interaction Interaction index
    /// @param offsets Array of offsets (ignored in current implementation)
    /// @return updatedSelf Modified PointEvaluator struct with advanced state
    /// @return maskValues Array of mask values
    function nextInteractionMask(
        PointEvaluator memory self,
        uint256 interaction,
        int256[] memory offsets
    ) internal pure returns (PointEvaluator memory updatedSelf, QM31Field.QM31[] memory maskValues) {
        require(interaction < self.mask.length, "Invalid interaction index");
        
        uint256 currentColIndex = self.colIndex[interaction];
        require(currentColIndex < self.mask[interaction].length, "Column index out of bounds");
        
        // Get the entire mask column (equivalent to mask.clone() in Rust)
        maskValues = self.mask[interaction][currentColIndex];
        
        // Assert length matches expected N (equivalent to assert_eq!(mask.len(), N))
        require(maskValues.length == offsets.length, "Mask length mismatch");

        // Advance column index for this interaction
        self.colIndex[interaction]++;
        self.currentColumn++;
        return (self, maskValues);
    }

    /// @notice Add constraint to accumulator
    /// @param self The PointEvaluator struct
    /// @param constraint Constraint to add
    /// @return updatedSelf Modified PointEvaluator struct with updated accumulator
    function addConstraint(
        PointEvaluator memory self,
        QM31Field.QM31 memory constraint
    ) internal pure returns (PointEvaluator memory updatedSelf) {
        // Apply denominator inverse: constraint_quotient = constraint * denom_inverse
        QM31Field.QM31 memory quotient = QM31Field.mul(constraint, self.denomInverse);
        
        // Accumulate the constraint quotient
        self.evaluationAccumulator = self.evaluationAccumulator.accumulate(quotient);
        
        self.constraintsAdded++;
        
        return self;
    }
    // TODO:
    // /// @notice Combine extension field values
    // /// @param values Array of 4 QM31 values
    // /// @return extendedValue Combined extended field value
    // function combineEF(QM31Field.QM31[4] memory values) 
    //     internal 
    //     pure 
    //     returns (QM31Field.QM31 memory extendedValue)
    // {
    //     // For QM31, we already work with extended field
    //     // This is a placeholder implementation
    //     return values[0];
    // }

    /// @notice Get next trace mask value
    /// @param self The PointEvaluator struct
    /// @return updatedSelf Modified PointEvaluator struct with advanced state
    /// @return maskValue Next trace mask value
    function nextTraceMask(PointEvaluator memory self) 
        internal 
        pure 
        returns (PointEvaluator memory updatedSelf, QM31Field.QM31 memory maskValue) 
    {
        int256[] memory offsets = new int256[](1);
        offsets[0] = 0; // Offset 0 for next trace mask
        
        QM31Field.QM31[] memory masks;
        (self, masks) = nextInteractionMask(self, ORIGINAL_TRACE_IDX, offsets);
        return (self, masks[0]);
    }

    /// @notice Get preprocessed column value
    /// @param self The PointEvaluator struct
    /// @param _columnId Column identifier (unused in current implementation)
    /// @return updatedSelf Modified PointEvaluator struct with advanced state
    /// @return columnValue Preprocessed column value
    function getPreprocessedColumn(PointEvaluator memory self, uint256 _columnId) 
        internal 
        pure 
        returns (PointEvaluator memory updatedSelf, QM31Field.QM31 memory columnValue)
    {
        int256[] memory offsets = new int256[](1);
        offsets[0] = 0;
        
        QM31Field.QM31[] memory masks;
        (self, masks) = nextInteractionMask(self, PREPROCESSED_TRACE_IDX, offsets);
        return (self, masks[0]);
    }

    // TODO: check if it's correct
    /// @notice Add to relation (simplified implementation)
    /// @param self The PointEvaluator struct
    /// @param relationId Relation identifier
    /// @param entries Relation entries
    /// @return updatedSelf Modified PointEvaluator struct with accumulated relations
    function addToRelation(
        PointEvaluator memory self,
        uint256 relationId,
        QM31Field.QM31[] memory entries
    ) internal pure returns (PointEvaluator memory updatedSelf) {
        // For now, we implement a simplified version that treats relation entries
        // as constraints to be accumulated
        for (uint256 i = 0; i < entries.length; i++) {
            self = addConstraint(self, entries[i]);
        }
        return self;
    }

    // TODO: check if it's correct
    /// @notice Add logup constraint
    /// @param self The PointEvaluator struct
    /// @param numerator Logup numerator
    /// @param denominator Logup denominator
    /// @return updatedSelf Modified PointEvaluator struct with logup constraint
    function addLogupConstraint(
        PointEvaluator memory self,
        QM31Field.QM31 memory numerator, 
        QM31Field.QM31 memory denominator
    ) internal pure returns (PointEvaluator memory updatedSelf) {
        // Placeholder for logup constraints
        // In full implementation, this would handle logup fraction accumulation
        QM31Field.QM31 memory logupValue = QM31Field.div(numerator, denominator);
        return addConstraint(self, logupValue);
    }

    // State Access Functions

    /// @notice Get evaluation state
    /// @param self The PointEvaluator struct
    /// @return currentInteraction Current interaction index
    /// @return currentColumn Current column index
    /// @return constraintsAdded Number of constraints added
    function getEvaluationState(PointEvaluator memory self)
        internal
        pure
        returns (
            uint256 currentInteraction,
            uint256 currentColumn,
            uint256 constraintsAdded
        )
    {
        return (self.currentInteraction, self.currentColumn, self.constraintsAdded);
    }

    /// @notice Check if evaluation is complete
    /// @param self The PointEvaluator struct
    /// @return isComplete True if evaluation is complete
    function isEvaluationComplete(PointEvaluator memory self) 
        internal 
        pure 
        returns (bool isComplete) 
    {
        return self.evaluationComplete;
    }

    /// @notice Get the current accumulator state
    /// @param self The PointEvaluator struct
    /// @return accumulator Current point evaluation accumulator
    function getAccumulator(PointEvaluator memory self) 
        internal 
        pure 
        returns (PointEvaluationAccumulator.Accumulator memory accumulator) 
    {
        return self.evaluationAccumulator;
    }

    /// @notice Reset column indices for reuse
    /// @param self The PointEvaluator struct
    function resetColumnIndices(PointEvaluator memory self) internal pure {
        for (uint256 i = 0; i < self.colIndex.length; i++) {
            self.colIndex[i] = 0;
        }
        self.currentColumn = 0;
        self.constraintsAdded = 0;
        self.evaluationComplete = false;
    }

    /// @notice Mark evaluation as complete
    /// @param self The PointEvaluator struct
    function markComplete(PointEvaluator memory self) internal pure {
        self.evaluationComplete = true;
    }

    /// @notice Get mask dimensions for debugging
    /// @param self The PointEvaluator struct
    /// @return nTrees Number of trees (interactions)
    /// @return nColumns Number of columns per tree
    /// @return nValues Number of values per column
    function getMaskDimensions(PointEvaluator memory self) 
        internal 
        pure 
        returns (
            uint256 nTrees,
            uint256[] memory nColumns,
            uint256[][] memory nValues
        )
    {
        nTrees = self.mask.length;
        nColumns = new uint256[](nTrees);
        nValues = new uint256[][](nTrees);

        for (uint256 i = 0; i < nTrees; i++) {
            nColumns[i] = self.mask[i].length;
            nValues[i] = new uint256[](self.mask[i].length);
            
            for (uint256 j = 0; j < self.mask[i].length; j++) {
                nValues[i][j] = self.mask[i][j].length;
            }
        }
    }
}