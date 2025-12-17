// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../pcs/TreeVec.sol";
import "../pcs/PcsConfig.sol";
import "../vcs/MerkleVerifier.sol";
import "../core/CirclePoint.sol";
import "../core/CirclePolyDegreeBound.sol";
import "../fields/QM31Field.sol";
import "../utils/ArrayUtils.sol";
import "./KeccakChannelLib.sol";

/// @title CommitmentSchemeVerifierLib
/// @notice Library for verifying polynomial commitment scheme proofs using FRI and Merkle trees
/// @dev Stateless library for STWO commitment scheme with state stored in calling contract
library CommitmentSchemeVerifierLib {
    using TreeVec for TreeVec.Bytes32TreeVec;
    using TreeVec for TreeVec.Uint32ArrayTreeVec;
    using PcsConfig for PcsConfig.Config;
    using MerkleVerifier for MerkleVerifier.Verifier;
    using QM31Field for QM31Field.QM31;
    using CirclePoint for CirclePoint.Point;
    using CirclePolyDegreeBound for CirclePolyDegreeBound.Bound;
    using ArrayUtils for TreeVec.Uint32ArrayTreeVec;
    using KeccakChannelLib for KeccakChannelLib.ChannelState;

    /// @notice Verifier state containing trees and configuration
    /// @param trees TreeVec of Merkle verifiers for each commitment tree
    /// @param config PCS configuration (FRI + PoW parameters)
    struct VerifierState {
        MerkleVerifier.Verifier merkleVerifier;    // Multi-tree Merkle verifier
        PcsConfig.Config config;                    // PCS configuration
    }

    /// @notice Commitment scheme proof structure
    /// @param commitments Tree roots for each commitment
    /// @param sampledValues Sampled polynomial values at OODS point
    /// @param decommitments Merkle decommitment proofs
    /// @param queriedValues Values at FRI query positions
    /// @param proofOfWork Proof of work nonce
    /// @param friProof FRI verification proof (placeholder for now)
    struct Proof {
        bytes32[] commitments;           // TreeVec<Hash>
        QM31Field.QM31[] sampledValues;  // TreeVec<ColumnVec<Vec<SecureField>>>
        bytes[] decommitments;           // TreeVec<MerkleDecommitment> (encoded)
        uint32[] queriedValues;          // TreeVec<Vec<BaseField>>
        uint64 proofOfWork;              // Proof of work nonce
        bytes friProof;                  // FRI proof (to be implemented)
    }

    /// @notice Commitment scheme verification error types
    error InvalidCommitment(uint256 treeIndex, bytes32 expected, bytes32 actual);
    error InvalidProofStructure(string reason);
    error OodsNotMatching(QM31Field.QM31 expected, QM31Field.QM31 actual);
    error ProofOfWorkFailed(uint32 required, uint64 nonce);
    error FriVerificationFailed(string reason);
    error MerkleDecommitmentFailed(uint256 treeIndex);

    /// @notice Events for debugging and monitoring
    event CommitmentAdded(uint256 indexed treeIndex, bytes32 indexed root);
    event VerificationStarted(bytes32 indexed proofHash);
    event VerificationCompleted(bool indexed success);

    /// @notice Initialize verifier state with configuration and trees
    /// @param state Verifier state to initialize
    /// @param config PCS configuration
    /// @param treeRoots Array of Merkle tree roots (from proof commitments)
    /// @param treeColumnLogSizes Array of column log sizes arrays (one per tree)
    function initialize(
        VerifierState storage state, 
        PcsConfig.Config memory config,
        bytes32[] memory treeRoots,
        uint32[][] memory treeColumnLogSizes
    ) internal {
        require(PcsConfig.isValidConfig(config), "Invalid PCS configuration");
        require(treeRoots.length == treeColumnLogSizes.length, "Mismatched trees and column sizes");
        
        state.config = config;
        
        // Create Merkle verifier with all trees
        state.merkleVerifier = MerkleVerifier.newVerifier(treeRoots, treeColumnLogSizes);
    }
    
    /// @notice Initialize verifier state with configuration only (for incremental tree addition)
    /// @param state Verifier state to initialize
    /// @param config PCS configuration
    function initializeEmpty(VerifierState storage state, PcsConfig.Config memory config) internal {
        require(PcsConfig.isValidConfig(config), "Invalid PCS configuration");
        
        state.config = config;
        // Initialize empty merkle verifier (trees will be added via commit)
        delete state.merkleVerifier;
    }

    /// @notice Clear verifier state after verification
    /// @param state Verifier state to clear
    function clearState(VerifierState storage state) internal {
        // Clear merkle verifier
        delete state.merkleVerifier;
        // Keep config for reuse
    }

    /// @notice Add commitment tree to verifier
    /// @param state Verifier state
    /// @param commitment Tree root hash
    /// @param logSizes Column log sizes for this tree
    /// @param channelState Channel state for Fiat-Shamir mixing
    function commit(
        VerifierState storage state,
        bytes32 commitment,
        uint32[] memory logSizes,
        KeccakChannelLib.ChannelState storage channelState
    ) internal {
        channelState.mixRoot(channelState.digest, commitment);
        
        uint32[] memory extendedLogSizes = new uint32[](logSizes.length);
        for (uint256 i = 0; i < logSizes.length; i++) {
            extendedLogSizes[i] = logSizes[i] + state.config.friConfig.logBlowupFactor;
        }
        
        MerkleVerifier.MerkleTree memory newTree = MerkleVerifier.createMerkleTree(
            commitment,
            extendedLogSizes
        );
        
        uint256 currentLength = state.merkleVerifier.trees.length;
        MerkleVerifier.MerkleTree[] memory newTrees = new MerkleVerifier.MerkleTree[](currentLength + 1);
        for (uint256 i = 0; i < currentLength; i++) {
            newTrees[i] = state.merkleVerifier.trees[i];
        }
        newTrees[currentLength] = newTree;
        state.merkleVerifier.trees = newTrees;
        
    }



    /// @notice Get verifier configuration
    /// @param state Verifier state
    /// @return Current PCS configuration
    function getConfig(VerifierState storage state) internal view returns (PcsConfig.Config memory) {
        return state.config;
    }

    /// @notice Get number of commitment trees
    /// @param state Verifier state
    /// @return Number of trees
    function getTreeCount(VerifierState storage state) internal view returns (uint256) {
        return state.merkleVerifier.trees.length;
    }

    /// @notice Get tree root by index
    /// @param state Verifier state
    /// @param index Tree index
    /// @return Tree root hash
    function getTreeRoot(VerifierState storage state, uint256 index) internal view returns (bytes32) {
        require(index < state.merkleVerifier.trees.length, "Tree index out of bounds");
        return state.merkleVerifier.trees[index].root;
    }

    /// @notice Get column log sizes for tree
    /// @param state Verifier state
    /// @param index Tree index
    /// @return Column log sizes
    function getColumnLogSizes(VerifierState storage state, uint256 index) internal view returns (uint32[] memory) {
        require(index < state.merkleVerifier.trees.length, "Tree index out of bounds");
        return state.merkleVerifier.trees[index].columnLogSizes;
    }

    /// @notice Get column log sizes for all trees (matches Rust column_log_sizes)
    /// @param state Verifier state
    /// @return Array of column log sizes arrays (one per tree)
    function columnLogSizes(VerifierState storage state) internal view returns (uint32[][] memory) {
        uint32[][] memory result = new uint32[][](state.merkleVerifier.trees.length);
        for (uint256 i = 0; i < state.merkleVerifier.trees.length; i++) {
            result[i] = state.merkleVerifier.trees[i].columnLogSizes;
        }
        return result;
    }


    /// @notice Calculate degree bounds for FRI verification
    ///                    .map(|log_size| CirclePolyDegreeBound::new(log_size - self.config.fri_config.log_blowup_factor))
    /// @param state Verifier state containing column log sizes and config
    /// @return bounds Array of CirclePolyDegreeBound for FRI verification
    function calculateBounds(VerifierState storage state) 
        internal 
        view 
        returns (CirclePolyDegreeBound.Bound[] memory bounds) 
    {
        uint32[] memory flattenedLogSizes = _flattenColumnLogSizes(state);
        
        uint32[] memory processedLogSizes = _sortReverseDedup(flattenedLogSizes);
        
        uint32 logBlowupFactor = state.config.friConfig.logBlowupFactor;
        bounds = new CirclePolyDegreeBound.Bound[](processedLogSizes.length);
        
        for (uint256 i = 0; i < processedLogSizes.length; i++) {
            uint32 adjustedLogSize = processedLogSizes[i] - logBlowupFactor;
            bounds[i] = CirclePolyDegreeBound.create(adjustedLogSize);
        }
    }

    /// @notice Get flattened column log sizes for debugging
    /// @param state Verifier state
    /// @return flattened Flattened array of all column log sizes
    function getFlattenedColumnLogSizes(VerifierState storage state) 
        internal 
        view 
        returns (uint32[] memory flattened) 
    {
        return _flattenColumnLogSizes(state);
    }

    /// @notice Get processed column log sizes (sorted, reversed, deduplicated)
    /// @param state Verifier state  
    /// @return processed Processed array ready for bounds calculation
    function getProcessedColumnLogSizes(VerifierState storage state)
        internal
        view
        returns (uint32[] memory processed)
    {
        uint32[] memory flattened = _flattenColumnLogSizes(state);
        return _sortReverseDedup(flattened);
    }

    /// @notice Calculate bounds with explicit log blowup factor (for testing)
    /// @param state Verifier state
    /// @param logBlowupFactor Override log blowup factor
    /// @return bounds Array of CirclePolyDegreeBound
    function calculateBoundsWithBlowup(
        VerifierState storage state, 
        uint32 logBlowupFactor
    ) 
        internal 
        view 
        returns (CirclePolyDegreeBound.Bound[] memory bounds) 
    {
        uint32[] memory flattened = _flattenColumnLogSizes(state);
        uint32[] memory processedLogSizes = _sortReverseDedup(flattened);
        bounds = new CirclePolyDegreeBound.Bound[](processedLogSizes.length);
        
        for (uint256 i = 0; i < processedLogSizes.length; i++) {
            uint32 adjustedLogSize = processedLogSizes[i] - logBlowupFactor;
            bounds[i] = CirclePolyDegreeBound.create(adjustedLogSize);
        }
    }
    
    /// @notice Helper: Flatten column log sizes from all trees
    function _flattenColumnLogSizes(VerifierState storage state) 
        private 
        view 
        returns (uint32[] memory flattened) 
    {
        uint256 totalColumns = 0;
        for (uint256 i = 0; i < state.merkleVerifier.trees.length; i++) {
            totalColumns += state.merkleVerifier.trees[i].columnLogSizes.length;
        }
        flattened = new uint32[](totalColumns);
        uint256 idx = 0;
        for (uint256 i = 0; i < state.merkleVerifier.trees.length; i++) {
            uint32[] memory treeColumns = state.merkleVerifier.trees[i].columnLogSizes;
            for (uint256 j = 0; j < treeColumns.length; j++) {
                flattened[idx++] = treeColumns[j];
            }
        }
    }
    
    /// @notice Helper: Sort, reverse, and deduplicate
    function _sortReverseDedup(uint32[] memory arr) 
        private 
        pure 
        returns (uint32[] memory result) 
    {
        if (arr.length == 0) return new uint32[](0);
        
        for (uint256 i = 0; i < arr.length; i++) {
            for (uint256 j = i + 1; j < arr.length; j++) {
                if (arr[i] < arr[j]) {
                    (arr[i], arr[j]) = (arr[j], arr[i]);
                }
            }
        }
        
        uint32[] memory temp = new uint32[](arr.length);
        temp[0] = arr[0];
        uint256 uniqueCount = 1;
        
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i-1]) {
                temp[uniqueCount++] = arr[i];
            }
        }
        
        result = new uint32[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; i++) {
            result[i] = temp[i];
        }
    }
}