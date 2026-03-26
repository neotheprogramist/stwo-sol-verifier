// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/M31Field.sol";
import {console} from "forge-std/console.sol";

/// @title MerkleVerifier
/// @notice Verifies Merkle tree decommitments for vector commitment schemes
library MerkleVerifier {
    using M31Field for uint32;

    /// @notice Single Merkle tree verifier
    struct MerkleTree {
        bytes32 root;
        uint32[] columnLogSizes;
        uint32[] logSizes;
        uint256[] nColumnsPerLogSize;
    }

    /// @notice Commitment scheme verifier state
    struct Verifier {
        MerkleTree[] trees;
    }
    
    /// @notice Legacy single-tree verifier
    /// @dev Alias for MerkleTree - use this for single tree operations
    struct VerifierLegacy {
        bytes32 root;
        uint32[] columnLogSizes;
        uint32[] logSizes;
        uint256[] nColumnsPerLogSize;
    }

    /// @notice Merkle decommitment proof (matches Rust MerkleDecommitment)
    /// @param hashWitness Hash values that verifier needs but cannot deduce
    /// @param columnWitness Column values that verifier needs but cannot deduce
    struct Decommitment {
        bytes32[] hashWitness;
        uint32[] columnWitness;
    }

    /// @notice Query specification per log size (matches Rust queries_per_log_size)
    /// @param logSize Log size for this set of queries
    /// @param queries Query positions for columns of this log size
    struct QueriesPerLogSize {
        uint32 logSize;
        uint256[] queries;
    }

    /// @notice Error thrown when Merkle verification fails
    error MerkleVerificationError(string reason);
    
    /// @notice Error thrown when decommitment data is malformed
    error InvalidDecommitment(string reason);
    
    /// @notice Error thrown when query parameters are invalid
    error InvalidQuery(string reason);

    /// @notice Create new Merkle verifier with multiple trees (matches Rust CommitmentSchemeVerifier)
    /// @param treeRoots Array of Merkle tree roots (one per tree)
    /// @param treeColumnLogSizes Array of column log sizes arrays (one array per tree)
    /// @return verifier New multi-tree verifier instance
    function newVerifier(
        bytes32[] memory treeRoots,
        uint32[][] memory treeColumnLogSizes
    ) internal pure returns (Verifier memory verifier) {
        require(treeRoots.length == treeColumnLogSizes.length, "Mismatched trees and column sizes");
        
        verifier.trees = new MerkleTree[](treeRoots.length);
        
        for (uint256 treeIdx = 0; treeIdx < treeRoots.length; treeIdx++) {
            verifier.trees[treeIdx] = createMerkleTree(treeRoots[treeIdx], treeColumnLogSizes[treeIdx]);
        }
    }

    /// @notice Create single Merkle tree verifier (matches Rust MerkleVerifier::new)
    /// @dev Public function to allow creating individual trees for CommitmentSchemeVerifier
    /// @param root Merkle tree root
    /// @param columnLogSizes Log sizes for columns
    /// @return tree New Merkle tree instance
    function createMerkleTree(
        bytes32 root,
        uint32[] memory columnLogSizes
    ) internal pure returns (MerkleTree memory tree) {
        tree.root = root;
        tree.columnLogSizes = columnLogSizes;
        
        // Build n_columns_per_log_size arrays (matches Rust BTreeMap logic)
        // First pass: find unique log sizes
        uint32[] memory tempLogSizes = new uint32[](columnLogSizes.length);
        uint256[] memory tempCounts = new uint256[](columnLogSizes.length);
        uint256 uniqueCount = 0;
        
        for (uint256 i = 0; i < columnLogSizes.length; i++) {
            uint32 logSize = columnLogSizes[i];
            bool found = false;
            
            // Check if we've seen this log size before
            for (uint256 j = 0; j < uniqueCount; j++) {
                if (tempLogSizes[j] == logSize) {
                    tempCounts[j]++;
                    found = true;
                    break;
                }
            }
            
            // If not found, add new entry
            if (!found) {
                tempLogSizes[uniqueCount] = logSize;
                tempCounts[uniqueCount] = 1;
                uniqueCount++;
            }
        }
        
        // Copy to correctly sized arrays
        tree.logSizes = new uint32[](uniqueCount);
        tree.nColumnsPerLogSize = new uint256[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; i++) {
            tree.logSizes[i] = tempLogSizes[i];
            tree.nColumnsPerLogSize[i] = tempCounts[i];
        }
    }

    /// @notice Create single-tree verifier (legacy interface, backward compatible)
    /// @param root Merkle tree root
    /// @param columnLogSizes Log sizes for columns
    /// @return verifier New single-tree verifier instance
    function newVerifierSingleTree(
        bytes32 root,
        uint32[] memory columnLogSizes
    ) internal pure returns (Verifier memory verifier) {
        bytes32[] memory roots = new bytes32[](1);
        roots[0] = root;
        
        uint32[][] memory columnSizes = new uint32[][](1);
        columnSizes[0] = columnLogSizes;
        
        return newVerifier(roots, columnSizes);
    }

    /// @notice Verify Merkle decommitment for specific tree (matches Rust MerkleVerifier::verify)
    /// @param tree Single Merkle tree to verify against
    /// @param queriesPerLogSize Queries organized by log size
    /// @param queriedValues Queried values in order
    /// @param decommitment Decommitment proof
    function verify(
        MerkleTree memory tree,
        QueriesPerLogSize[] memory queriesPerLogSize,
        uint32[] memory queriedValues,
        Decommitment memory decommitment
    ) internal pure {
        uint256 nColumns = tree.columnLogSizes.length;
        if (nColumns == 0) {
            return;
        }

        uint32 maxLogSize = 0;
        for (uint256 i = 0; i < nColumns; i++) {
            if (tree.columnLogSizes[i] > maxLogSize) {
                maxLogSize = tree.columnLogSizes[i];
            }
        }

        uint256[] memory queryPositions = _findQueriesForLogSize(queriesPerLogSize, maxLogSize);
        if (queryPositions.length == 0) {
            revert InvalidQuery("Missing queries for max log size");
        }

        if (queriedValues.length % nColumns != 0) {
            revert InvalidQuery("Queried values length mismatch");
        }
        uint256 nQueries = queriedValues.length / nColumns;
        if (nQueries != queryPositions.length) {
            revert InvalidQuery("Query count mismatch");
        }

        // Check duplicate query positions consistency, same as Rust verifier.
        for (uint256 i = 0; i + 1 < nQueries; i++) {
            if (queryPositions[i] == queryPositions[i + 1]) {
                for (uint256 c = 0; c < nColumns; c++) {
                    uint256 base = c * nQueries;
                    if (queriedValues[base + i] != queriedValues[base + i + 1]) {
                        revert InvalidQuery("Duplicate query values mismatch");
                    }
                }
            }
        }

        uint256 uniqueQueryCount = _countUniqueConsecutive(queryPositions);
        uint256[] memory sortedColumnIndices = _sortedColumnIndicesByLogSize(tree.columnLogSizes);

        // Build deduplicated per-column values in sorted column order.
        uint32[][] memory sortedDedupValues = new uint32[][](nColumns);
        for (uint256 sortedCol = 0; sortedCol < nColumns; sortedCol++) {
            uint256 colIdx = sortedColumnIndices[sortedCol];
            uint32[] memory dedupVals = new uint32[](uniqueQueryCount);
            uint256 writeIdx = 0;
            uint256 base = colIdx * nQueries;
            for (uint256 q = 0; q < nQueries; q++) {
                if (q == 0 || queryPositions[q] != queryPositions[q - 1]) {
                    dedupVals[writeIdx++] = queriedValues[base + q];
                }
            }
            sortedDedupValues[sortedCol] = dedupVals;
        }

        // Build leaves for unique query positions.
        LayerHash[] memory prevLayerHashes = new LayerHash[](uniqueQueryCount);
        uint256 leafIdx = 0;
        for (uint256 q = 0; q < nQueries; q++) {
            if (q == 0 || queryPositions[q] != queryPositions[q - 1]) {
                uint32[] memory row = new uint32[](nColumns);
                for (uint256 c = 0; c < nColumns; c++) {
                    row[c] = sortedDedupValues[c][leafIdx];
                }
                prevLayerHashes[leafIdx] = LayerHash({
                    nodeIndex: queryPositions[q],
                    hash: _hashLeaf(row)
                });
                leafIdx++;
            }
        }

        // Verify inner layers using hash witness only (lifted verifier semantics).
        uint256 hashWitnessIndex = 0;
        for (uint32 layer = 0; layer < maxLogSize; layer++) {
            LayerHash[] memory currLayerHashes = new LayerHash[](prevLayerHashes.length);
            uint256 currCount = 0;

            uint256 i = 0;
            while (i < prevLayerHashes.length) {
                uint256 idx0 = prevLayerHashes[i].nodeIndex;
                bytes32 hash0 = prevLayerHashes[i].hash;

                bytes32 left;
                bytes32 right;

                bool hasSibling = (i + 1 < prevLayerHashes.length) &&
                    (prevLayerHashes[i + 1].nodeIndex == (idx0 ^ 1));

                if (hasSibling) {
                    bytes32 hash1 = prevLayerHashes[i + 1].hash;
                    if ((idx0 & 1) == 0) {
                        left = hash0;
                        right = hash1;
                    } else {
                        left = hash1;
                        right = hash0;
                    }
                    i += 2;
                } else {
                    if (hashWitnessIndex >= decommitment.hashWitness.length) {
                        revert MerkleVerificationError("Witness too short");
                    }
                    bytes32 witness = decommitment.hashWitness[hashWitnessIndex++];
                    if ((idx0 & 1) == 0) {
                        left = hash0;
                        right = witness;
                    } else {
                        left = witness;
                        right = hash0;
                    }
                    i += 1;
                }

                currLayerHashes[currCount++] = LayerHash({
                    nodeIndex: idx0 >> 1,
                    hash: _hashChildren(left, right)
                });
            }

            LayerHash[] memory resized = new LayerHash[](currCount);
            for (uint256 k = 0; k < currCount; k++) {
                resized[k] = currLayerHashes[k];
            }
            prevLayerHashes = resized;
        }

        if (hashWitnessIndex < decommitment.hashWitness.length) {
            revert MerkleVerificationError("Witness too long");
        }

        if (prevLayerHashes.length != 1) {
            revert MerkleVerificationError("Expected single root hash");
        }

        if (prevLayerHashes[0].hash != tree.root) {
            revert MerkleVerificationError("Root mismatch");
        }
    }
    
    /// @notice Verify Merkle decommitment for multi-tree verifier
    /// @param verifier Multi-tree verifier state
    /// @param treeIndex Index of tree to verify
    /// @param queriesPerLogSize Queries organized by log size
    /// @param queriedValues Queried values in order
    /// @param decommitment Decommitment proof
    function verifyTree(
        Verifier memory verifier,
        uint256 treeIndex,
        QueriesPerLogSize[] memory queriesPerLogSize,
        uint32[] memory queriedValues,
        Decommitment memory decommitment
    ) internal pure {
        require(treeIndex < verifier.trees.length, "Tree index out of bounds");
        verify(verifier.trees[treeIndex], queriesPerLogSize, queriedValues, decommitment);
    }

    /// @notice Layer hash structure for propagation between layers
    struct LayerHash {
        uint256 nodeIndex;
        bytes32 hash;
    }

    /// @notice Iterator state for processing (matches Rust mutable iterators)
    struct IteratorState {
        uint256 queriedValuesIndex;
        uint256 hashWitnessIndex;
        uint256 columnWitnessIndex;
        uint256 prevLayerIndex; // For iterating through previousLayerHashes
    }

    /// @notice Process single layer of Merkle tree (legacy path, not used by lifted verifier)
    function _processLayer(
        uint32 layerLogSize,
        uint256 nColumnsInLayer,
        QueriesPerLogSize[] memory queriesPerLogSize,
        LayerHash[] memory previousLayerHashes,
        uint32[] memory queriedValues,
        Decommitment memory decommitment,
        IteratorState memory iterators
    ) internal pure returns (LayerHash[] memory layerHashes) {
        // Find queries for this log size
        uint256[] memory layerQueries;
        for (uint256 i = 0; i < queriesPerLogSize.length; i++) {
            if (queriesPerLogSize[i].logSize == layerLogSize) {
                layerQueries = queriesPerLogSize[i].queries;
                break;
            }
        }
        if (layerQueries.length == 0) {
            layerQueries = new uint256[](0);
        }

        // Reset prevLayerIndex for this layer
        iterators.prevLayerIndex = 0;
        
        // Temporary storage for this layer's hashes
        LayerHash[] memory tempLayerHashes = new LayerHash[](layerQueries.length + previousLayerHashes.length);
        uint256 layerHashCount = 0;

        // Process all nodes in this layer (matches Rust while loop)
        (tempLayerHashes, layerHashCount) = _processLayerNodes(
            layerQueries,
            previousLayerHashes,
            nColumnsInLayer,
            queriedValues,
            decommitment,
            iterators,
            tempLayerHashes,
            layerHashCount
        );

        // Copy to correctly sized array
        layerHashes = new LayerHash[](layerHashCount);
        for (uint256 i = 0; i < layerHashCount; i++) {
            layerHashes[i] = tempLayerHashes[i];
        }
    }

    /// @notice Hash children (lifted verifier semantics): keccak(left || right)
    /// @param leftChild Left child hash
    /// @param rightChild Right child hash
    /// @return Hash of parent
    function _hashChildren(
        bytes32 leftChild,
        bytes32 rightChild
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(leftChild, rightChild));
    }

    /// @notice Hash node with column values (legacy path)
    function _hashNode(
        bytes32 leftChild,
        bytes32 rightChild, 
        uint32[] memory columnValues
    ) internal pure returns (bytes32) {
        // Match Rust: NODE_PREFIX + left_child + right_child + column_values
        bytes memory data = new bytes(64 + 64 + columnValues.length * 4);
        
        // NODE_PREFIX: "node" + 60 zero bytes
        data[0] = 0x6e; // 'n'
        data[1] = 0x6f; // 'o'
        data[2] = 0x64; // 'd'
        data[3] = 0x65; // 'e'
        // bytes 4-63 are already zero
        
        // Add left and right child hashes
        for (uint256 i = 0; i < 32; i++) {
            data[64 + i] = leftChild[i];
            data[96 + i] = rightChild[i];
        }
        
        // Add column values in little-endian format
        for (uint256 i = 0; i < columnValues.length; i++) {
            _writeUint32LE(data, 128 + i * 4, columnValues[i]);
        }
        
        return keccak256(data);
    }

    /// @notice Hash leaf with column values (lifted verifier semantics): keccak(little_endian_values)
    /// @param columnValues Column values for this leaf
    /// @return Hash of leaf
    function _hashLeaf(uint32[] memory columnValues) internal pure returns (bytes32) {
        bytes memory data = new bytes(columnValues.length * 4);
        
        // Add column values in little-endian format
        for (uint256 i = 0; i < columnValues.length; i++) {
            _writeUint32LE(data, i * 4, columnValues[i]);
        }
        
        return keccak256(data);
    }

    function _findQueriesForLogSize(
        QueriesPerLogSize[] memory queriesPerLogSize,
        uint32 logSize
    ) internal pure returns (uint256[] memory) {
        for (uint256 i = 0; i < queriesPerLogSize.length; i++) {
            if (queriesPerLogSize[i].logSize == logSize) {
                return queriesPerLogSize[i].queries;
            }
        }
        return new uint256[](0);
    }

    function _countUniqueConsecutive(uint256[] memory values) internal pure returns (uint256 count) {
        if (values.length == 0) {
            return 0;
        }
        count = 1;
        for (uint256 i = 1; i < values.length; i++) {
            if (values[i] != values[i - 1]) {
                count++;
            }
        }
    }

    function _sortedColumnIndicesByLogSize(
        uint32[] memory columnLogSizes
    ) internal pure returns (uint256[] memory indices) {
        indices = new uint256[](columnLogSizes.length);
        for (uint256 i = 0; i < columnLogSizes.length; i++) {
            indices[i] = i;
        }

        // Stable insertion sort by log size.
        for (uint256 i = 1; i < indices.length; i++) {
            uint256 key = indices[i];
            uint32 keyLog = columnLogSizes[key];
            uint256 j = i;
            while (j > 0 && columnLogSizes[indices[j - 1]] > keyLog) {
                indices[j] = indices[j - 1];
                j--;
            }
            indices[j] = key;
        }
    }

    /// @notice Write uint32 value as little-endian bytes
    /// @param data Target byte array
    /// @param offset Starting position in array
    /// @param value Value to write
    function _writeUint32LE(bytes memory data, uint256 offset, uint32 value) internal pure {
        data[offset] = bytes1(uint8(value));
        data[offset + 1] = bytes1(uint8(value >> 8));
        data[offset + 2] = bytes1(uint8(value >> 16));
        data[offset + 3] = bytes1(uint8(value >> 24));
    }

    /// @notice Get number of columns for a given log size
    /// @param tree Merkle tree state
    /// @param logSize Log size to search for
    /// @return Number of columns for this log size
    function _getColumnsForLogSize(
        MerkleTree memory tree,
        uint32 logSize
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < tree.logSizes.length; i++) {
            if (tree.logSizes[i] == logSize) {
                return tree.nColumnsPerLogSize[i];
            }
        }
        return 0; // No columns for this log size
    }

    /// @notice Process layer nodes to reduce stack depth
    function _processLayerNodes(
        uint256[] memory layerQueries,
        LayerHash[] memory previousLayerHashes,
        uint256 nColumnsInLayer,
        uint32[] memory queriedValues,
        Decommitment memory decommitment,
        IteratorState memory iterators,
        LayerHash[] memory tempLayerHashes,
        uint256 layerHashCount
    ) internal pure returns (LayerHash[] memory, uint256) {
        uint256 layerQueryIndex = 0;
        
        while (iterators.prevLayerIndex < previousLayerHashes.length || layerQueryIndex < layerQueries.length) {
            // Determine next node and whether it's from current layer queries
            bool isFromLayerQuery;
            uint256 nodeIndex;
            (nodeIndex, isFromLayerQuery) = _getNextNodeIndexAndSource(
                layerQueries,
                previousLayerHashes,
                iterators.prevLayerIndex,
                layerQueryIndex
            );

            // Note: In Rust, prev_layer_queries (indices only) are skipped here,
            // but prev_layer_hashes (with hashes) are separate and used in _getNodeHashes.
            // In Solidity, we have previousLayerHashes which contains both indices and hashes,
            // so we DON'T skip them here - they're consumed in _getNodeHashes instead.

            // Get node hashes and values
            (bytes32 nodeHash, uint256 newLayerQueryIndex) = _processNode(
                nodeIndex,
                isFromLayerQuery,
                layerQueryIndex,
                previousLayerHashes,
                nColumnsInLayer,
                queriedValues,
                decommitment,
                iterators
            );
            
            layerQueryIndex = newLayerQueryIndex;

            // Store result
            tempLayerHashes[layerHashCount] = LayerHash({
                nodeIndex: nodeIndex,
                hash: nodeHash
            });
            layerHashCount++;
        }
        
        return (tempLayerHashes, layerHashCount);
    }

    /// @notice Get next node index to process and its source
    /// @return nodeIndex The next node index to process
    /// @return isFromLayerQuery True if node comes from current layer queries, false if from previous layer parents
    function _getNextNodeIndexAndSource(
        uint256[] memory layerQueries,
        LayerHash[] memory previousLayerHashes,
        uint256 prevLayerIndex,
        uint256 layerQueryIndex
    ) internal pure returns (uint256, bool) {
        if (prevLayerIndex >= previousLayerHashes.length) {
            // Only layer queries remain
            return (layerQueries[layerQueryIndex], true);
        } else if (layerQueryIndex >= layerQueries.length) {
            // Only previous layer parents remain
            return (previousLayerHashes[prevLayerIndex].nodeIndex / 2, false);
        } else {
            // Both sources available - take minimum
            uint256 prevNodeIndex = previousLayerHashes[prevLayerIndex].nodeIndex / 2;
            uint256 queryNodeIndex = layerQueries[layerQueryIndex];
            if (prevNodeIndex < queryNodeIndex) {
                return (prevNodeIndex, false);
            } else if (queryNodeIndex < prevNodeIndex) {
                return (queryNodeIndex, true);
            } else {
                // Same node index from both sources - it's a queried node
                return (queryNodeIndex, true);
            }
        }
    }

    /// @notice Process single node and return hash
    function _processNode(
        uint256 nodeIndex,
        bool isFromLayerQuery,
        uint256 layerQueryIndex,
        LayerHash[] memory previousLayerHashes,
        uint256 nColumnsInLayer,
        uint32[] memory queriedValues,
        Decommitment memory decommitment,
        IteratorState memory iterators
    ) internal pure returns (bytes32, uint256) {
        // Get node hashes
        bool hasChildren = previousLayerHashes.length > 0;
        (bytes32 leftHash, bytes32 rightHash) = _getNodeHashes(
            nodeIndex,
            previousLayerHashes,
            decommitment,
            iterators,
            hasChildren
        );

        // Node is queried only if it comes from current layer queries
        bool isQueriedNode = isFromLayerQuery;
        
        uint32[] memory nodeValues = _getNodeValues(
            isQueriedNode,
            nColumnsInLayer,
            queriedValues,
            decommitment,
            iterators
        );

        uint256 newLayerQueryIndex = layerQueryIndex;
        if (isQueriedNode) {
            newLayerQueryIndex++;
        }

        // Compute hash
        bytes32 nodeHash;
        if (hasChildren) {
            // Internal node: NODE_PREFIX + left + right + column_values
            nodeHash = _hashNode(leftHash, rightHash, nodeValues);
        } else {
            // Leaf node: LEAF_PREFIX + column_values
            nodeHash = _hashLeaf(nodeValues);
        }

        return (nodeHash, newLayerQueryIndex);
    }

    /// @notice Get node hashes from previous layer or witness (matches Rust next_if logic)
    function _getNodeHashes(
        uint256 nodeIndex,
        LayerHash[] memory previousLayerHashes,
        Decommitment memory decommitment,
        IteratorState memory iterators,
        bool hasChildren
    ) internal pure returns (bytes32, bytes32) {
        if (!hasChildren) {
            return (bytes32(0), bytes32(0));
        }

        bytes32 leftHash;
        bytes32 rightHash;
        
        // Try to get left child from previous layer (matches Rust next_if)
        if (iterators.prevLayerIndex < previousLayerHashes.length && 
            previousLayerHashes[iterators.prevLayerIndex].nodeIndex == 2 * nodeIndex) {
            leftHash = previousLayerHashes[iterators.prevLayerIndex].hash;
            iterators.prevLayerIndex++;
        } else {
            // Left child not in previous layer, get from witness
            if (iterators.hashWitnessIndex >= decommitment.hashWitness.length) {
                revert MerkleVerificationError("Witness too short");
            }
            leftHash = decommitment.hashWitness[iterators.hashWitnessIndex++];
        }

        // Try to get right child from previous layer (matches Rust next_if)
        if (iterators.prevLayerIndex < previousLayerHashes.length && 
            previousLayerHashes[iterators.prevLayerIndex].nodeIndex == 2 * nodeIndex + 1) {
            rightHash = previousLayerHashes[iterators.prevLayerIndex].hash;
            iterators.prevLayerIndex++;
        } else {
            // Right child not in previous layer, get from witness
            if (iterators.hashWitnessIndex >= decommitment.hashWitness.length) {
                revert MerkleVerificationError("Witness too short");
            }
            rightHash = decommitment.hashWitness[iterators.hashWitnessIndex++];
        }

        return (leftHash, rightHash);
    }

    /// @notice Get node values from queries or witness (matches Rust logic)
    function _getNodeValues(
        bool isQueriedNode,
        uint256 nColumnsInLayer,
        uint32[] memory queriedValues,
        Decommitment memory decommitment,
        IteratorState memory iterators
    ) internal pure returns (uint32[] memory) {
        uint32[] memory nodeValues = new uint32[](nColumnsInLayer);
        
        if (isQueriedNode) {
            // Read from queried_values
            for (uint256 i = 0; i < nColumnsInLayer; i++) {
                if (iterators.queriedValuesIndex >= queriedValues.length) {
                    revert MerkleVerificationError("Too few queried values");
                }
                nodeValues[i] = queriedValues[iterators.queriedValuesIndex++];
            }
        } else {
            // Read from column_witness
            for (uint256 i = 0; i < nColumnsInLayer; i++) {
                if (iterators.columnWitnessIndex >= decommitment.columnWitness.length) {
                    revert MerkleVerificationError("Witness too short");
                }
                nodeValues[i] = decommitment.columnWitness[iterators.columnWitnessIndex++];
            }
        }

        return nodeValues;
    }


    /// @notice Create verifier (alias for newVerifierSingleTree)
    /// @param root Merkle tree root
    /// @param columnLogSizes Log sizes for columns
    /// @return verifier New verifier instance
    function create(
        bytes32 root,
        uint32[] memory columnLogSizes
    ) internal pure returns (Verifier memory verifier) {
        return newVerifierSingleTree(root, columnLogSizes);
    }

    /// @notice Verify single position with M31 values array (for FriVerifier compatibility)
    /// @dev Simple Merkle path verification for a single leaf
    /// @param verifier Merkle verifier state
    /// @param position Position to verify
    /// @param expectedValues Expected M31 values array at position
    /// @param decommitment Decommitment proof
    /// @return True if verification succeeds
    function _verifyPositionWithM31Array(
        Verifier memory verifier,
        uint256 position,
        uint32[] memory expectedValues,
        Decommitment memory decommitment,
        uint256 /* queryIndex */
    ) internal pure returns (bool) {
        // For backward compatibility, use first tree
        if (verifier.trees.length == 0) return true;
        MerkleTree memory tree = verifier.trees[0];
        
        uint32 logSize = 0;
        for (uint256 i = 0; i < tree.columnLogSizes.length; i++) {
            if (tree.columnLogSizes[i] > logSize) {
                logSize = tree.columnLogSizes[i];
            }
        }
        
        if (logSize == 0) return true;
        
        // Start with leaf hash
        bytes32 currentHash = _hashLeaf(expectedValues);
        
        // Climb up the tree using witness hashes
        uint256 currentPos = position;
        uint256 witnessIndex = 0;
        
        for (uint32 level = 0; level < logSize; level++) {
            if (witnessIndex >= decommitment.hashWitness.length) {
                revert InvalidDecommitment("Insufficient hash witness");
            }
            
            bytes32 siblingHash = decommitment.hashWitness[witnessIndex++];
            
            // Create empty column values for internal nodes
            uint32[] memory emptyValues = new uint32[](0);
            
            // Determine if current node is left or right child
            if (currentPos % 2 == 0) {
                // Current is left child
                currentHash = _hashNode(currentHash, siblingHash, emptyValues);
            } else {
                // Current is right child  
                currentHash = _hashNode(siblingHash, currentHash, emptyValues);
            }
            
            currentPos = currentPos / 2;
        }
        
        // Final hash should match root (use first tree for backward compatibility)
        return currentHash == tree.root;
    }
}