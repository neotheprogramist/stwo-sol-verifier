// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/M31Field.sol";

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
        // Find max log size
        uint32 maxLogSize = 0;
        for (uint256 i = 0; i < tree.columnLogSizes.length; i++) {
            if (tree.columnLogSizes[i] > maxLogSize) {
                maxLogSize = tree.columnLogSizes[i];
            }
        }

        if (maxLogSize == 0) {
            return; // No columns to verify
        }

        // Initialize iterators (simulating Rust iterators)
        IteratorState memory iterators = IteratorState({
            queriedValuesIndex: 0,
            hashWitnessIndex: 0,
            columnWitnessIndex: 0,
            prevLayerIndex: 0
        });

        // Layer hashes for propagation (matches Rust last_layer_hashes)
        LayerHash[] memory lastLayerHashes;
        
        // Process each layer from max_log_size down to 0 (matches Rust loop)
        for (uint32 layerLogSize = maxLogSize; ; layerLogSize--) {
            // Get number of columns in this layer
            uint256 nColumnsInLayer = _getColumnsForLogSize(tree, layerLogSize);
            
            // Process layer and get new layer hashes
            lastLayerHashes = _processLayer(
                layerLogSize,
                nColumnsInLayer,
                queriesPerLogSize,
                lastLayerHashes,
                queriedValues,
                decommitment,
                iterators
            );
            
            if (layerLogSize == 0) break; // Prevent underflow
        }

        // Check that all witnesses and values have been consumed (matches Rust)
        if (iterators.hashWitnessIndex < decommitment.hashWitness.length) {
            revert MerkleVerificationError("Witness too long");
        }
        if (iterators.queriedValuesIndex < queriedValues.length) {
            revert MerkleVerificationError("Too many queried values");
        }
        if (iterators.columnWitnessIndex < decommitment.columnWitness.length) {
            revert MerkleVerificationError("Witness too long");
        }

        // Verify final root (matches Rust)
        if (lastLayerHashes.length != 1) {
            revert MerkleVerificationError("Expected single root hash");
        }
        
        if (lastLayerHashes[0].hash != tree.root) {
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

    /// @notice Process single layer of Merkle tree (matches Rust layer processing logic)
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

    /// @notice Hash node with column values (matches Rust hash_node with children_hashes: Some)
    /// @param leftChild Left child hash
    /// @param rightChild Right child hash  
    /// @param columnValues Column values for this node
    /// @return Hash of node
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

    /// @notice Hash leaf with column values (matches Rust hash_node with children_hashes: None)
    /// @param columnValues Column values for this leaf
    /// @return Hash of leaf
    function _hashLeaf(uint32[] memory columnValues) internal pure returns (bytes32) {
        // Match Rust: LEAF_PREFIX + column_values
        bytes memory data = new bytes(64 + columnValues.length * 4);
        
        // LEAF_PREFIX: "leaf" + 60 zero bytes
        data[0] = 0x6c; // 'l'
        data[1] = 0x65; // 'e'
        data[2] = 0x61; // 'a'
        data[3] = 0x66; // 'f'
        // bytes 4-63 are already zero
        
        // Add column values in little-endian format
        for (uint256 i = 0; i < columnValues.length; i++) {
            _writeUint32LE(data, 64 + i * 4, columnValues[i]);
        }
        
        return keccak256(data);
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