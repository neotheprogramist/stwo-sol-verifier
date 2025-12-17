// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/QM31Field.sol";
import "../pcs/FriVerifier.sol";
import "../vcs/MerkleVerifier.sol";
import "../pcs/PcsConfig.sol";

/// @title ProofParser
/// @notice Helper library to parse proof.json data into Solidity structs
/// @dev Provides functions to convert JSON arrays into proper Solidity structures
library ProofParser {
    using QM31Field for QM31Field.QM31;

    struct Proof {
        PcsConfig.Config config;
        bytes32[] commitments;
        QM31Field.QM31[][][] sampledValues;
        MerkleVerifier.Decommitment[] decommitments;
        uint32[][] queriedValues;
        uint64 proofOfWork;
        FriVerifier.FriProof friProof;
        CompositionPoly compositionPoly;
    }

    struct CompositionPoly {
        uint32[] coeffs0;
        uint32[] coeffs1;
        uint32[] coeffs2;
        uint32[] coeffs3;
    }

    /// @notice Parse commitments from uint8[][] to bytes32[]
    /// @param commitmentsData Array of 3 commitments, each 32 bytes
    /// @return commitments Array of bytes32 commitments
    function parseCommitments(uint8[32][] memory commitmentsData) 
        internal 
        pure 
        returns (bytes32[] memory commitments) 
    {
        commitments = new bytes32[](commitmentsData.length);
        for (uint256 i = 0; i < commitmentsData.length; i++) {
            commitments[i] = _uint8ArrayToBytes32(commitmentsData[i]);
        }
    }

    /// @notice Parse sampled values from nested uint32 arrays to QM31 structure
    /// @dev Structure: [tree][column][point][qm31_component]
    /// @param sampledData Raw sampled values data
    /// @return sampledValues Parsed QM31 values
    function parseSampledValues(uint32[][][][] memory sampledData) 
        internal 
        pure 
        returns (QM31Field.QM31[][][] memory sampledValues) 
    {
        sampledValues = new QM31Field.QM31[][][](sampledData.length);
        
        for (uint256 treeIdx = 0; treeIdx < sampledData.length; treeIdx++) {
            sampledValues[treeIdx] = new QM31Field.QM31[][](sampledData[treeIdx].length);
            
            for (uint256 colIdx = 0; colIdx < sampledData[treeIdx].length; colIdx++) {
                sampledValues[treeIdx][colIdx] = new QM31Field.QM31[](
                    sampledData[treeIdx][colIdx].length
                );
                
                for (uint256 pointIdx = 0; pointIdx < sampledData[treeIdx][colIdx].length; pointIdx++) {
                    // Each QM31 has 4 components: [first.real, first.imag, second.real, second.imag]
                    require(
                        sampledData[treeIdx][colIdx][pointIdx].length == 4,
                        "Invalid QM31 component count"
                    );
                    
                    sampledValues[treeIdx][colIdx][pointIdx] = QM31Field.QM31({
                        first: CM31Field.CM31({
                            real: sampledData[treeIdx][colIdx][pointIdx][0],
                            imag: sampledData[treeIdx][colIdx][pointIdx][1]
                        }),
                        second: CM31Field.CM31({
                            real: sampledData[treeIdx][colIdx][pointIdx][2],
                            imag: sampledData[treeIdx][colIdx][pointIdx][3]
                        })
                    });
                }
            }
        }
    }

    // Internal Helper Functions

    /// @notice Extract composition trace OODS evaluation from sampled values
    /// The last tree in sampledValues is the composition tree (4 columns for SECURE_EXTENSION_DEGREE)
    /// Each column has one evaluation at the OODS point
    /// @param proof The complete proof structure
    /// @return oodsEval The composition OODS evaluation as SecureField (QM31)
    /// @return success True if extraction was successful
    function extractCompositionOodsEval(Proof memory proof) 
        internal 
        pure 
        returns (QM31Field.QM31 memory oodsEval, bool success) 
    {
        // Rust: let [.., composition_mask] = &**self.sampled_values
        if (proof.sampledValues.length == 0) {
            return (QM31Field.zero(), false);
        }
        
        uint256 compositionTreeIdx = proof.sampledValues.length - 1;
        QM31Field.QM31[][] memory compositionMask = proof.sampledValues[compositionTreeIdx];
        
        // Rust: composition_mask.iter().map(|columns| { let &[eval] = &columns[..]; Some(eval) })
        // Each column should have exactly 1 evaluation (at OODS point)
        // SECURE_EXTENSION_DEGREE = 4 columns
        uint256 SECURE_EXTENSION_DEGREE = 4;
        
        if (compositionMask.length != SECURE_EXTENSION_DEGREE) {
            return (QM31Field.zero(), false);
        }
        
        QM31Field.QM31[4] memory coordinateEvals;
        
        for (uint256 i = 0; i < SECURE_EXTENSION_DEGREE; i++) {
            // Each column should have exactly 1 point (OODS point)
            if (compositionMask[i].length != 1) {
                return (QM31Field.zero(), false);
            }
            coordinateEvals[i] = compositionMask[i][0];
        }
        
        // Rust: SecureField::from_partial_evals(coordinate_evals)
        // In QM31, this is just the direct value (already a QM31 from 4 M31 coordinates)
        // The 4 QM31 values represent the 4 coordinates of the SecureField
        // We need to combine them into a single QM31
        oodsEval = QM31Field.fromPartialEvals(coordinateEvals);
        
        return (oodsEval, true);
    }

    /// @notice Flatten sampled values from 3D to 1D array
    /// Flattens tree -> column -> point structure into single array
    /// @param sampledValues 3D array [tree][column][point]
    /// @return flattened 1D array of all QM31 values
    function flattenCols(QM31Field.QM31[][][] memory sampledValues) 
        internal 
        pure 
        returns (QM31Field.QM31[] memory flattened) 
    {
        // First, count total number of elements
        uint256 totalCount = 0;
        for (uint256 treeIdx = 0; treeIdx < sampledValues.length; treeIdx++) {
            for (uint256 colIdx = 0; colIdx < sampledValues[treeIdx].length; colIdx++) {
                totalCount += sampledValues[treeIdx][colIdx].length;
            }
        }
        
        // Allocate result array
        flattened = new QM31Field.QM31[](totalCount);
        
        // Flatten: iterate through tree -> column -> point
        uint256 flatIdx = 0;
        for (uint256 treeIdx = 0; treeIdx < sampledValues.length; treeIdx++) {
            for (uint256 colIdx = 0; colIdx < sampledValues[treeIdx].length; colIdx++) {
                for (uint256 pointIdx = 0; pointIdx < sampledValues[treeIdx][colIdx].length; pointIdx++) {
                    flattened[flatIdx] = sampledValues[treeIdx][colIdx][pointIdx];
                    flatIdx++;
                }
            }
        }
        
        return flattened;
    }

    /// @notice Convert uint8[32] to bytes32
    function _uint8ArrayToBytes32(uint8[32] memory arr) 
        internal 
        pure 
        returns (bytes32 result) 
    {
        assembly {
            result := mload(add(arr, 32))
        }
    }

    /// @notice Convert bytes32 to uint8[32]
    function _bytes32ToUint8Array(bytes32 value) 
        internal 
        pure 
        returns (uint8[32] memory arr) 
    {
        for (uint256 i = 0; i < 32; i++) {
            arr[i] = uint8(uint256(value >> (8 * (31 - i))) & 0xFF);
        }
    }
}
