// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "../fields/M31Field.sol";
import "../fields/QM31Field.sol";

/**
 * @title KeccakChannelLib
 * @notice Library for STWO verifier channel using native EVM keccak256
 */
library KeccakChannelLib {
    using M31Field for uint32;
    using QM31Field for uint256[4];
    
    /// @notice Channel state structure
    /// @param digest Current channel digest
    /// @param nDraws Number of draws performed
    struct ChannelState {
        bytes32 digest;
        uint32 nDraws;
    }
    
    uint32 private constant POW_PREFIX = 0x12345678;
    uint256 private constant KECCAK_BYTES_PER_HASH = 32;
    uint256 private constant FELTS_PER_HASH = 8;
    uint256 private constant SECURE_EXTENSION_DEGREE = 4;
    
    /// @notice Initialize channel state with zero digest
    /// @param state Channel state to initialize
    function initialize(ChannelState storage state) internal {
        state.digest = bytes32(0);
        state.nDraws = 0;
    }
    
    /// @notice Initialize channel state with specific digest and draw counter
    function initializeWith(ChannelState storage state, bytes32 digest, uint32 nDraws) internal {
        state.digest = digest;
        state.nDraws = nDraws;
    }
    
    /// @notice Clear channel state after verification
    function clearState(ChannelState storage state) internal {
        state.digest = bytes32(0);
        state.nDraws = 0;
    }
    
    /// @notice Update digest and reset draw counter
    function updateDigest(ChannelState storage state, bytes32 newDigest) internal {
        state.digest = newDigest;
        state.nDraws = 0;
    }
    
    /// @notice Number of bytes produced by keccak256
    function BYTES_PER_HASH() internal pure returns (uint256) {
        return KECCAK_BYTES_PER_HASH;
    }
    
    /// @notice Mix array of u32 values using keccak256
    function mixU32s(ChannelState storage state, uint32[] memory data) internal {
        bytes memory input = abi.encodePacked(state.digest);
        
        for (uint256 i = 0; i < data.length; i++) {
            input = abi.encodePacked(input, _u32ToLittleEndian(data[i]));
        }
        
        state.digest = keccak256(input);
        state.nDraws = 0;
    }
    
    /// @notice Mix array of QM31 field elements into channel
    function mixFelts(ChannelState storage state, QM31Field.QM31[] memory felts) internal {
        bytes memory feltsBytes = new bytes(felts.length * 16);
        uint256 byteIndex = 0;
        
        for (uint256 i = 0; i < felts.length; i++) {
            uint32[4] memory m31Array = QM31Field.toM31Array(felts[i]);
            for (uint256 j = 0; j < 4; j++) {
                bytes4 m31Bytes = _u32ToLittleEndian(m31Array[j]);
                for (uint256 k = 0; k < 4; k++) {
                    feltsBytes[byteIndex] = m31Bytes[k];
                    byteIndex++;
                }
            }
        }
        
 
        bytes memory input = abi.encodePacked(state.digest, feltsBytes);
        
        state.digest = keccak256(input);
        state.nDraws = 0;
    }
    
    /// @notice Mix u64 value by splitting into two u32s
    function mixU64(ChannelState storage state, uint64 value) internal {
        uint32[] memory u32s = new uint32[](2);
        u32s[0] = uint32(value);
        u32s[1] = uint32(value >> 32);
        mixU32s(state, u32s);
    }
    
    /// @notice Draw random secure field element
    function drawSecureFelt(ChannelState storage state) internal returns (QM31Field.QM31 memory) {
        uint32[FELTS_PER_HASH] memory basefelts = _drawBaseFelts(state);
        
        uint32[4] memory secureArray;
        for (uint256 i = 0; i < SECURE_EXTENSION_DEGREE; i++) {
            secureArray[i] = basefelts[i];
        }
        
        return QM31Field.fromM31Array(secureArray);
    }
    
    /// @notice Draw multiple random secure field elements
    function drawSecureFelts(ChannelState storage state, uint256 nFelts) internal returns (QM31Field.QM31[] memory) {
        QM31Field.QM31[] memory result = new QM31Field.QM31[](nFelts);
        
        uint32[FELTS_PER_HASH] memory currentBatch;
        uint256 batchIndex = FELTS_PER_HASH;
        
        for (uint256 i = 0; i < nFelts; i++) {
            if (batchIndex + SECURE_EXTENSION_DEGREE > FELTS_PER_HASH) {
                currentBatch = _drawBaseFelts(state);
                batchIndex = 0;
            }
            
            uint32[4] memory secureArray;
            for (uint256 j = 0; j < SECURE_EXTENSION_DEGREE; j++) {
                secureArray[j] = currentBatch[batchIndex + j];
            }
            
            result[i] = QM31Field.fromM31Array(secureArray);
            batchIndex += SECURE_EXTENSION_DEGREE;
        }
        
        return result;
    }
    
    /// @notice Draw random u32 values from current state
    function drawU32s(ChannelState storage state) internal returns (uint32[] memory) {
        bytes memory input = abi.encodePacked(
            state.digest,
            _u32ToLittleEndian(state.nDraws),
            uint8(0)
        );
        
        state.nDraws++;
        bytes32 hash = keccak256(input);
        
        uint32[] memory result = new uint32[](FELTS_PER_HASH);
        for (uint256 i = 0; i < FELTS_PER_HASH; i++) {
            uint256 offset = i * 4;
            result[i] = uint32(uint8(hash[offset])) |
                       (uint32(uint8(hash[offset + 1])) << 8) |
                       (uint32(uint8(hash[offset + 2])) << 16) |
                       (uint32(uint8(hash[offset + 3])) << 24);
        }
        
        return result;
    }
    
    /// @notice Verify proof-of-work nonce
    function verifyPowNonce(ChannelState storage state, uint32 nBits, uint64 nonce) internal view returns (bool) {
        bytes memory prefixInput = abi.encodePacked(
            _u32ToLittleEndian(POW_PREFIX),
            new bytes(24),
            state.digest,
            _u32ToLittleEndian(nBits)
        );
        bytes32 prefixedDigest = keccak256(prefixInput);
        
        bytes memory finalInput = abi.encodePacked(
            prefixedDigest,
            _u64ToLittleEndian(nonce)
        );
        bytes32 finalHash = keccak256(finalInput);
        
        uint256 trailingZeros = _countTrailingZeros(finalHash);
        
        return trailingZeros >= nBits;
    }
    
    /// @notice Hash two elements sequentially
    function mixRoot(ChannelState storage state, bytes32 left, bytes32 right) internal returns (bytes32) {
        bytes32 newDigest = keccak256(abi.encodePacked(left, right));
        state.nDraws = 0;
        state.digest = newDigest;
        return newDigest;
    }
    
    /// @notice Generate uniform random M31 field elements
    function _drawBaseFelts(ChannelState storage state) private returns (uint32[FELTS_PER_HASH] memory) {
        uint32 maxRetries = 100;
        uint32 retries = 0;
        
        while (retries < maxRetries) {
            uint32[] memory u32s = drawU32s(state);
            
            bool allValid = true;
            for (uint256 i = 0; i < FELTS_PER_HASH; i++) {
                if (u32s[i] >= 2 * M31Field.MODULUS) {
                    allValid = false;
                    break;
                }
            }
            
            if (allValid) {
                uint32[FELTS_PER_HASH] memory result;
                for (uint256 i = 0; i < FELTS_PER_HASH; i++) {
                    result[i] = M31Field.reduce(uint64(u32s[i]));
                }
                return result;
            }
            
            retries++;
        }
        
        revert("KeccakChannelLib: Failed to generate valid base felts");
    }

    /// @notice Convert u32 to little-endian bytes
    function _u32ToLittleEndian(uint32 value) private pure returns (bytes4) {
        return bytes4(abi.encodePacked(
            uint8(value),
            uint8(value >> 8),
            uint8(value >> 16),
            uint8(value >> 24)
        ));
    }
    
    /// @notice Convert u64 to little-endian bytes
    function _u64ToLittleEndian(uint64 value) private pure returns (bytes8) {
        return bytes8(
            _u32ToLittleEndian(uint32(value)) |
            (bytes8(_u32ToLittleEndian(uint32(value >> 32))) << 32)
        );
    }
    
    /// @notice Count trailing zeros in hash
    function _countTrailingZeros(bytes32 hash) private pure returns (uint256) {
        uint256 zeros = 0;
        
        uint256 value = 0;
        for (uint256 i = 0; i < 32; i++) {
            value |= uint256(uint8(hash[i])) << (i * 8);
        }
        
        if (value == 0) {
            return 256;
        }
        
        while ((value & 1) == 0) {
            value >>= 1;
            zeros++;
        }
        
        return zeros;
    }
}