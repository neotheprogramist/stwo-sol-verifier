// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title PcsConfig
/// @notice Configuration for Polynomial Commitment Scheme verification
library PcsConfig {

    /// @notice FRI (Fast Reed-Solomon Interactive Oracle Proof) configuration
    /// @param logBlowupFactor Log of FRI blowup factor (extension degree)
    /// @param logLastLayerDegreeBound Log of degree bound for last FRI layer
    /// @param nQueries Number of FRI queries for soundness
    struct FriConfig {
        uint32 logBlowupFactor;
        uint32 logLastLayerDegreeBound; 
        uint256 nQueries;
    }

    /// @notice Polynomial Commitment Scheme configuration
    /// @param powBits Number of proof-of-work bits required
    /// @param friConfig FRI verification parameters
    struct Config {
        uint32 powBits;
        FriConfig friConfig;
    }

    /// @notice Error thrown when configuration parameters are invalid
    error InvalidConfig(string reason);

    /// @notice Create default FRI configuration for testing
    /// @return Default FRI configuration
    function defaultFriConfig() internal pure returns (FriConfig memory) {
        return FriConfig({
            logBlowupFactor: 1,  // 2x blowup factor
            logLastLayerDegreeBound: 0,  // Degree bound 1 for last layer
            nQueries: 84  // Standard number of queries for ~100-bit security
        });
    }

    /// @notice Create default PCS configuration for testing
    /// @return Default PCS configuration
    function defaultConfig() internal pure returns (Config memory) {
        return Config({
            powBits: 20,  // 20-bit proof of work (~1M operations)
            friConfig: defaultFriConfig()
        });
    }

    /// @notice Create secure PCS configuration for production
    /// @return Production PCS configuration
    function secureConfig() internal pure returns (Config memory) {
        return Config({
            powBits: 26,  // 26-bit proof of work (~67M operations)
            friConfig: FriConfig({
                logBlowupFactor: 1,
                logLastLayerDegreeBound: 0,
                nQueries: 84
            })
        });
    }

    /// @notice Validate FRI configuration parameters
    /// @param config FRI configuration to validate
    /// @return True if configuration is valid
    function isValidFriConfig(FriConfig memory config) internal pure returns (bool) {
        // Blowup factor must be reasonable (1-4 typically)
        if (config.logBlowupFactor > 4) {
            return false;
        }
        
        // Last layer degree bound must be reasonable
        if (config.logLastLayerDegreeBound > 10) {
            return false;
        }
        
        // Number of queries must be sufficient for security
        // Allow lower values for testing (matching Rust behavior)
        if (config.nQueries < 1 || config.nQueries > 200) {
            return false;
        }
        
        return true;
    }

    /// @notice Validate PCS configuration parameters
    /// @param config PCS configuration to validate
    /// @return True if configuration is valid
    function isValidConfig(Config memory config) internal pure returns (bool) {
        // Proof of work bits must be reasonable (0-32)
        if (config.powBits > 32) {
            return false;
        }
        
        return isValidFriConfig(config.friConfig);
    }

    /// @notice Get extended log sizes with FRI blowup factor
    /// @param originalLogSizes Original column log sizes
    /// @param config FRI configuration
    /// @return Extended log sizes including blowup
    function getExtendedLogSizes(
        uint32[] memory originalLogSizes,
        FriConfig memory config
    ) internal pure returns (uint32[] memory) {
        uint32[] memory extended = new uint32[](originalLogSizes.length);
        
        for (uint256 i = 0; i < originalLogSizes.length; i++) {
            extended[i] = originalLogSizes[i] + config.logBlowupFactor;
        }
        
        return extended;
    }

    /// @notice Calculate degree bounds for FRI layers
    /// @param columnLogSizes Column log sizes
    /// @param config FRI configuration  
    /// @return Degree bounds for each FRI layer
    function calculateDegreeBounds(
        uint32[] memory columnLogSizes,
        FriConfig memory config
    ) internal pure returns (uint256[] memory) {
        uint256[] memory bounds = new uint256[](columnLogSizes.length);
        
        for (uint256 i = 0; i < columnLogSizes.length; i++) {
            // Degree bound = 2^(log_size + blowup_factor) - 1
            bounds[i] = (1 << (columnLogSizes[i] + config.logBlowupFactor)) - 1;
        }
        
        return bounds;
    }

    /// @notice Get FRI security level from number of queries
    /// @param nQueries Number of FRI queries
    /// @return Approximate security level in bits
    function getSecurityLevel(uint256 nQueries) internal pure returns (uint256) {
        // Each query provides roughly 1 bit of security
        // With soundness error ~2^(-n_queries)
        return nQueries;
    }

    /// @notice Calculate required queries for target security level
    /// @param securityBits Target security level in bits
    /// @return Number of queries needed
    function calculateRequiredQueries(uint256 securityBits) internal pure returns (uint256) {
        // Add small safety margin
        return securityBits + 4;
    }

    /// @notice Encode configuration for hashing/commitment
    /// @param config Configuration to encode
    /// @return Encoded configuration bytes
    function encode(Config memory config) internal pure returns (bytes memory) {
        return abi.encode(
            config.powBits,
            config.friConfig.logBlowupFactor,
            config.friConfig.logLastLayerDegreeBound,
            config.friConfig.nQueries
        );
    }

    /// @notice Decode configuration from bytes
    /// @param data Encoded configuration
    /// @return Decoded configuration
    function decode(bytes memory data) internal pure returns (Config memory) {
        (
            uint32 powBits,
            uint32 logBlowupFactor,
            uint32 logLastLayerDegreeBound,
            uint256 nQueries
        ) = abi.decode(data, (uint32, uint32, uint32, uint256));
        
        return Config({
            powBits: powBits,
            friConfig: FriConfig({
                logBlowupFactor: logBlowupFactor,
                logLastLayerDegreeBound: logLastLayerDegreeBound,
                nQueries: nQueries
            })
        });
    }

    /// @notice Mix configuration into channel for Fiat-Shamir
    /// @param config Configuration to mix
    /// @return Hash of configuration
    function hash(Config memory config) internal pure returns (bytes32) {
        return keccak256(encode(config));
    }
}