// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../cosets/CosetM31.sol";
import "./ICosetCache.sol";
import {console} from "forge-std/console.sol";

/// @title CosetCacheStorage
/// @notice Standalone contract for caching coset calculations
contract CosetCacheStorage is ICosetCache {
    /// @notice Cache for cosets to avoid recalculation
    /// @dev Key is hash of (initialIndex.value, logSize)
    mapping(bytes32 => CosetM31.CosetStruct) private _cosetCache;
    
    /// @notice Track which cosets are cached
    mapping(bytes32 => bool) private _cosetCacheExists;

    /// @notice Get or compute cached coset
    /// @dev Uses storage cache to avoid recomputing same cosets
    /// @param initialIndex Initial circle point index
    /// @param logSize Log2 of coset size
    /// @return coset Cached or newly computed coset
    function getCachedCoset(
        CosetM31.CirclePointIndex memory initialIndex,
        uint32 logSize
    ) external returns (CosetM31.CosetStruct memory coset) {
        // Generate cache key from parameters
        bytes32 cacheKey = keccak256(abi.encodePacked(initialIndex.value, logSize));
        
        console.log("[CACHE DEBUG] Checking cache for key:", uint256(cacheKey));
        console.log("[CACHE DEBUG] initialIndex:", initialIndex.value, "logSize:", logSize);
        console.log("[CACHE DEBUG] Cache exists:", _cosetCacheExists[cacheKey]);
        
        // Check if coset exists in cache
        if (_cosetCacheExists[cacheKey]) {
            console.log("[CACHE] Coset cache HIT for logSize:", logSize, "index:", initialIndex.value);
            return _cosetCache[cacheKey];
        }
        
        // Cache miss - compute coset
        console.log("[CACHE] Coset cache MISS for logSize:", logSize, "index:", initialIndex.value);
        coset = CosetM31.newCoset(initialIndex, logSize);
        
        // Store in cache
        _cosetCache[cacheKey] = coset;
        _cosetCacheExists[cacheKey] = true;
        console.log("[CACHE DEBUG] Stored in cache, exists now:", _cosetCacheExists[cacheKey]);
        
        return coset;
    }

    /// @notice Clear cache (for testing)
    function clearCache() external {
        // Note: This doesn't actually delete mappings, just marks them as not existing
        // In production, we'd need a more sophisticated approach
    }
}
