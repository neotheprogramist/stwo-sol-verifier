// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../contracts/verifier/StwoVerifier.sol";
import "../contracts/libraries/ComponentsLib.sol";
import "../contracts/libraries/FrameworkComponentLib.sol";
import "../contracts/libraries/TraceLocationAllocatorLib.sol";

/// @title Deploy STWO Verifier Script
/// @notice Deploys STWO verifier contract to Anvil local network
contract DeploySTWOVerifier is Script {
    function run() external {
        // Get deployer private key from environment or use default Anvil key
        uint256 deployerPrivateKey = vm.envOr(
            "PRIVATE_KEY",
            uint256(
                0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
            )
        );

        console.log("Starting STWO Verifier deployment...");
        console.log("Deployer address:", vm.addr(deployerPrivateKey));
        console.log("Chain ID:", block.chainid);
        console.log("Block number:", block.number);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy external libraries first
        console.log("Deploying libraries...");

        // Note: Libraries with only internal functions are embedded automatically
        // External libraries are deployed separately by Forge

        // Deploy STWO Verifier contract (Forge will handle library linking)
        console.log("Deploying STWO Verifier...");
        STWOVerifier verifier = new STWOVerifier();

        vm.stopBroadcast();

        console.log("=== DEPLOYMENT SUCCESSFUL ===");
        console.log("STWO Verifier deployed at:", address(verifier));
        console.log("Gas used for deployment:");

        // Verify deployment
        console.log("Verifying deployment...");
        require(
            address(verifier) != address(0),
            "Deployment failed - zero address"
        );
        console.log(" Deployment verified successfully");

        // Log deployment info (writeFile requires fs_permissions in foundry.toml)
        console.log("=== DEPLOYMENT INFO ===");
        console.log("Chain ID:", block.chainid);
        console.log("Block:", block.number);
        console.log("Deployer:", vm.addr(deployerPrivateKey));
    }
}
