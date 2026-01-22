use alloy::primitives::Address;
use anyhow::Result;
use clap::{Arg, Command};
use contracts::{STWOVerifier, VerifierInput};
use verifier::deploy::{AnvilConfig, DeploymentResult, STWOVerifierDeployer};

mod fibonacci_circuit;
mod prove;
mod verify;

/// Fibonacci STARK proof verification example
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("Fibonacci STARK Verifier")
        .version("1.0")
        .about("Example demonstrating Fibonacci sequence verification using STWO verifier")
        .arg(
            Arg::new("only-deploy")
                .long("only-deploy")
                .help("Only deploy the verifier contract without running verification")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("only-verify")
                .long("only-verify")
                .help("Only verify using existing contract (requires --node-url and --contract-address)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("node-url")
                .long("node-url")
                .help("RPC URL of the node to connect to (required with --only-verify)")
                .value_name("URL"),
        )
        .arg(
            Arg::new("contract-address")
                .long("contract-address")
                .help("Address of the deployed verifier contract (required with --only-verify)")
                .value_name("ADDRESS"),
        )
        .arg(
            Arg::new("sequence-length")
                .long("sequence-length")
                .short('n')
                .help("Length of Fibonacci sequence to verify")
                .value_name("LENGTH")
                .default_value("10"),
        )
        .get_matches();

    println!("🧮 Fibonacci STARK Verifier Example");
    println!("===================================");

    // Handle --only-verify flag first
    if matches.get_flag("only-verify") {
        let node_url = matches
            .get_one::<String>("node-url")
            .ok_or("--node-url is required when using --only-verify")?;
        let contract_address = matches
            .get_one::<String>("contract-address")
            .ok_or("--contract-address is required when using --only-verify")?;

        // Parse contract address
        let verifier_address: Address = contract_address
            .parse()
            .map_err(|_| "Invalid contract address format")?;

        // Prepare verification data
        let verifier_input = prepare_fibonacci_verification().await?;

        // Connect to existing contract and verify
        verify_with_existing_contract(node_url, verifier_address, verifier_input).await?;

        println!("\n🎉 Fibonacci verification completed!");
        return Ok(());
    }

    // Step 1: Deploy STWOVerifier contract
    let (deployment_result, deployer) = deploy_verifier().await?;

    if matches.get_flag("only-deploy") {
        println!(
            "\n✅ Deployment complete. Use contract at: {:?}",
            deployment_result.verifier_address
        );
        return Ok(());
    }

    // Step 2: Setup Fibonacci sequence parameters
    let sequence_length: u32 = matches
        .get_one::<String>("sequence-length")
        .unwrap()
        .parse()
        .unwrap_or(10);

    println!(
        "\n📊 Setting up Fibonacci verification for sequence length: {}",
        sequence_length
    );

    // Step 3: Prepare verification data
    let verifier_input = prepare_fibonacci_verification().await?;

    // Step 4: Interact with deployed contract
    interact_with_verifier(
        deployment_result.verifier_address,
        verifier_input,
        &deployer,
    )
    .await?;

    println!("\n🎉 Fibonacci verification example completed!");
    Ok(())
}

/// Deploy the STWOVerifier contract using Anvil and return both result and deployer
async fn deploy_verifier() -> Result<(DeploymentResult, STWOVerifierDeployer)> {
    println!("\n🚀 Deploying STWOVerifier contract...");

    let anvil_config = AnvilConfig {
        block_time: 1,
        code_size_limit: 100000,
        gas_limit: "30000000".to_string(),
        fork_url: None,
    };

    let deployer = STWOVerifierDeployer::with_anvil_config(anvil_config)?;
    let result = deployer.deploy().await?;

    println!("✅ STWOVerifier deployed successfully!");
    println!("   Contract Address: {:?}", result.verifier_address);
    if let Some(chain_id) = result.chain_id {
        println!("   Chain ID: {}", chain_id);
    }

    Ok((result, deployer))
}

async fn prepare_fibonacci_verification() -> Result<VerifierInput, Box<dyn std::error::Error>> {
    let (proof, composition_polynomial, metadata) = prove::prove_fibonacci()?;
    let verifier_input = verify::verify_and_prepare_on_chain_proof_fibonacci(
        proof,
        composition_polynomial,
        metadata,
    )?;

    Ok(verifier_input)
}

/// Interact with the deployed verifier contract
async fn interact_with_verifier(
    verifier_address: Address,
    verifier_input: VerifierInput,
    deployer: &STWOVerifierDeployer,
) -> Result<()> {
    use alloy::{
        network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    };

    println!("\n🔗 Connecting to verifier contract...");
    println!("   Contract Address: {:?}", verifier_address);

    // Get deployment info to reuse the same Anvil instance
    let deployment_info = deployer.get_info();
    let rpc_url = deployment_info.rpc_url.parse()?;

    // Use the same private key as deployer (Anvil's default account #0)
    let signer: PrivateKeySigner = deployer.get_signer().await?;

    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create contract instance
    let contract = STWOVerifier::new(verifier_address, &provider);

    // Call the verify function
    println!("\n⚡ Calling contract verify function...");

    let verification_call = contract.verify(
        verifier_input.proof.clone(),
        verifier_input.verificationParams.clone(),
        verifier_input.treeRoots.clone(),
        verifier_input.treeColumnLogSizes.clone(),
        verifier_input.digest.clone(),
        verifier_input.nDraws,
    );

    // Execute the call and get transaction receipt to track gas
    match verification_call.send().await {
        Ok(pending_tx) => {
            println!("   Transaction sent, waiting for confirmation...");
            let receipt = pending_tx.get_receipt().await?;

            println!("⛽ Gas Usage Information:");
            println!("   Gas Used: {}", receipt.gas_used);
            let gas_price = receipt.effective_gas_price;
            let gas_cost_wei = receipt.gas_used as u128 * gas_price;
            let gas_cost_eth = gas_cost_wei as f64 / 1e18;
            println!("   Gas Price: {} wei", gas_price);
            println!(
                "   Total Cost: {} wei ({:.8} ETH)",
                gas_cost_wei, gas_cost_eth
            );

            // Check transaction status for verification result
            if receipt.status() {
                println!("✅ Verification transaction successful!");

                // To get the actual return value, we need to call the view function
                let view_result = verification_call.call().await?;

                if view_result {
                    println!("🎯 Verification PASSED! The Fibonacci proof is valid.");
                } else {
                    println!("❌ Verification FAILED! The proof was rejected.");
                }
            } else {
                println!("💥 Verification transaction failed!");
            }
        }
        Err(e) => {
            println!("💥 Contract call failed: {}", e);
            return Err(e.into());
        }
    }

    println!("🏁 Contract interaction completed successfully!");
    Ok(())
}

/// Verify using an existing deployed contract on a specific network
async fn verify_with_existing_contract(
    node_url: &str,
    verifier_address: Address,
    verifier_input: VerifierInput,
) -> Result<()> {
    use alloy::{
        network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
    };

    println!("\n🔗 Connecting to existing verifier contract...");
    println!("   Node URL: {}", node_url);
    println!("   Contract Address: {:?}", verifier_address);

    let rpc_url = node_url.parse()?;

    // For external networks, we need a private key from environment or user input
    // For now, we'll use a default private key (user should provide their own in production)
    let private_key = std::env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
    }); // Default anvil key

    let signer: PrivateKeySigner = private_key
        .parse()
        .map_err(|_| "Invalid private key format")
        .unwrap();

    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    // Create contract instance
    let contract = STWOVerifier::new(verifier_address, &provider);

    // Call the verify function
    println!("\n⚡ Calling contract verify function...");

    let verification_call = contract.verify(
        verifier_input.proof.clone(),
        verifier_input.verificationParams.clone(),
        verifier_input.treeRoots.clone(),
        verifier_input.treeColumnLogSizes.clone(),
        verifier_input.digest.clone(),
        verifier_input.nDraws,
    );

    let view_result = verification_call.call().await?;

    if view_result {
        println!("🎯 Verification PASSED! The Fibonacci proof is valid.");
    } else {
        println!("❌ Verification FAILED! The proof was rejected.");
    };

    // // Execute the call and get transaction receipt to track gas
    // match verification_call.send().await {
    //     Ok(pending_tx) => {
    //         println!("   Transaction sent, waiting for confirmation...");
    //         let receipt = pending_tx.get_receipt().await?;

    //         println!("⛽ Gas Usage Information:");
    //         println!("   Gas Used: {}", receipt.gas_used);
    //         let gas_price = receipt.effective_gas_price;
    //         let gas_cost_wei = receipt.gas_used as u128 * gas_price;
    //         let gas_cost_eth = gas_cost_wei as f64 / 1e18;
    //         println!("   Gas Price: {} wei", gas_price);
    //         println!(
    //             "   Total Cost: {} wei ({:.8} ETH)",
    //             gas_cost_wei, gas_cost_eth
    //         );

    //         // Check transaction status for verification result
    //         if receipt.status() {
    //             println!("✅ Verification transaction successful!");

    //             // To get the actual return value, we need to call the view function
    //             let view_result = verification_call.call().await?;

    //             if view_result {
    //                 println!("🎯 Verification PASSED! The Fibonacci proof is valid.");
    //             } else {
    //                 println!("❌ Verification FAILED! The proof was rejected.");
    //             }
    //         } else {
    //             println!("💥 Verification transaction failed!");
    //         }
    //     }
    //     Err(e) => {
    //         println!("💥 Contract call failed: {}", e);
    //         return Err(e.into());
    //     }
    // }

    println!("🏁 Contract verification completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deployment_only() -> Result<()> {
        // This test only verifies that deployment setup works
        // Actual deployment would require running environment

        let anvil_config = AnvilConfig::default();
        assert_eq!(anvil_config.block_time, 1);

        Ok(())
    }
}
