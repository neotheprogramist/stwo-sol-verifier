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
        verifier_input.proof,
        verifier_input.verificationParams,
        verifier_input.treeRoots,
        verifier_input.treeColumnLogSizes,
        verifier_input.digest,
        verifier_input.nDraws,
    );

    match verification_call.call().await {
        Ok(result) => {
            if result {
                println!("✅ Verification PASSED! The Fibonacci proof is valid.");
            } else {
                println!("❌ Verification FAILED! The proof was rejected.");
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
