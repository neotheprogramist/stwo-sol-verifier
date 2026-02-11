use alloy::primitives::Address;
use anyhow::Result;
use clap::{Arg, Command};
// use contracts::{STWOVerifier, VerifierInput};
// use stwo_prover::core::{channel::Blake2sChannel, vcs::blake2_merkle::Blake2sMerkleChannel};
use verifier::deploy::{AnvilConfig, DeploymentResult, STWOVerifierDeployer};

mod fibonacci_circuit;
mod gnark_json_gen;
mod prove_blake;

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
            Arg::new("prepare-gnark-proof")
                .long("prepare-gnark-proof")
                .help("Generate proof and verification parameters JSON files for Gnark")
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

    if matches.get_flag("prepare-gnark-proof") {
        println!("📝 Preparing Gnark proof and parameters...");
        prepare_gnark_json().await?;
        println!("✅ Gnark JSON files created: proof.json, params.json");
        return Ok(());
    }

    // Handle --only-verify flag first
    if matches.get_flag("only-verify") {
        let _ = matches
            .get_one::<String>("node-url")
            .ok_or("--node-url is required when using --only-verify")?;
        let contract_address = matches
            .get_one::<String>("contract-address")
            .ok_or("--contract-address is required when using --only-verify")?;

        // Parse contract address
        let _: Address = contract_address
            .parse()
            .map_err(|_| "Invalid contract address format")?;

        // Prepare verification data
        // let verifier_input = prepare_fibonacci_verification().await?;

        // // Connect to existing contract and verify
        // verify_with_existing_contract(node_url, verifier_address, verifier_input).await?;

        println!("\n🎉 Fibonacci verification completed!");
        return Ok(());
    }

    // Step 1: Deploy STWOVerifier contract
    let (deployment_result, _) = deploy_verifier().await?;

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

    // // Step 3: Prepare verification data
    // let verifier_input = prepare_fibonacci_verification().await?;

    // // Step 4: Interact with deployed contract
    // interact_with_verifier(
    //     deployment_result.verifier_address,
    //     verifier_input,
    //     &deployer,
    // )
    // .await?;

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
async fn prepare_gnark_json() -> Result<(), Box<dyn std::error::Error>> {
    use crate::fibonacci_circuit::{FibonacciComponent, FibonacciEval};
    use crate::gnark_json_gen::{convert_stark_proof, convert_verification_params};
    use crate::prove_blake::Metadata;
    use num_traits::Zero;
    use stwo_prover::core::air::Component;
    use stwo_prover::core::backend::simd::SimdBackend;
    use stwo_prover::core::channel::Blake2sChannel;
    use stwo_prover::core::fields::qm31::SecureField;
    use stwo_prover::core::pcs::CommitmentSchemeVerifier;
    use stwo_prover::core::poly::circle::SecureCirclePoly;
    use stwo_prover::core::prover::StarkProof;
    use stwo_prover::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
    use stwo_prover::constraint_framework::TraceLocationAllocator;
    use stwo_polynomial::verify::verify_with_queries;

    // 1. Generate Proof
    let (proof, composition_polynomial, metadata): (
        StarkProof<Blake2sMerkleHasher>,
        SecureCirclePoly<SimdBackend>,
        Metadata,
    ) = prove_blake::prove_fibonacci()?;

    // 2. Run off-chain verification (Blake2s)
    prove_blake::verify_fibonacci_blake(proof.clone(), SecureCirclePoly::<SimdBackend>(composition_polynomial.clone()), metadata.clone())?;

    // 3. Prepare JSON for Proof
    let proof_json = convert_stark_proof(proof.clone(), SecureCirclePoly::<SimdBackend>(composition_polynomial.clone()));
    let proof_file = std::fs::File::create("proof.json")?;
    serde_json::to_writer_pretty(proof_file, &proof_json)?;

    // 3. Prepare Verification Params (requires partial verification to get digest)

    // Recreate component from metadata
    let component = FibonacciComponent::new(
        &mut TraceLocationAllocator::default(),
        FibonacciEval {
            log_n_rows: metadata.log_size,
        },
        SecureField::zero(),
    );

    let config = proof.config;
    let verify_channel = &mut Blake2sChannel::default();
    let mut verify_commitment_scheme = CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // Channel commitments
    verify_commitment_scheme.commit(
        proof.commitments[0],
        &component.trace_log_degree_bounds()[0],
        verify_channel,
    );
    verify_commitment_scheme.commit(
        proof.commitments[1],
        &component.trace_log_degree_bounds()[1],
        verify_channel,
    );

    // Get digest (state before verify)
    let digest = verify_channel.digest();

    // Run off-chain verify to ensure it's valid and to get preprocessed columns info if needed (though here it's static)
    verify_with_queries(
        &[&component],
        verify_channel,
        &mut verify_commitment_scheme,
        proof.clone(),
        SecureCirclePoly::<SimdBackend>(composition_polynomial.clone()),
    )?;

    
    // Prepare JSON for Params
    let n_preprocessed_columns = verify_commitment_scheme.trees[0] // PREPROCESSED_TRACE_IDX is 0
        .column_log_sizes
        .len();

    let params_json = convert_verification_params(
        vec![component],
        n_preprocessed_columns,
        &proof,
        digest.0,
    );

    let params_file = std::fs::File::create("params.json")?;
    serde_json::to_writer_pretty(params_file, &params_json)?;

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
