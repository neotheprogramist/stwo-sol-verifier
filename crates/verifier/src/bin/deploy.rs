use anyhow::Result;
use clap::{Arg, Command};
use verifier::deploy::{STWOVerifierDeployer, AnvilConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("STWO Verifier Deployer")
        .version("1.0")
        .about("Deploys STWO Verifier contract using Alloy with Anvil")
        .arg(
            Arg::new("block-time")
                .long("block-time")
                .help("Block time in seconds")
                .value_name("SECONDS")
                .default_value("1"),
        )
        .arg(
            Arg::new("code-size-limit")
                .long("code-size-limit")
                .help("Code size limit for contracts")
                .value_name("BYTES")
                .default_value("51000"),
        )
        .arg(
            Arg::new("gas-limit")
                .long("gas-limit")
                .help("Gas limit")
                .value_name("GAS")
                .default_value("99999999999999"),
        )
        .arg(
            Arg::new("keep-running")
                .long("keep-running")
                .help("Keep Anvil running after deployment")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    // Create Anvil configuration from command line args
    let anvil_config = AnvilConfig {
        block_time: matches.get_one::<String>("block-time")
            .unwrap()
            .parse()
            .unwrap_or(1),
        code_size_limit: matches.get_one::<String>("code-size-limit")
            .unwrap()
            .parse()
            .unwrap_or(51000),
        gas_limit: matches.get_one::<String>("gas-limit")
            .unwrap()
            .clone(),
        fork_url: std::env::var("ETH_RPC_URL").ok(),
    };

    println!("🔧 Starting deployment with configuration:");
    println!("   Block time: {} seconds", anvil_config.block_time);
    println!("   Code size limit: {} bytes", anvil_config.code_size_limit);
    println!("   Gas limit: {}", anvil_config.gas_limit);
    if let Some(ref fork_url) = anvil_config.fork_url {
        println!("   Fork URL: {}", fork_url);
    }

    // Create deployer and deploy
    let deployer = STWOVerifierDeployer::with_anvil_config(anvil_config)?;
    let result = deployer.deploy().await?;
    
    println!("\n🎉 Deployment completed successfully!");
    println!("📋 Results:");
    println!("   Contract Address: {:?}", result.verifier_address);
    if let Some(chain_id) = result.chain_id {
        println!("   Chain ID: {}", chain_id);
    }
    if let Some(block_number) = result.block_number {
        println!("   Block Number: {}", block_number);
    }
    
    if matches.get_flag("keep-running") {
        // Keep Anvil running until user stops it
        deployer.wait_for_shutdown().await?;
    } else {
        // Stop Anvil immediately
        deployer.stop_anvil();
    }

    Ok(())
}