use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::Address,
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    providers::Provider,
};
use anyhow::Result;

sol!(
    #[sol(rpc)]
    STWOVerifier,
    "../../out/StwoVerifier.sol/STWOVerifier.json"
);

/// Configuration for Anvil instance
#[derive(Debug, Clone)]
pub struct AnvilConfig {
    /// Block time in seconds
    pub block_time: u64,
    /// Code size limit
    pub code_size_limit: u64,
    /// Gas limit
    pub gas_limit: String,
    /// Fork URL (optional)
    pub fork_url: Option<String>,
}

impl Default for AnvilConfig {
    fn default() -> Self {
        Self {
            block_time: 1,
            code_size_limit: 51000,
            gas_limit: "99999999999999".to_string(),
            fork_url: std::env::var("ETH_RPC_URL").ok(),
        }
    }
}

/// Result of a successful deployment
#[derive(Debug, Clone)]
pub struct DeploymentResult {
    pub verifier_address: Address,
    pub chain_id: Option<u64>,
    pub block_number: Option<u64>,
}

/// Configuration for deployment
#[derive(Debug)]
pub struct DeployConfig {
    private_key: PrivateKeySigner,
    rpc_url: Option<String>,
    anvil_instance: AnvilInstance,
    anvil_config: AnvilConfig,
}

impl DeployConfig {
    pub fn new(
        private_key: PrivateKeySigner,
        rpc_url: Option<String>,
        anvil_instance: AnvilInstance,
        anvil_config: AnvilConfig,
    ) -> Self {
        Self {
            private_key,
            rpc_url,
            anvil_instance,
            anvil_config,
        }
    }
}

/// Information about deployment configuration
#[derive(Debug, Clone)]
pub struct DeploymentInfo {
    pub rpc_url: String,
    pub anvil_config: AnvilConfig,
}

pub struct STWOVerifierDeployer {
    config: DeployConfig,
}

impl STWOVerifierDeployer {
    pub fn new(config: DeployConfig) -> Self {
        Self { config }
    }

    /// Create deployer with default Anvil configuration
    pub fn with_anvil() -> Result<Self> {
        Self::with_anvil_config(AnvilConfig::default())
    }

    /// Create deployer with custom Anvil configuration
    pub fn with_anvil_config(anvil_config: AnvilConfig) -> Result<Self> {
        let anvil = Self::setup_anvil(&anvil_config)?;
        let private_key = anvil.keys()[0].clone().into();
        let rpc_url = Some(anvil.endpoint());
        
        let config = DeployConfig::new(
            private_key,
            rpc_url,
            anvil,
            anvil_config,
        );

        Ok(Self { config })
    }

    /// Setup Anvil instance with given configuration
    fn setup_anvil(config: &AnvilConfig) -> Result<AnvilInstance> {
        let mut anvil_builder = Anvil::new()
            .block_time(config.block_time)
            .arg("--code-size-limit")
            .arg(config.code_size_limit.to_string())
            .arg("--gas-limit")
            .arg(&config.gas_limit);

        if let Some(ref fork_url) = config.fork_url {
            println!("🔗 Forking from: {}", fork_url);
            anvil_builder = anvil_builder.fork(fork_url.clone());
        }

        let anvil = anvil_builder.try_spawn()?;
        println!("⚡ Anvil started on: {}", anvil.endpoint());
        
        Ok(anvil)
    }

    /// Deploy STWOVerifier contract
    pub async fn deploy(&self) -> Result<DeploymentResult> {
        println!("🚀 Starting STWO Verifier deployment...");
        
        let provider = self.create_provider().await?;
        
        // Get network info
        let chain_id = provider.get_chain_id().await.ok();
        let block_number = provider.get_block_number().await.ok();
        
        println!("📋 Network info:");
        if let Some(id) = chain_id {
            println!("   Chain ID: {}", id);
        }
        if let Some(block) = block_number {
            println!("   Block number: {}", block);
        }

        // Deploy contract
        let deploy_tx = STWOVerifier::deploy(&provider).await?;
        let verifier_address = *deploy_tx.address();
        
        
        println!("✅ Contract deployed at: {:?}", verifier_address);
        
        // Verify deployment
        self.verify_deployment(verifier_address).await?;

        Ok(DeploymentResult {
            verifier_address,
            chain_id,
            block_number,
        })
    }

    /// Create provider with wallet
    async fn create_provider(&self) -> Result<impl alloy::providers::Provider> {
        let wallet = EthereumWallet::from(self.config.private_key.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.config.anvil_instance.endpoint_url().clone());
        
        Ok(provider)
    }

    /// Get deployment configuration info
    pub fn get_info(&self) -> DeploymentInfo {
        let rpc_url = self.config.rpc_url
            .as_ref()
            .unwrap_or(&"http://127.0.0.1:8545".to_string())
            .clone();
            
        DeploymentInfo {
            rpc_url,
            anvil_config: self.config.anvil_config.clone(),
        }
    }

    /// Verify that deployment was successful
    async fn verify_deployment(&self, verifier_address: Address) -> Result<()> {
        println!("🔍 Verifying deployment...");

        if verifier_address == Address::ZERO {
            anyhow::bail!("❌ Deployment failed - zero address");
        }

        // Additional verification could be added here:
        // - Check contract code exists
        // - Call a simple contract function
        
        println!("✅ Deployment verified successfully");
        Ok(())
    }

    /// Stop the Anvil instance
    pub fn stop_anvil(self) {
        drop(self.config.anvil_instance);
        println!("🛑 Anvil instance stopped");
    }

    /// Wait for user interruption (Ctrl+C)
    pub async fn wait_for_shutdown(self) -> Result<()> {
        println!("\n⏳ Anvil is running. Press Ctrl+C to stop...");
        tokio::signal::ctrl_c().await?;
        self.stop_anvil();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deploy_with_anvil() -> Result<()> {
        let deployer = STWOVerifierDeployer::with_anvil()?;
        let result = deployer.deploy().await?;

        assert_ne!(result.verifier_address, Address::ZERO);

        println!("Test deployment successful: {:?}", result.verifier_address);

        Ok(())
    }

    #[tokio::test]
    async fn test_deploy_with_custom_config() -> Result<()> {
        let custom_config = AnvilConfig {
            block_time: 2,
            code_size_limit: 100000,
            gas_limit: "50000000".to_string(),
            fork_url: None,
        };

        let deployer = STWOVerifierDeployer::with_anvil_config(custom_config)?;
        let result = deployer.deploy().await?;

        assert_ne!(result.verifier_address, Address::ZERO);
        println!("Custom config deployment successful: {:?}", result.verifier_address);

        Ok(())
    }
}