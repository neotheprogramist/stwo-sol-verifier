# STWO Solidity Verifier

## Commands

### Deploy STWOVerifier Contract

```bash
# Deploy with default settings
cargo run --bin deploy

# Deploy with custom gas limit  
cargo run --bin deploy -- --gas-limit 50000000

# Deploy with custom block time
cargo run --bin deploy -- --block-time 2

# Deploy with larger code size limit
cargo run --bin deploy -- --code-size-limit 100000

# Keep Anvil running after deployment
cargo run --bin deploy -- --keep-running

# Deploy on external RPC (set environment variable)
ETH_RPC_URL=https://eth-mainnet.alchemyapi.io/v2/your-key cargo run --bin deploy
```

### Run Fibonacci Example

```bash
# Full example: deploy + prove + verify
cargo run --bin fibonacci

# Deploy only (skip verification)
cargo run --bin fibonacci -- --only-deploy
```

### Project Structure

- `crates/verifier` - Contract deployment tools
- `crates/contracts` - Alloy type definitions  
- `crates/examples/fibonacci` - Fibonacci proof verification example