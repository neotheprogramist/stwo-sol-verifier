
use num_traits::Zero;

use stwo::core::channel::KeccakChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig as StwoFriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{PolyOps, SecureCirclePoly};
use stwo::prover::CommitmentSchemeProver;
use stwo_constraint_framework::TraceLocationAllocator;
use stwo_polynomial::prove::prove;

use crate::fibonacci_circuit::{gen_fibonacci_trace, FibonacciComponent, FibonacciEval};

#[derive(Debug, Clone)]
pub struct Metadata {
    pub log_size: u32,
}

// Example prove for fibonacci(10)
pub fn prove_fibonacci() -> Result<
    (
        StarkProof<KeccakMerkleHasher>,
        SecureCirclePoly<SimdBackend>,
        Metadata,
    ),
    Box<dyn std::error::Error>,
> {
    let target_n = 10; // Compute f(10) = 55
    let (trace, target_value, log_size) = gen_fibonacci_trace(target_n);
    println!("Fibonacci target value {}", target_value);
    // Setup PCS config
    let config = PcsConfig {
        pow_bits: 10,
        fri_config: StwoFriConfig::new(1, 1, 3),
    };
    println!("Security bits: {}", config.security_bits());

    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    let channel = &mut KeccakChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, KeccakMerkleChannel>::new(config, &twiddles);

    // Commit preprocessed (empty for Fibonacci)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(vec![]);
    tree_builder.commit(channel);

    // Commit trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.clone());
    tree_builder.commit(channel);

    // Create component
    let component = FibonacciComponent::new(
        &mut TraceLocationAllocator::default(),
        FibonacciEval {
            log_n_rows: log_size,
        },
        SecureField::zero(),
    );

    let (proof, composition_polynomial) = prove(&[&component], channel, commitment_scheme)?;

    println!("  ✅ STARK proof generated\n");

    let metadata = Metadata { log_size };

    Ok((proof, composition_polynomial, metadata))
}
