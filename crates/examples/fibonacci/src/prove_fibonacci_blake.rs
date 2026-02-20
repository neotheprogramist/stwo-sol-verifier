use std::collections::BTreeSet;
use std::path::Path;

use num_traits::Zero;
use stwo_prover::core::air::Component;
use serde_json::json;
use stwo_prover::core::channel::{Blake2sChannel};
use stwo_prover::core::fields::qm31::SecureField;
use stwo_prover::core::fri::FriConfig as StwoFriConfig;
use stwo_prover::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo_prover::core::poly::circle::CanonicCoset;
use stwo_prover::core::prover::StarkProof;
use stwo_prover::core::queries::{Queries, QueriesWithBranching};
use stwo_prover::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
// use stwo_prover::core::vcs::keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher};
use stwo_prover::core::backend::simd::SimdBackend;
use stwo_prover::core::poly::circle::{PolyOps, SecureCirclePoly};
use stwo_prover::core::pcs::CommitmentSchemeProver;
use stwo_prover::constraint_framework::TraceLocationAllocator;
use stwo_polynomial::prove::prove;
use stwo_polynomial::verify::{verify_with_queries};

use crate::fibonacci_circuit::{gen_fibonacci_trace, FibonacciComponent, FibonacciEval};

#[derive(Debug, Clone)]
pub struct Metadata {
    pub log_size: u32,
}

// Example prove for fibonacci(10)
pub fn prove_fibonacci() -> Result<
    (
        StarkProof<Blake2sMerkleHasher>,
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

    let channel = &mut Blake2sChannel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

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

/// Verify Blake2s Fibonacci proof off-chain
pub fn verify_fibonacci_blake(
    proof: StarkProof<Blake2sMerkleHasher>,
    composition_polynomial: SecureCirclePoly<SimdBackend>,
    metadata: Metadata,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Starting off-chain verification (Blake2s)...");

    // Create component
    let component = FibonacciComponent::new(
        &mut TraceLocationAllocator::default(),
        FibonacciEval {
            log_n_rows: metadata.log_size,
        },
        SecureField::zero(),
    );

    let config = proof.config;

    let verify_channel = &mut Blake2sChannel::default();
    let mut verify_commitment_scheme =
        CommitmentSchemeVerifier::<Blake2sMerkleChannel>::new(config);

    // Channel and commitment scheme state initialization
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

    println!("  📊 Commitments processed");
    println!("  🔐 Channel digest: {:?}", verify_channel.digest());

    // Off-chain verification
    let queries_with_column_log_sizes = verify_with_queries(
        &[&component],
        verify_channel,
        &mut verify_commitment_scheme,
        proof.clone(),
        SecureCirclePoly::<SimdBackend>(composition_polynomial.clone()),
    )?;
    let inner_layers_len = proof.fri_proof.inner_layers.len();

    let (QueriesWithBranching { queries, branching }, column_log_sizes) =
        queries_with_column_log_sizes.clone();
    
    let mut queries_branching = branching;
    let deduped_shape = build_deduped_queries_shape(queries.clone());
    let base_queries = build_queries_by_log_size(queries);
    let column_bounds = build_column_bounds(&[column_log_sizes.clone()
        .flatten()
        .iter()
        .map(|&x| x as u64)
        .collect::<Vec<u64>>()]);
    let paired_layers: BTreeSet<usize> = column_bounds.iter().copied().collect();
    let first_layer_positions = build_positions_with_pairs(&base_queries, &paired_layers);
    let fri_first_layer_branching = build_branching(&first_layer_positions);
    let fri_inner_layer_branching =
        build_fri_inner_layer_branching(&base_queries, &column_bounds, inner_layers_len);
    if queries_branching.len() < deduped_shape.len() {
        queries_branching.resize(deduped_shape.len(), Vec::new());
    }

    let shape_path = Path::new("fibonacci_shape.json");
    let payload = json!({
        "columnLogSizes": column_log_sizes,
        "dedupedQueriesShape": deduped_shape,
        "queriesBranching": queries_branching,
        "friFirstLayerBranching": fri_first_layer_branching,
        "friInnerLayerBranching": fri_inner_layer_branching,
    });
    std::fs::write(&shape_path, serde_json::to_string_pretty(&payload).unwrap()).unwrap();

    println!("  📋 Queries with branching: {:?}", queries_with_column_log_sizes);
    println!("  ✅ Off-chain verification PASSED\n");

    Ok(())
}

fn build_branching(positions_by_log_size: &[Vec<usize>]) -> Vec<Vec<u8>> {
    if positions_by_log_size.is_empty() {
        return Vec::new();
    }
    let mut branching = vec![Vec::new(); positions_by_log_size.len()];
    for log_size in 0..positions_by_log_size.len() - 1 {
        let children = &positions_by_log_size[log_size + 1];
        for &parent in &positions_by_log_size[log_size] {
            let left = parent * 2;
            let right = left + 1;
            let left_present = children.binary_search(&left).is_ok();
            let right_present = children.binary_search(&right).is_ok();
            let code = (left_present as u8) | ((right_present as u8) << 1);
            branching[log_size].push(code);
        }
    }
    branching
}

fn build_deduped_queries_shape(mut queries: Queries) -> Vec<u64> {
    let mut shape = vec![0u64; 32];
    loop {
        let log_size = queries.log_domain_size as usize;
        if log_size < shape.len() {
            println!("Log size: {}, positions: {:?}", log_size, queries.positions);
            shape[log_size] = queries.positions.len() as u64;
        }
        if log_size == 0 {
            break;
        }
        queries = queries.fold(1);
    }
    shape
}

fn build_queries_by_log_size(mut queries: Queries) -> Vec<Vec<usize>> {
    let mut per_log = vec![Vec::new(); queries.log_domain_size as usize + 1];
    loop {
        let log_size = queries.log_domain_size as usize;
        per_log[log_size] = queries.positions.clone();
        if log_size == 0 {
            break;
        }
        queries = queries.fold(1);
    }
    per_log
}

fn build_column_bounds(column_log_sizes: &[Vec<u64>]) -> Vec<usize> {
    let mut set = BTreeSet::new();
    for tree in column_log_sizes {
        for &log_size in tree {
            set.insert((log_size + 1) as usize);
        }
    }
    let mut bounds: Vec<usize> = set.into_iter().collect();
    bounds.sort_by(|a, b| b.cmp(a));
    bounds
}

fn build_positions_with_pairs(
    base_positions: &[Vec<usize>],
    paired_layers: &BTreeSet<usize>,
) -> Vec<Vec<usize>> {
    let mut positions = vec![Vec::new(); base_positions.len()];
    for log_size in 0..base_positions.len() {
        if paired_layers.contains(&log_size) {
            if log_size == 0 {
                positions[log_size] = base_positions[log_size].clone();
            } else {
                let parents = &base_positions[log_size - 1];
                let mut paired = Vec::with_capacity(parents.len() * 2);
                for &parent in parents {
                    paired.push(parent * 2);
                    paired.push(parent * 2 + 1);
                }
                positions[log_size] = paired;
            }
        } else {
            positions[log_size] = base_positions[log_size].clone();
        }
    }
    positions
}

fn build_fri_inner_layer_branching(
    base_positions: &[Vec<usize>],
    column_bounds: &[usize],
    n_inner_layers: usize,
) -> Vec<Vec<Vec<u8>>> {
    if column_bounds.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(n_inner_layers);
    let mut log_size = column_bounds[0].saturating_sub(2);
    for _ in 0..n_inner_layers {
        let paired_layer = log_size + 1;
        let mut paired_layers = BTreeSet::new();
        paired_layers.insert(paired_layer);
        let positions = build_positions_with_pairs(base_positions, &paired_layers);
        result.push(build_branching(&positions));
        if log_size == 0 {
            break;
        }
        log_size -= 1;
    }
    result
}
