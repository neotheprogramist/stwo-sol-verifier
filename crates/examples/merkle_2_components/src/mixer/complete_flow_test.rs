//! Complete End-to-End Privacy Mixer Flow
//!
//! This test demonstrates the COMPLETE flow matching the frontend:
//! 1. Generate operations (deterministic)
//! 2. Compute commitments
//! 3. Add to HybridMerkleTree (incremental with zero hashes)
//! 4. Get proof data
//! 5. Verify using STARK proof (AIR)

use std::collections::BTreeSet;

use stwo_prover::core::queries::Queries;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use serde_json::json;
    use stwo_prover::constraint_framework::preprocessed_columns::PreProcessedColumnId;
    use stwo_prover::constraint_framework::FrameworkEval;
    use stwo_prover::core::air::Component;
    use stwo_prover::core::backend::simd::SimdBackend;
    use stwo_prover::core::channel::Blake2sChannel;
    use stwo_prover::core::fields::m31::BaseField;
    use stwo_prover::core::fields::qm31::SecureField;
    use stwo_prover::core::fri::FriConfig;
    use stwo_prover::core::pcs::CommitmentSchemeProver;
    use stwo_prover::core::pcs::PcsConfig;
    use stwo_prover::core::pcs::TreeVec;
    use stwo_prover::core::poly::circle::CanonicCoset;
    use stwo_prover::core::poly::circle::PolyOps;
    use stwo_prover::core::poly::circle::SecureCirclePoly;
    use stwo_prover::core::queries::QueriesWithBranching;
    use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleChannel;

    use crate::gnark_json_gen::convert_stark_proof;
    use crate::gnark_json_gen::convert_verification_params;
    use crate::mixer::complete_flow_test::build_branching;
    use crate::mixer::complete_flow_test::build_column_bounds;
    use crate::mixer::complete_flow_test::build_deduped_queries_shape;
    use crate::mixer::complete_flow_test::build_fri_inner_layer_branching;
    use crate::mixer::complete_flow_test::build_positions_with_pairs;
    use crate::mixer::complete_flow_test::build_queries_by_log_size;
    use crate::mixer::full_flow::{compute_commitment, generate_operation, HybridMerkleTree};
    use crate::utils::{prove_merkle, verify_merkle};

    #[test]
    fn test_complete_privacy_mixer_flow() {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║   COMPLETE PRIVACY MIXER FLOW (Frontend-Compatible)     ║");
        println!("╚══════════════════════════════════════════════════════════╝\n");

        // ═══════════════════════════════════════════════════════════
        // STEP 1: GENERATE OPERATIONS (like frontend generateOperation)
        // ═══════════════════════════════════════════════════════════
        println!("📝 STEP 1: Generate Operations (Deterministic)\n");

        let master_nonce = BaseField::from_u32_unchecked(987654321);
        let num_operations = 5;

        let operations: Vec<_> = (0..num_operations)
            .map(|i| generate_operation(i, master_nonce))
            .collect();

        println!("Generated {} operations:", num_operations);
        for (i, op) in operations.iter().enumerate() {
            println!(
                "  Op {}: secret={}, nullifier={}, hash={}",
                i, op.secret.0, op.nullifier.0, op.hash.0
            );
        }

        // ═══════════════════════════════════════════════════════════
        // STEP 2: COMPUTE COMMITMENTS (like frontend)
        // ═══════════════════════════════════════════════════════════
        println!("\n💰 STEP 2: Compute Commitments\n");

        let amount = BaseField::from_u32_unchecked(1000);
        let token_address = BaseField::from_u32_unchecked(42);

        let commitments: Vec<_> = operations
            .iter()
            .map(|op| {
                let commitment = compute_commitment(op.hash, amount, token_address);
                println!("  Op {} → Commitment: {}", op.index, commitment.0);
                commitment
            })
            .collect();

        // ═══════════════════════════════════════════════════════════
        // STEP 3: BUILD MERKLE TREE (Incremental, like frontend)
        // ═══════════════════════════════════════════════════════════
        println!("\n🌳 STEP 3: Build Merkle Tree (Hybrid with Zero Hashes)\n");

        let tree_height = 5; // Can hold up to 32 leaves
        let mut tree = HybridMerkleTree::new(tree_height);

        println!("Created hybrid tree with height {}", tree_height);
        println!("Precomputed zero hashes:");
        for (i, hash) in tree.precomputed.iter().take(3).enumerate() {
            println!("  Level {}: {}", i, hash.0);
        }
        println!("  ...");

        println!("\nAdding commitments incrementally:");
        for (i, &commitment) in commitments.iter().enumerate() {
            tree.add_leaf(commitment);
            println!("  Added commitment {} → Root: {}", i, tree.get_root().0);
        }

        let final_root = tree.get_root();
        println!("\n✅ Final Merkle Root: {}", final_root.0);

        // ═══════════════════════════════════════════════════════════
        // STEP 4: GET PROOF DATA (like frontend getProofData)
        // ═══════════════════════════════════════════════════════════
        println!("\n🔗 STEP 4: Get Proof Data for Commitment 2\n");

        let target_commitment = commitments[2];
        let proof_data = tree
            .get_proof_data(target_commitment)
            .expect("Failed to get proof data");

        println!("Proof data for commitment 2:");
        println!("  Index: {}", proof_data.index);
        println!("  Root: {}", proof_data.root.0);
        println!(
            "  Siblings: {:?}",
            proof_data.siblings.iter().map(|s| s.0).collect::<Vec<_>>()
        );
        println!("  IsRight flags: {:?}", proof_data.is_right);

        // ═══════════════════════════════════════════════════════════
        // STEP 5: VERIFY USING STARK PROOF (AIR Verification)
        // ═══════════════════════════════════════════════════════════
        println!("\n✨ STEP 5: Verify Membership using STARK Proof (AIR)\n");

        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig::new(0, 1, 3),
        };
        println!("Security bits: {}", config.security_bits());
        let channel = &mut Blake2sChannel::default();
        let twiddles =
            SimdBackend::precompute_twiddles(CanonicCoset::new(20).circle_domain().half_coset);
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        // Generate STARK proof for membership
        println!("Generating STARK proof...");
        let (proof, _, _, statement0, statement1, secure_circle_poly) = prove_merkle(
            tree_height - 1, // depth = height - 1
            target_commitment,
            proof_data.siblings.clone(),
            proof_data.index as u32,
            proof_data.root,
            channel,
            commitment_scheme,
        )
        .expect("Failed to generate proof");

        println!("✅ STARK proof generated successfully!");

        // Verify STARK proof
        println!("\nVerifying STARK proof...");
        let (
            digest,
            merkle_computing_component,
            merkle_scheduler_component,
            roots,
            extended_log_sizes,
            composition_log_degree_bound,
            queries_with_column_log_sizes,
            n_preprocessed_columns,
        ) = verify_merkle(
            proof.clone(),
            tree_height - 1,
            statement0,
            statement1,
            config,
            SecureCirclePoly::<SimdBackend>(secure_circle_poly.clone()),
        )
        .expect("Failed to verify proof");

        let inner_layers_len = proof.fri_proof.inner_layers.len();

        let (QueriesWithBranching { queries, branching }, column_log_sizes) =
            queries_with_column_log_sizes.clone();
        let mut queries_branching = branching;
        let deduped_shape = build_deduped_queries_shape(queries.clone());
        let base_queries = build_queries_by_log_size(queries);
        let column_bounds = build_column_bounds(&[column_log_sizes
            .clone()
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

        let shape_path = Path::new("merkle_shape.json");
        let payload = json!({
            "columnLogSizes": column_log_sizes,
            "dedupedQueriesShape": deduped_shape,
            "queriesBranching": queries_branching,
            "friFirstLayerBranching": fri_first_layer_branching,
            "friInnerLayerBranching": fri_inner_layer_branching,
        });
        std::fs::write(&shape_path, serde_json::to_string_pretty(&payload).unwrap()).unwrap();

        let proof_json = convert_stark_proof(
            proof.clone(),
            SecureCirclePoly::<SimdBackend>(secure_circle_poly.clone()),
        );
        let proof_file = std::fs::File::create("merkle_proof.json").unwrap();

        serde_json::to_writer_pretty(proof_file, &proof_json).unwrap();

        let components_claimed_sum: Vec<SecureField> = vec![
            merkle_computing_component.claimed_sum(),
            merkle_scheduler_component.claimed_sum(),
        ];
        let components_preprocessed_columns: Vec<Vec<PreProcessedColumnId>> = vec![
            merkle_computing_component.info.preprocessed_columns.clone(),
            merkle_scheduler_component.info.preprocessed_columns.clone(),
        ];

        let components_log_sizes = vec![
            merkle_computing_component.log_size(),
            merkle_scheduler_component.log_size(),
        ];

        let components_mask_offsets: Vec<TreeVec<Vec<Vec<isize>>>> = vec![
            merkle_computing_component.info.mask_offsets.clone(),
            merkle_scheduler_component.info.mask_offsets.clone(),
        ];


        let params_json = convert_verification_params(
            vec![
                &merkle_computing_component as &dyn Component,
                &merkle_scheduler_component as &dyn Component,
            ],
            components_log_sizes,
            n_preprocessed_columns,
            components_mask_offsets,
            components_claimed_sum,
            components_preprocessed_columns,
            extended_log_sizes,
            &proof,
            digest.0,
        );

        let params_file = std::fs::File::create("merkle_params.json").unwrap();
        serde_json::to_writer_pretty(params_file, &params_json).unwrap();

        println!("✅ STARK proof verified successfully!");
    }

    #[test]
    fn test_multiple_verifications() {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║        Multiple Verifications (like batch withdraw)      ║");
        println!("╚══════════════════════════════════════════════════════════╝\n");

        let master_nonce = BaseField::from_u32_unchecked(111222333);
        let amount = BaseField::from_u32_unchecked(500);
        let token = BaseField::from_u32_unchecked(1);

        // Generate 3 operations and commitments
        let ops: Vec<_> = (0..3)
            .map(|i| generate_operation(i, master_nonce))
            .collect();

        let commitments: Vec<_> = ops
            .iter()
            .map(|op| compute_commitment(op.hash, amount, token))
            .collect();

        // Build tree
        let mut tree = HybridMerkleTree::new(4);
        for &commitment in &commitments {
            tree.add_leaf(commitment);
        }

        println!("Tree with {} commitments", commitments.len());
        println!("Root: {}\n", tree.get_root().0);

        // Setup for verification
        let config = PcsConfig::default();
        let twiddles =
            SimdBackend::precompute_twiddles(CanonicCoset::new(16).circle_domain().half_coset);

        // Verify each commitment
        for (i, &commitment) in commitments.iter().enumerate() {
            println!("Verifying commitment {}...", i);

            let channel = &mut Blake2sChannel::default();
            let commitment_scheme =
                CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

            let proof_data = tree.get_proof_data(commitment).unwrap();

            let (proof, _, _, statement0, statement1, secure_circle_poly) = prove_merkle(
                3, // depth
                commitment,
                proof_data.siblings,
                proof_data.index as u32,
                proof_data.root,
                channel,
                commitment_scheme,
            )
            .unwrap();

            verify_merkle(proof, 3, statement0, statement1, config, secure_circle_poly).unwrap();

            println!(
                "  ✅ Commitment {} verified (index {})",
                i, proof_data.index
            );
        }

        println!(
            "\n🎉 All {} commitments verified successfully!",
            commitments.len()
        );
    }

    #[test]
    fn test_production_tree_height_32() {
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║     PRODUCTION HEIGHT (32) - Full Scale Test            ║");
        println!("╚══════════════════════════════════════════════════════════╝\n");

        // ═══════════════════════════════════════════════════════════
        // STEP 1: Generate Operations
        // ═══════════════════════════════════════════════════════════
        println!("📝 STEP 1: Generate Operations\n");

        let master_nonce = BaseField::from_u32_unchecked(123456789);
        let num_operations = 10; // Can test with more if needed

        let operations: Vec<_> = (0..num_operations)
            .map(|i| generate_operation(i, master_nonce))
            .collect();

        println!("Generated {} operations", num_operations);

        // ═══════════════════════════════════════════════════════════
        // STEP 2: Compute Commitments
        // ═══════════════════════════════════════════════════════════
        println!("\n💰 STEP 2: Compute Commitments\n");

        let amount = BaseField::from_u32_unchecked(1000);
        let token_address = BaseField::from_u32_unchecked(42);

        let commitments: Vec<_> = operations
            .iter()
            .map(|op| compute_commitment(op.hash, amount, token_address))
            .collect();

        println!("Computed {} commitments", commitments.len());

        // ═══════════════════════════════════════════════════════════
        // STEP 3: Build Production-Scale Merkle Tree (HEIGHT = 32)
        // ═══════════════════════════════════════════════════════════
        println!("\n🌳 STEP 3: Build Merkle Tree with HEIGHT = 32\n");

        let tree_height = 32; // PRODUCTION HEIGHT
        let mut tree = HybridMerkleTree::new(tree_height);

        println!("✅ Created hybrid tree with height {}", tree_height);
        println!(
            "   Max capacity: 2^{} = {} leaves",
            tree_height - 1,
            1u64 << (tree_height - 1)
        );
        println!("   Precomputed zero hashes: {}", tree.precomputed.len());

        println!("\nFirst 5 precomputed zero hashes:");
        for (i, hash) in tree.precomputed.iter().take(5).enumerate() {
            println!("  Level {}: {}", i, hash.0);
        }
        println!("  ...");
        println!("  Level 31: {}", tree.precomputed[31].0);

        println!("\nAdding commitments:");
        for (i, &commitment) in commitments.iter().enumerate() {
            tree.add_leaf(commitment);
            if i < 3 || i == commitments.len() - 1 {
                println!("  [{}] Root: {}", i, tree.get_root().0);
            } else if i == 3 {
                println!("  ...");
            }
        }

        let final_root = tree.get_root();
        println!("\n✅ Final Merkle Root: {}", final_root.0);
        println!("   Current leaves: {}", tree.get_leafs().len());

        // ═══════════════════════════════════════════════════════════
        // STEP 4: Get Proof Data (depth = 31)
        // ═══════════════════════════════════════════════════════════
        println!("\n🔗 STEP 4: Get Proof Data\n");

        let target_commitment = commitments[5]; // Middle commitment
        let proof_data = tree
            .get_proof_data(target_commitment)
            .expect("Failed to get proof data");

        println!("Proof data for commitment at index {}:", proof_data.index);
        println!("  Root: {}", proof_data.root.0);
        println!(
            "  Siblings path length: {} (depth = {})",
            proof_data.siblings.len(),
            tree_height - 1
        );
        println!("  First 3 siblings:");
        for (i, sibling) in proof_data.siblings.iter().take(3).enumerate() {
            println!(
                "    Level {}: {} (isRight: {})",
                i, sibling.0, proof_data.is_right[i]
            );
        }
        println!("  ...");

        // ═══════════════════════════════════════════════════════════
        // STEP 5: Verify with STARK (depth = 31)
        // ═══════════════════════════════════════════════════════════
        println!("\n✨ STEP 5: STARK Verification (depth = 31)\n");

        let config = PcsConfig::default();
        let channel = &mut Blake2sChannel::default();

        // Note: log_size must accommodate depth=31 trace
        // We need at least 2^5=32 rows for depth=31
        let twiddles =
            SimdBackend::precompute_twiddles(CanonicCoset::new(16).circle_domain().half_coset);
        let commitment_scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);

        println!("Generating STARK proof for depth = {} ...", tree_height - 1);
        let start = std::time::Instant::now();

        let (proof, _, _, statement0, statement1, secure_circle_poly) = prove_merkle(
            tree_height - 1, // depth = 31
            target_commitment,
            proof_data.siblings.clone(),
            proof_data.index as u32,
            proof_data.root,
            channel,
            commitment_scheme,
        )
        .expect("Failed to generate proof");

        let proof_time = start.elapsed();
        println!("✅ STARK proof generated in {:?}", proof_time);

        println!("\nVerifying STARK proof...");
        let start = std::time::Instant::now();

        verify_merkle(
            proof,
            tree_height - 1,
            statement0,
            statement1,
            config,
            secure_circle_poly,
        )
        .expect("Failed to verify proof");

        let verify_time = start.elapsed();
        println!("✅ STARK proof verified in {:?}", verify_time);

        // ═══════════════════════════════════════════════════════════
        // SUMMARY
        // ═══════════════════════════════════════════════════════════
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║          PRODUCTION SCALE TEST COMPLETE ✅                ║");
        println!("╚══════════════════════════════════════════════════════════╝\n");

        println!("📊 Production Statistics:");
        println!("  Tree height: {}", tree_height);
        println!("  Tree depth: {}", tree_height - 1);
        println!(
            "  Max capacity: 2^{} = {} leaves",
            tree_height - 1,
            1u64 << (tree_height - 1)
        );
        println!("  Current leaves: {}", tree.get_leafs().len());
        println!("  Precomputed hashes: {}", tree.precomputed.len());
        println!("  Siblings path length: {}", proof_data.siblings.len());
        println!("  Final root: {}", final_root.0);
        println!("  Proof generation time: {:?}", proof_time);
        println!("  Verification time: {:?}", verify_time);

        println!(
            "\n🎉 Successfully verified commitment at index {} in production-scale tree!",
            proof_data.index
        );
        println!("This tree can hold up to {} leaves (2^31)!", 1u64 << 31);
    }
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
