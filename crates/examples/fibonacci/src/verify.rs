use alloy::primitives::FixedBytes;

use contracts::{
    convert_to_solidity_proof, prepare_verification_params, VerificationParams, VerifierInput,
};
use num_traits::Zero;

use stwo::core::air::Component;
use stwo::core::channel::KeccakChannel;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::keccak_merkle::{KeccakMerkleChannel, KeccakMerkleHasher};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::SecureCirclePoly;

use stwo_constraint_framework::TraceLocationAllocator;
use stwo_polynomial::verify::verify;

use crate::fibonacci_circuit::{FibonacciComponent, FibonacciEval};
use crate::prove::Metadata;

pub const PREPROCESSED_TRACE_IDX: usize = 0;

pub fn verify_and_prepare_on_chain_proof_fibonacci(
    proof: StarkProof<KeccakMerkleHasher>,
    composition_polynomial: SecureCirclePoly<SimdBackend>,
    metadata: Metadata,
) -> Result<VerifierInput, Box<dyn std::error::Error>> {
    // Create component
    let component = FibonacciComponent::new(
        &mut TraceLocationAllocator::default(),
        FibonacciEval {
            log_n_rows: metadata.log_size,
        },
        SecureField::zero(),
    );

    let config = proof.config;

    let verify_channel = &mut KeccakChannel::default();
    let mut verify_commitment_scheme = CommitmentSchemeVerifier::<KeccakMerkleChannel>::new(config);

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

    // Merkle verifiers data for init in contract
    let extended_log_sizes: Vec<Vec<u32>> = component
        .trace_log_degree_bounds()
        .iter()
        .map(|log_size| {
            log_size
                .iter()
                .map(|&ls| ls + proof.config.fri_config.log_blowup_factor)
                .collect()
        })
        .collect();

    let roots = vec![proof.commitments[0], proof.commitments[1]];

    let roots_bytes32: Vec<FixedBytes<32>> = roots.iter().map(|r| FixedBytes::from(r.0)).collect();

    // Channel state before off-chain verification
    let digest = verify_channel.digest();

    // Off chain verification
    verify(
        &[&component],
        verify_channel,
        &mut verify_commitment_scheme,
        proof.clone(),
        composition_polynomial.clone(),
    )?;
    let n_preprocessed_columns = verify_commitment_scheme.trees[PREPROCESSED_TRACE_IDX]
        .column_log_sizes
        .len();

    let verification_params: VerificationParams =
        prepare_verification_params(vec![component], n_preprocessed_columns)?;

    let solidity_proof = convert_to_solidity_proof(proof, composition_polynomial);

    let verifier_input = VerifierInput {
        proof: solidity_proof,
        verificationParams: verification_params,
        treeRoots: roots_bytes32,
        treeColumnLogSizes: extended_log_sizes,
        digest: FixedBytes::from(digest.0),
        nDraws: 0,
    };

    Ok(verifier_input)
}
