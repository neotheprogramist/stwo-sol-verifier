use alloy::sol;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval};

// Main contract with all nested types included
sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    STWOVerifier,
    "../../out/StwoVerifier.sol/STWOVerifier.json"
);

// Re-export main contract types
use crate::{
    CM31Field::CM31,
    FrameworkComponentLib::ComponentInfo,
    FriVerifier::{FriLayerProof, FriProof},
    MerkleVerifier::Decommitment,
    PcsConfig::{Config, FriConfig},
    ProofParser::{CompositionPoly, Proof},
    QM31Field::QM31,
};
use alloy_primitives::{Bytes, FixedBytes, U256};
use stwo::{
    core::{
        air::{Component, Components},
        proof::StarkProof,
        utils::bit_reverse,
        vcs::keccak_merkle::KeccakMerkleHasher,
    },
    prover::{backend::simd::SimdBackend, poly::circle::SecureCirclePoly},
};

sol!(
    struct VerifierInput{
        Proof proof;
        VerificationParams verificationParams;
        bytes32[] treeRoots;
        uint32[][]  treeColumnLogSizes;
        bytes32 digest;
        uint32 nDraws;
    }
);
pub use STWOVerifier::*;

/// Recreate Solidity abi.encodePacked for decommitment
fn encode_decommitment_packed(hash_witness: &[FixedBytes<32>], column_witness: &[u32]) -> Bytes {
    let mut encoded = Vec::new();

    let length_bytes: [u8; 32] = U256::from(hash_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&length_bytes);

    for witness in hash_witness {
        encoded.extend_from_slice(witness.as_slice());
    }

    let column_length_bytes: [u8; 32] = U256::from(column_witness.len()).to_be_bytes();
    encoded.extend_from_slice(&column_length_bytes);

    for &val in column_witness {
        encoded.extend_from_slice(&val.to_be_bytes());
    }

    Bytes::from(encoded)
}

pub fn convert_to_solidity_proof(
    proof: StarkProof<KeccakMerkleHasher>,
    composition_polynomial: SecureCirclePoly<SimdBackend>,
) -> Proof {
    let sol_config = Config {
        powBits: proof.config.pow_bits,
        friConfig: FriConfig {
            logBlowupFactor: proof.config.fri_config.log_blowup_factor,
            logLastLayerDegreeBound: proof.config.fri_config.log_last_layer_degree_bound,
            nQueries: U256::from(proof.config.fri_config.n_queries),
        },
    };

    let commitments: Vec<FixedBytes<32>> = proof
        .0
        .commitments
        .iter()
        .map(|commitment| FixedBytes::from(commitment.0))
        .collect();

    let sampled_values: Vec<Vec<Vec<QM31>>> = proof
        .sampled_values
        .iter()
        .map(|column| {
            column
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|qm31| QM31 {
                            first: CM31 {
                                real: qm31.0 .0 .0,
                                imag: qm31.0 .1 .0,
                            },
                            second: CM31 {
                                real: qm31.1 .0 .0,
                                imag: qm31.1 .1 .0,
                            },
                        })
                        .collect()
                })
                .collect()
        })
        .collect();

    let decommitments: Vec<Decommitment> = proof
        .0
        .decommitments
        .iter()
        .map(|decom| Decommitment {
            hashWitness: decom
                .hash_witness
                .iter()
                .map(|h| FixedBytes::from(h.0))
                .collect::<Vec<_>>(),
            columnWitness: decom.column_witness.iter().map(|m| m.0).collect::<Vec<_>>(),
        })
        .collect();

    let first_layer: FriLayerProof = {
        let layer = &proof.0.fri_proof.first_layer;
        FriLayerProof {
            friWitness: layer
                .fri_witness
                .iter()
                .map(|val| QM31 {
                    first: CM31 {
                        real: val.0 .0 .0,
                        imag: val.0 .1 .0,
                    },
                    second: CM31 {
                        real: val.1 .0 .0,
                        imag: val.1 .1 .0,
                    },
                })
                .collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| FixedBytes::from(h.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|m| m.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        }
    };

    let inner_layers: Vec<FriLayerProof> = proof
        .0
        .fri_proof
        .inner_layers
        .iter()
        .map(|layer| FriLayerProof {
            friWitness: layer
                .fri_witness
                .iter()
                .map(|val| QM31 {
                    first: CM31 {
                        real: val.0 .0 .0,
                        imag: val.0 .1 .0,
                    },
                    second: CM31 {
                        real: val.1 .0 .0,
                        imag: val.1 .1 .0,
                    },
                })
                .collect(),
            decommitment: encode_decommitment_packed(
                &layer
                    .decommitment
                    .hash_witness
                    .iter()
                    .map(|h| FixedBytes::from(h.0))
                    .collect::<Vec<_>>(),
                &layer
                    .decommitment
                    .column_witness
                    .iter()
                    .map(|m| m.0)
                    .collect::<Vec<_>>(),
            ),
            commitment: FixedBytes::from(layer.commitment.0),
        })
        .collect();

    let fri_proof = FriProof {
        innerLayers: inner_layers,
        lastLayerPoly: {
            let mut coeffs = proof
                .clone()
                .0
                .fri_proof
                .last_layer_poly
                .into_ordered_coefficients();
            bit_reverse(&mut coeffs);
            coeffs
                .iter()
                .map(|v| QM31 {
                    first: CM31 {
                        real: v.0 .0 .0,
                        imag: v.0 .1 .0,
                    },
                    second: CM31 {
                        real: v.1 .0 .0,
                        imag: v.1 .1 .0,
                    },
                })
                .collect()
        },
        firstLayer: first_layer,
    };

    let composition_polynomial_to_solidity: Vec<Vec<u32>> = composition_polynomial
        .into_coordinate_polys()
        .iter()
        .map(|poly| {
            let mut layer = Vec::new();
            for coeff in &poly.coeffs.data {
                let coeff_as_u32: Vec<u32> = coeff.to_array().iter().map(|m| m.0).collect();
                layer.extend_from_slice(&coeff_as_u32);
            }
            layer
        })
        .collect();

    let comp_poly = CompositionPoly {
        coeffs0: composition_polynomial_to_solidity[0].clone(),
        coeffs1: composition_polynomial_to_solidity[1].clone(),
        coeffs2: composition_polynomial_to_solidity[2].clone(),
        coeffs3: composition_polynomial_to_solidity[3].clone(),
    };

    let queried_values: Vec<Vec<u32>> = proof
        .0
        .queried_values
        .iter()
        .map(|column| column.iter().map(|val| val.0).collect())
        .collect();

    Proof {
        config: sol_config,
        commitments,
        sampledValues: sampled_values,
        decommitments,
        queriedValues: queried_values,
        proofOfWork: proof.proof_of_work,
        friProof: fri_proof,
        compositionPoly: comp_poly,
    }
}

pub fn prepare_verification_params<C: FrameworkEval>(
    components: Vec<FrameworkComponent<C>>,
    n_preprocessed_columns: usize,
) -> Result<VerificationParams, Box<dyn std::error::Error>> {
    let mut component_params = Vec::new();
    for comp in &components {
        let info = ComponentInfo {
            maxConstraintLogDegreeBound: comp.max_constraint_log_degree_bound(),
            logSize: comp.log_size(),
            maskOffsets: comp
                .info
                .mask_offsets
                .0
                .iter()
                .map(|tree| {
                    tree.iter()
                        .map(|col| col.iter().map(|&offset| offset as i32).collect())
                        .collect()
                })
                .collect(),
            preprocessedColumns: comp
                .info
                .preprocessed_columns
                .iter()
                .enumerate()
                .map(|(idx, _)| U256::from(idx))
                .collect(),
        };
        let params = ComponentParams {
            logSize: info.logSize,
            claimedSum: QM31 {
                first: CM31 {
                    real: comp.claimed_sum().0 .0 .0,
                    imag: comp.claimed_sum().0 .1 .0,
                },
                second: CM31 {
                    real: comp.claimed_sum().1 .0 .0,
                    imag: comp.claimed_sum().1 .1 .0,
                },
            },
            info: info.clone(),
        };
        component_params.push(params);
    }

    let components_vec: Vec<&dyn Component> =
        components.iter().map(|c| c as &dyn Component).collect();

    let components = Components {
        components: components_vec,
        n_preprocessed_columns,
    };

    let verification_params = VerificationParams {
        componentParams: component_params.clone(),
        nPreprocessedColumns: U256::from(n_preprocessed_columns),
        componentsCompositionLogDegreeBound: components.composition_log_degree_bound(),
    };

    Ok(verification_params)
}
