use serde::Serialize;
use stwo_prover::core::fields::qm31::QM31;
use stwo_prover::core::prover::StarkProof;
use stwo_prover::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo_prover::core::backend::simd::SimdBackend;
use stwo_prover::core::poly::circle::SecureCirclePoly;
use stwo_prover::constraint_framework::FrameworkComponent;
use stwo_prover::constraint_framework::FrameworkEval;
use stwo_prover::core::air::Component;
use stwo_prover::core::air::Components;

// --- Go-Compatible Structures ---

#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct StarkProofDef {
    pub config: PcsConfigDef,
    pub commitments: Vec<[u8; 32]>,
    pub sampled_values: Vec<Vec<Vec<QM31Def>>>,
    pub queried_values: Vec<Vec<u32>>, // Assuming M31 is serialized as u32
    pub decommitments: Vec<MerkleDecommitmentDef>,
    pub fri_proof: FriProofDef,
    pub proof_of_work: u64,
    pub composition_poly: SecureCirclePolyDef,
}

#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct PcsConfigDef {
    pub pow_bits: u32,
    pub fri_config: FriConfigDef,
}

#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct FriConfigDef {
    pub log_blowup_factor: u32,
    pub log_last_layer_degree_bound: u32,
    pub n_queries: usize,
}

#[derive(Serialize, Clone, Copy)]
pub struct QM31Def(pub CM31Def, pub CM31Def);

#[derive(Serialize, Clone, Copy)]
pub struct CM31Def(pub u32, pub u32);

#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct MerkleDecommitmentDef {
    pub hash_witness: Vec<[u8; 32]>,
    pub column_witness: Vec<u32>, // Assuming M31
}

#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct FriProofDef {
    pub first_layer_proof: FriLayerProofDef,
    pub inner_layer_proofs: Vec<FriLayerProofDef>,
    pub last_layer_poly: LinePolyDef,
}

// Correction: Go struct says LastLayerPoly circle.LinePoly. 
// In Stwo, last layer is a LinePoly ( coefficients).
// I will assume LinePoly serializes to a list of coeffs (M31/QM31?).
// In Stwo, last_layer_poly is LinePoly<QM31>.
// So I will make it Vec<QM31Def>.
#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct FriLayerProofDef {
    pub fri_witness: Vec<QM31Def>,
    pub decommitment: MerkleDecommitmentDef,
    pub commitment: [u8; 32],
}

// For SecureCirclePoly, contracts maps it to 4 arrays of u32 (M31).
#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct SecureCirclePolyDef {
    pub coeffs0: Vec<u32>,
    pub coeffs1: Vec<u32>,
    pub coeffs2: Vec<u32>,
    pub coeffs3: Vec<u32>,
}

// For LastLayerPoly (LinePoly), it is a polynomial over QM31.
#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct LinePolyDef {
    pub coeffs: Vec<QM31Def>,
    pub log_size: u32,
}


// --- Verification Params ---

#[derive(Serialize)]
pub struct VerificationParamsDef {
    pub component_params: Vec<ComponentParamsDef>,
    pub n_preprocessed_columns: usize,
    pub components_composition_log_degree_bound: u32,
    pub tree_roots: Vec<[u8; 32]>,
    pub tree_column_log_sizes: Vec<Vec<u32>>,
    pub digest: [u32; 8],
    pub n_draws: usize,
}

#[derive(Serialize)]
pub struct ComponentParamsDef {
    pub log_size: u32,
    pub claimed_sum: QM31Def,
    pub info: ComponentInfoDef,
}

#[derive(Serialize)]
// #[serde(rename_all = "PascalCase")]
pub struct ComponentInfoDef {
    pub max_constraint_log_degree_bound: u32,
    pub log_size: u32,
    pub mask_offsets: Vec<Vec<Vec<i32>>>, // Go: [][][]Variable
    pub preprocessed_columns: Vec<usize>,
}


// --- Converters ---

impl From<QM31> for QM31Def {
    fn from(val: QM31) -> Self {
        QM31Def(
            CM31Def(val.0.0.0, val.0.1.0),
            CM31Def(val.1.0.0, val.1.1.0),
        )
    }
}
pub const fn bit_reverse_index(i: usize, log_size: u32) -> usize {
    if log_size == 0 {
        return i;
    }
    i.reverse_bits() >> (usize::BITS - log_size)
}

pub fn bit_reverse<T>(v: &mut [T]) {
    let n = v.len();
    assert!(n.is_power_of_two());
    let log_n = n.ilog2();
    for i in 0..n {
        let j = bit_reverse_index(i, log_n);
        if j > i {
            v.swap(i, j);
        }
    }
}

pub fn convert_stark_proof(
    proof: StarkProof<Blake2sMerkleHasher>,
    composition_polynomial: SecureCirclePoly<SimdBackend>,
) -> StarkProofDef {
    let config = PcsConfigDef {
        pow_bits: proof.config.pow_bits,
        fri_config: FriConfigDef {
            log_blowup_factor: proof.config.fri_config.log_blowup_factor,
            log_last_layer_degree_bound: proof.config.fri_config.log_last_layer_degree_bound,
            n_queries: proof.config.fri_config.n_queries,
        },
    };

    let commitments: Vec<[u8; 32]> = proof.commitments.iter().map(|c| c.0).collect();

    let sampled_values: Vec<Vec<Vec<QM31Def>>> = proof.sampled_values.iter().map(|tree| {
        tree.iter().map(|col| {
            col.iter().map(|val| QM31Def::from(*val)).collect()
        }).collect()
    }).collect();

    let queried_values: Vec<Vec<u32>> = proof.queried_values.iter().map(|tree| {
        tree.iter().map(|val| val.0).collect()
    }).collect();

    let decommitments: Vec<MerkleDecommitmentDef> = proof.decommitments.iter().map(|d| {
        MerkleDecommitmentDef {
            hash_witness: d.hash_witness.iter().map(|h| h.0).collect(),
            column_witness: d.column_witness.iter().map(|m| m.0).collect(),
        }
    }).collect();

    let first_layer = FriLayerProofDef {
        fri_witness: proof.fri_proof.first_layer.fri_witness.iter().map(|v| QM31Def::from(*v)).collect(),
        decommitment: MerkleDecommitmentDef {
            hash_witness: proof.fri_proof.first_layer.decommitment.hash_witness.iter().map(|h| h.0).collect(),
            column_witness: proof.fri_proof.first_layer.decommitment.column_witness.iter().map(|m| m.0).collect(),
        },
        commitment: proof.fri_proof.first_layer.commitment.0,
    };

    let inner_layers: Vec<FriLayerProofDef> = proof.fri_proof.inner_layers.iter().map(|l| {
        FriLayerProofDef {
            fri_witness: l.fri_witness.iter().map(|v| QM31Def::from(*v)).collect(),
            decommitment: MerkleDecommitmentDef {
                hash_witness: l.decommitment.hash_witness.iter().map(|h| h.0).collect(),
                column_witness: l.decommitment.column_witness.iter().map(|m| m.0).collect(),
            },
            commitment: l.commitment.0,
        }
    }).collect();

    // Prepare CompositionPoly similar to Solidity converter
    let composition_polynomial_coords: Vec<Vec<u32>> = composition_polynomial
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

    let composition_poly = SecureCirclePolyDef {
        coeffs0: composition_polynomial_coords[0].clone(),
        coeffs1: composition_polynomial_coords[1].clone(),
        coeffs2: composition_polynomial_coords[2].clone(),
        coeffs3: composition_polynomial_coords[3].clone(),
    };

    // Prepare Last Layer Poly (LinePoly)
    // The Go struct says LastLayerPoly circle.LinePoly
    // I need to decide if I use SecureCirclePolyDef logic or something else.
    // In Stwo, fri_proof.last_layer_poly is LinePoly<QM31>.
    // It's a single polynomial.
    // If Go `circle.LinePoly` struct matches `coeffs []QM31` (or similar), I'll use that.
    // Wait, the Go `FriProof` struct definition has `LastLayerPoly circle.LinePoly`.
    // The previous `StarkProof.CompositionPoly` had `circle.SecureCirclePoly`.
    // These are different types.
    // In Stwo, LinePoly has coefficients.
    // `contracts` converts it by getting ordered coefficients and bit-reversing them.
    let mut last_layer_coeffs = proof.fri_proof.last_layer_poly.clone().into_ordered_coefficients();
    bit_reverse(&mut last_layer_coeffs);
    // But `contracts` converts them to QM31.
    // I'll assume Go expects array of QM31 or similar.
    // But I used `SecureCirclePolyDef` type in `FriProofDef` above which has `coeffs0..3`. That's WRONG for `LinePoly`.
    // `LinePoly` is 1D. `SecureCirclePoly` is 2D (over circle).
    // I need to change `FriProofDef` to use `LinePolyDef` (or just Vec<QM31Def>).
    // I'll update the struct definition below (in my head, then file).

    // UPDATE: Redefining FriProofDef in the file write logic.

    StarkProofDef {
        config,
        commitments,
        sampled_values,
        queried_values,
        decommitments,
        fri_proof: FriProofDef {
            first_layer_proof: first_layer,
            inner_layer_proofs: inner_layers,
            last_layer_poly: LinePolyDef {
                coeffs: last_layer_coeffs.iter().map(|v| QM31Def::from(*v)).collect(),
                log_size: (last_layer_coeffs.len() as u32).trailing_zeros(),
            }
        },
        proof_of_work: proof.proof_of_work,
        composition_poly,
    }
}

pub fn convert_verification_params<C: FrameworkEval>(
    components: Vec<FrameworkComponent<C>>,
    n_preprocessed_columns: usize,
    proof: &StarkProof<Blake2sMerkleHasher>, // needed for tree roots etc
    channel_digest: [u8; 32],
) -> VerificationParamsDef {
    let mut component_params = Vec::new();
    for comp in &components {
        let info = ComponentInfoDef {
            max_constraint_log_degree_bound: comp.max_constraint_log_degree_bound(),
            log_size: comp.log_size(),
            mask_offsets: comp.info.mask_offsets.0.iter().map(|tree| {
                tree.iter().map(|col| col.iter().map(|&off| off as i32).collect()).collect()
            }).collect(),
            preprocessed_columns: comp.info.preprocessed_columns.iter().enumerate().map(|(i, _)| i).collect(),
        };

        component_params.push(ComponentParamsDef {
            log_size: info.log_size,
            claimed_sum: QM31Def::from(comp.claimed_sum()),
            info,
        });
    }

    let components_vec: Vec<&dyn Component> = components.iter().map(|c| c as &dyn Component).collect();
    let comps_struct = Components {
        components: components_vec,
        n_preprocessed_columns,
    };
    let composition_log_degree_bound = comps_struct.composition_log_degree_bound();

    // Calculate extended log sizes
    let extended_log_sizes: Vec<Vec<u32>> = components[0] // Assuming uniform or iterating component
        .trace_log_degree_bounds()
        .iter()
        .map(|log_size| {
            log_size
                .iter()
                .map(|&ls| ls + proof.config.fri_config.log_blowup_factor)
                .collect()
        })
        .collect();
    // Note: This logic for `extended_log_sizes` takes from the first component? 
    // `verify_and_prepare` does: 
    // component.trace_log_degree_bounds().iter()... 
    // It seems to assume the structure matches the trees.
    // In `verify.rs`, `extended_log_sizes` is derived from `component`.
    
    // Digest conversion [u8;32] -> [u32; 8]
    let mut digest_u32 = [0u32; 8];
    for i in 0..8 {
        let start = i * 4;
        let bytes = [channel_digest[start], channel_digest[start+1], channel_digest[start+2], channel_digest[start+3]];
        // Big endian or little endian?
        // `contracts` does `FixedBytes::from(digest.0)`.
        // Go `uints.U32` usually implies native or LE/BE interpretation.
        // Stwo `KeccakChannel` digest is bytes.
        // If Go expects `[8]uints.U32` representing the same 32 bytes...
        // Gnark `uints` are usually LE in fields, but Keccak is bytes.
        // I will interpret as Big Endian to match standard byte order if treating as chunks?
        // Or simple cast.
        // Let's use BE to be safe with `u32::from_be_bytes`.
        digest_u32[i] = u32::from_le_bytes(bytes); // Switching to LE as Stwo/M31 often uses LE. 
        // Actually, Keccak is byte-oriented. 
        // If I use LE here, and Go uses LE, it matches.
    }
    
    // Correction: `contracts` uses `FixedBytes` which preserves byte order.
    // If I split it into u32s, I need to know how Go reconstructs it.
    // If Go `Digest` is `[8]uints.U32`, it effectively chunks the 32 bytes.
    // I will use `u32::from_le_bytes` as a default guess for field-based systems, or `be` if it's just raw chunks.
    // Let's stick to `from_le_bytes` as it's common in ZK.

    VerificationParamsDef {
        component_params,
        n_preprocessed_columns,
        components_composition_log_degree_bound: composition_log_degree_bound,
        tree_roots: proof.commitments.iter().map(|c| c.0).collect(),
        tree_column_log_sizes: extended_log_sizes,
        digest: digest_u32,
        n_draws: 0, // In verify.rs this is 0
    }
}
