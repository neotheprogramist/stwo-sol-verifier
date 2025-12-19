use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;

use stwo::core::ColumnVec;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval};

#[derive(Clone)]
pub struct FibonacciEval {
    pub log_n_rows: u32,
}

impl FrameworkEval for FibonacciEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_n_rows + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let a = eval.next_trace_mask(); // f(n-2)
        let b = eval.next_trace_mask(); // f(n-1)
        let c = eval.next_trace_mask(); // f(n)

        eval.add_constraint(c - (a + b));

        eval
    }
}

pub type FibonacciComponent = FrameworkComponent<FibonacciEval>;

/// Calculate the minimum log_size needed to compute f(target_n)
pub fn calculate_log_size(target_n: usize) -> u32 {
    let min_rows = target_n.saturating_sub(1).max(1);
    let log_size = (min_rows as f64).log2().ceil() as u32;
    log_size.max(2)
}

/// Generate trace for fibonacci sequence
pub fn gen_fibonacci_trace(
    target_n: usize,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    BaseField,
    u32,
) {
    let log_size = calculate_log_size(target_n);
    let n_rows = 1 << log_size;

    let mut col_a = Col::<SimdBackend, BaseField>::zeros(n_rows);
    let mut col_b = Col::<SimdBackend, BaseField>::zeros(n_rows);
    let mut col_c = Col::<SimdBackend, BaseField>::zeros(n_rows);

    let mut a = BaseField::from_u32_unchecked(0);
    let mut b = BaseField::from_u32_unchecked(1);
    let mut target_value = BaseField::from_u32_unchecked(0);

    let compute_rows = (target_n - 1).min(n_rows);

    for row in 0..compute_rows {
        let c = a + b;

        col_a.set(row, a);
        col_b.set(row, b);
        col_c.set(row, c);

        let current_index = row + 2;
        if current_index == target_n {
            target_value = c;
        }

        a = b;
        b = c;
    }

    let domain = CanonicCoset::new(log_size).circle_domain();

    let trace = vec![
        CircleEvaluation::new(domain, col_a),
        CircleEvaluation::new(domain, col_b),
        CircleEvaluation::new(domain, col_c),
    ];

    (trace, target_value, log_size)
}
