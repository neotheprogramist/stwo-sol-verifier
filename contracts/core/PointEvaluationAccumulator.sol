// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../fields/QM31Field.sol";
/// @title PointEvaluationAccumulator
/// @notice Accumulator for random linear combination of polynomial evaluations
library PointEvaluationAccumulator {
    using QM31Field for QM31Field.QM31;

    /// @param randomCoeff Random coefficient (alpha) for linear combination
    /// @param accumulation Current accumulated value
    struct Accumulator {
        QM31Field.QM31 randomCoeff;  // α
        QM31Field.QM31 accumulation; // Current sum
    }

    /// @notice Create new accumulator with random coefficient
    /// @param randomCoeff Random coefficient drawn from channel
    /// @return accumulator Initialized accumulator
    function newAccumulator(QM31Field.QM31 memory randomCoeff) 
        internal 
        pure 
        returns (Accumulator memory accumulator) 
    {
        accumulator = Accumulator({
            randomCoeff: randomCoeff,
            accumulation: QM31Field.zero()
        });
    }

    /// @notice Accumulate evaluation using Horner's method
    /// @dev Formula: accumulation = accumulation * random_coeff + evaluation
    /// @param accumulator Current accumulator state
    /// @param evaluation Polynomial evaluation to accumulate
    /// @return updatedAccumulator Updated accumulator
    function accumulate(
        Accumulator memory accumulator, 
        QM31Field.QM31 memory evaluation
    ) internal pure returns (Accumulator memory updatedAccumulator) {
        // Rust formula: self.accumulation = self.accumulation * self.random_coeff + evaluation;
        QM31Field.QM31 memory mulResult = QM31Field.mul(accumulator.accumulation, accumulator.randomCoeff);
        accumulator.accumulation = QM31Field.add(mulResult, evaluation);
        
        return accumulator;
    }

    /// @notice Finalize accumulator and return result
    /// @param accumulator Final accumulator state
    /// @return result Final accumulated value
    function finalize(Accumulator memory accumulator) 
        internal 
        pure 
        returns (QM31Field.QM31 memory result) 
    {
        return accumulator.accumulation;
    }

    /// @notice Direct computation for comparison (Horner's method)
    /// @param evaluations Array of evaluations to combine
    /// @param alpha Random coefficient
    /// @return result Combined evaluation
    function directComputation(
        QM31Field.QM31[] memory evaluations,
        QM31Field.QM31 memory alpha
    ) internal pure returns (QM31Field.QM31 memory result) {
        result = QM31Field.zero();
        
        for (uint256 i = 0; i < evaluations.length; i++) {
            // res = res * alpha + evaluation
            result = QM31Field.add(
                QM31Field.mul(result, alpha),
                evaluations[i]
            );
        }
    }

    /// @notice Convert M31 to QM31 (SecureField)
    /// @dev Helper for test compatibility with Rust
    /// @param value M31 value as uint32
    /// @return qm31Value QM31 representation
    function m31ToQM31(uint32 value) 
        internal 
        pure 
        returns (QM31Field.QM31 memory qm31Value) 
    {
        return QM31Field.fromM31(value, 0, 0, 0);
    }

    /// @notice Convert array of M31 to QM31
    /// @param m31Values Array of M31 values as uint32
    /// @return qm31Values Array of QM31 values
    function m31ArrayToQM31Array(uint32[] memory m31Values)
        internal
        pure
        returns (QM31Field.QM31[] memory qm31Values)
    {
        qm31Values = new QM31Field.QM31[](m31Values.length);
        for (uint256 i = 0; i < m31Values.length; i++) {
            qm31Values[i] = m31ToQM31(m31Values[i]);
        }
    }
}