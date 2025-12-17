// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./PointEvaluatorLib.sol";
import "../core/CirclePoint.sol";

/// @title IFrameworkEval
/// @dev Provides the core evaluation interface for AIR components
interface IFrameworkEval {
    // Core FrameworkEval Interface (matching Rust trait)

    /// @notice Get the log size of the trace
    /// @return logSize Log2 of the number of rows in the trace
    function logSize() external view returns (uint32 logSize);

    /// @notice Get the maximum constraint log degree bound
    /// @return maxLogDegreeBound Maximum log degree bound for constraints
    function maxConstraintLogDegreeBound() external view returns (uint32 maxLogDegreeBound);

    /// @notice Evaluate constraints using the provided evaluator
    /// @param eval Evaluator implementing IEvalAtRow for constraint evaluation
    /// @return updatedEval The evaluator after constraint evaluation
    function evaluate(PointEvaluatorLib.PointEvaluator memory eval) external returns (PointEvaluatorLib.PointEvaluator memory updatedEval);


}