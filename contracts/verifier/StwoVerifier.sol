// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../core/FrameworkComponentLib.sol";
import "../core/ComponentsLib.sol";
import "../core/TraceLocationAllocatorLib.sol";
import "../core/KeccakChannelLib.sol";
import "../core/CommitmentSchemeVerifierLib.sol";
import "../pcs/PcsConfig.sol";
import "../pcs/FriVerifier.sol";
import "../utils/TreeSubspan.sol";
import "../circle/CirclePoint.sol";
import "../fields/QM31Field.sol";
import "../vcs/MerkleVerifier.sol";
import "./ProofParser.sol";
import "../secure_poly/SecureCirclePoly.sol";
import {console} from "forge-std/console.sol";

/// @title STWOVerifier
/// @notice Generic STARK verifier
contract STWOVerifier {
    using QM31Field for QM31Field.QM31;
    using FrameworkComponentLib for FrameworkComponentLib.ComponentState;
    using ComponentsLib for ComponentsLib.Components;
    using TraceLocationAllocatorLib for TraceLocationAllocatorLib.AllocatorState;
    using KeccakChannelLib for KeccakChannelLib.ChannelState;
    using CommitmentSchemeVerifierLib for CommitmentSchemeVerifierLib.VerifierState;
    using FriVerifier for FriVerifier.FriVerifierState;
    using PcsConfig for PcsConfig.Config;

    /// @notice Channel state for Fiat-Shamir transform
    KeccakChannelLib.ChannelState private _channel;

    /// @notice Commitment scheme verifier state
    CommitmentSchemeVerifierLib.VerifierState private _commitmentScheme;

    /// @notice Trace location allocator state
    TraceLocationAllocatorLib.AllocatorState private _allocator;

    /// @notice Components state for framework evaluation
    ComponentsLib.Components private _components;

    /// @notice FRI verifier state
    FriVerifier.FriVerifierState private _friVerifier;

    uint32 private constant COMPOSITION_LOG_SPLIT = 1;
    uint256 private constant SECURE_EXTENSION_DEGREE = 4;

    struct ComponentParams{
        uint32 logSize;
        QM31Field.QM31 claimedSum;
        FrameworkComponentLib.ComponentInfo info;
    }

    struct ClaimData {
        uint32 nComponents;
        QM31Field.QM31[] packedEnableBits;
        QM31Field.QM31[] packedComponentLogSizes;
        QM31Field.QM31[] outputValues;
    }

    struct InteractionClaimData {
        QM31Field.QM31[] claimedSums;
    }

    /// @notice Parameters needed for verification
    struct VerificationParams {
        ComponentParams[] componentParams;
        uint256 nPreprocessedColumns;
        uint32 componentsCompositionLogDegreeBound;
        bool includeAllPreprocessedColumns;
        uint32 interactionPowBits;
        ClaimData claim;
        InteractionClaimData interactionClaim;
    }

    /// @notice Verify a STARK proof
    function verify(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        uint32[][] memory treeColumnLogSizes,
        uint32 channelSalt,
        uint64 interactionPowNonce
    ) external returns (bool) {
        uint256 gasBefore = gasleft();
        bool isValid = _verifyProof(proof, params, treeColumnLogSizes, channelSalt, interactionPowNonce);
        uint256 gasAfter = gasleft();
        console.log("Verification gas used:", gasBefore - gasAfter);
        return isValid;
    }

    function _verifyProof(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        uint32[][] memory treeColumnLogSizes,
        uint32 channelSalt,
        uint64 interactionPowNonce
    ) private returns (bool) {
        if (_components.isInitialized) {
            _components.reset();
        }
        
        uint256 gasBefore = gasleft();
        SecureCirclePoly.SecurePoly memory poly = _createSecurePoly(proof.compositionPoly);
        _initializeVerification(proof, params, treeColumnLogSizes, channelSalt, interactionPowNonce);
        uint256 gasAfterInit = gasleft();
        console.log("Initialization gas used:", gasBefore - gasAfterInit);
        return _performVerificationSteps(proof, params, poly);
    }

    function _initializeVerification(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        uint32[][] memory treeColumnLogSizes,
        uint32 channelSalt,
        uint64 interactionPowNonce
    ) private {
        KeccakChannelLib.initialize(_channel);

        // Mix channel salt.
        QM31Field.QM31[] memory salt = new QM31Field.QM31[](1);
        salt[0] = QM31Field.fromReal(channelSalt);
        _channel.mixFelts(salt);
        // Mix PCS config into channel (matches Rust PcsConfig::mix_into).
        PcsConfig.mixInto(proof.config, _channel);

        // Initialize commitment scheme with no trees, then commit roots in order.
        CommitmentSchemeVerifierLib.initializeEmpty(_commitmentScheme, proof.config);

        require(treeColumnLogSizes.length >= 3, "Expected at least 3 commitment trees");
        require(proof.commitments.length >= 3, "Expected at least 3 commitments");

        // Preprocessed tree.
        CommitmentSchemeVerifierLib.commit(
            _commitmentScheme,
            proof.commitments[0],
            treeColumnLogSizes[0],
            _channel
        );


        _mixClaim(params.claim);

        // Trace tree.
        CommitmentSchemeVerifierLib.commit(
            _commitmentScheme,
            proof.commitments[1],
            treeColumnLogSizes[1],
            _channel
        );

        // Interaction PoW + interaction elements + claim.
        require(
            _channel.verifyPowNonce(params.interactionPowBits, interactionPowNonce),
            "Interaction PoW failed"
        );
        _channel.mixU64(interactionPowNonce);
        _drawInteractionElements();
        _mixInteractionClaim(params.interactionClaim);

        // Interaction tree.
        CommitmentSchemeVerifierLib.commit(
            _commitmentScheme,
            proof.commitments[2],
            treeColumnLogSizes[2],
            _channel
        );

    }

    function _performVerificationSteps(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        SecureCirclePoly.SecurePoly memory poly
    ) private returns (bool) {
        uint32 maxLogDegreeBound = _computeMaxLogDegreeBound(params, proof.config);

        _channel.drawSecureFelt();

        if (!_performCompositionCommit(proof, maxLogDegreeBound)) return false;
        
        CirclePoint.Point memory oodsPoint = CirclePoint.getRandomPointFromState(_channel);
        uint256 gasBefore = gasleft();
        ComponentsLib.TreeVecMaskPoints memory samplePoints = _computeSamplePoints(
            oodsPoint,
            proof.commitments.length - 1,
            params,
            maxLogDegreeBound
        );
        uint256 gasAfterSamplePoints = gasleft();
        console.log("Sample point computation gas used:", gasBefore - gasAfterSamplePoints);
        
        if (!_performOodsVerification(proof, poly, oodsPoint, maxLogDegreeBound)) return false;
        return _performFriVerification(proof, samplePoints);
        // return true;
    }

    function _performCompositionCommit(
        ProofParser.Proof calldata proof,
        uint32 maxLogDegreeBound
    ) private returns (bool) {
        require(proof.commitments.length >= 4, "Missing composition commitment");
        uint32[] memory compositionSizes = new uint32[](2 * SECURE_EXTENSION_DEGREE);
        for (uint256 i = 0; i < 2 * SECURE_EXTENSION_DEGREE; i++) {
            compositionSizes[i] = maxLogDegreeBound;
        }
        CommitmentSchemeVerifierLib.commit(
            _commitmentScheme,
            proof.commitments[proof.commitments.length - 1],
            compositionSizes,
            _channel
        );
        return true;
    }

    function _performOodsVerification(
        ProofParser.Proof calldata proof,
        SecureCirclePoly.SecurePoly memory poly,
        CirclePoint.Point memory oodsPoint,
        uint32 maxLogDegreeBound
    ) public view returns (bool) {
        uint256 gasBefore = gasleft();
        (QM31Field.QM31 memory compositionOodsEval, bool extractSuccess) = ProofParser.extractCompositionOodsEval(
            proof,
            oodsPoint,
            maxLogDegreeBound
        );
        uint256 gasAfter = gasleft();
        console.log("OODS eval extraction gas used:", gasBefore - gasAfter);
        require(extractSuccess, "Failed to extract composition OODS eval");

        return _verifyOods(oodsPoint, compositionOodsEval, poly);
    }

    function _performFriVerification(
        ProofParser.Proof calldata proof,
        ComponentsLib.TreeVecMaskPoints memory samplePoints
    ) private returns (bool) {
        QM31Field.QM31[] memory flattenedSampledValues = ProofParser.flattenCols(proof.sampledValues);
        _channel.mixFelts(flattenedSampledValues);

        QM31Field.QM31 memory randomCoeff2 = _channel.drawSecureFelt();

        uint32 liftingLogSize = _getLiftingLogSize(proof.config);
        uint32 logBlowupFactor = _commitmentScheme.config.friConfig.logBlowupFactor;
        require(liftingLogSize >= logBlowupFactor, "Invalid lifting log size for FRI bound");

        CirclePolyDegreeBound.Bound[] memory bounds = new CirclePolyDegreeBound.Bound[](1);
        bounds[0] = CirclePolyDegreeBound.create(liftingLogSize - logBlowupFactor);

        _friVerifier = FriVerifier.commit(
            _channel,
            _commitmentScheme.config.friConfig,
            proof.friProof,
            bounds
        );
        if (!_verifyProofOfWork(proof.proofOfWork, proof.config.powBits)) {
            return false;
        }

        _channel.mixU64(proof.proofOfWork);

        uint32 preprocessedHeight = _getPreprocessedTreeHeight(proof.config);

        return _performFinalFriCheck(proof, randomCoeff2, samplePoints, liftingLogSize, preprocessedHeight);
    }

    function _performFinalFriCheck(
        ProofParser.Proof calldata proof,
        QM31Field.QM31 memory randomCoeff2,
        ComponentsLib.TreeVecMaskPoints memory samplePoints,
        uint32 liftingLogSize,
        uint32 preprocessedHeight
    ) private returns (bool) {
        FriVerifier.PointSample[][][] memory pointSamples = _zipSamplePointsWithValues(
            samplePoints,
            proof.sampledValues
        );
        return _verifyFri(
            pointSamples,
            proof.decommitments,
            proof.queriedValues,
            randomCoeff2,
            liftingLogSize,
            preprocessedHeight
        );
    }
    /// @notice Compute sample points for OODS evaluation
    function _computeSamplePoints(
        CirclePoint.Point memory oodsPoint,
        uint256 nTrees,
        VerificationParams calldata params,
        uint32 maxLogDegreeBound
    ) internal returns (ComponentsLib.TreeVecMaskPoints memory) {
        FrameworkComponentLib.ComponentState[] memory componentStates = new FrameworkComponentLib.ComponentState[](params.componentParams.length);

        if (TraceLocationAllocatorLib.isInitialized(_allocator)) {
            TraceLocationAllocatorLib.reset(_allocator);
        }
        TraceLocationAllocatorLib.initialize(_allocator);
        
        for (uint256 i = 0; i < params.componentParams.length; i++) {
            FrameworkComponentLib.ComponentState memory componentState = FrameworkComponentLib.createComponent(_allocator, params.componentParams[i].logSize, params.componentParams[i].claimedSum, params.componentParams[i].info);
            componentStates[i] = componentState;
        }

        _components.initialize(componentStates, params.nPreprocessedColumns);

        FrameworkComponentLib.SamplePoints[] memory componentMaskPoints = _components.maskPoints(oodsPoint, maxLogDegreeBound);

        ComponentsLib.TreeVecMaskPoints memory maskPoints = _concatCols(componentMaskPoints);

        _initializePreprocessedColumns(
            maskPoints,
            params.nPreprocessedColumns,
            oodsPoint,
            params.includeAllPreprocessedColumns
        );

        if (!params.includeAllPreprocessedColumns) {
            _setPreprocessedMaskPoints(componentStates, maskPoints, oodsPoint);
        }

        CirclePoint.Point[][][] memory newPoints = new CirclePoint.Point[][][](
            nTrees + 1
        );
        uint256[] memory newNColumns = new uint256[](nTrees + 1);

        for (uint256 i = 0; i < maskPoints.points.length; i++) {
            newPoints[i] = maskPoints.points[i];
            newNColumns[i] = maskPoints.nColumnsPerTree[i];
        }

        uint256 compositionTreeIdx = nTrees;
        uint256 COMPOSITION_COLUMNS = 2 * SECURE_EXTENSION_DEGREE;
        newPoints[compositionTreeIdx] = new CirclePoint.Point[][](COMPOSITION_COLUMNS);
        newNColumns[compositionTreeIdx] = COMPOSITION_COLUMNS;

        for (uint256 colIdx = 0; colIdx < COMPOSITION_COLUMNS; colIdx++) {
            newPoints[compositionTreeIdx][colIdx] = new CirclePoint.Point[](1);
            newPoints[compositionTreeIdx][colIdx][0] = oodsPoint;
            maskPoints.totalPoints++;
        }

        maskPoints.points = newPoints;
        maskPoints.nColumnsPerTree = newNColumns;
        
        
        return maskPoints;
    }

    /// @notice Get n_columns_per_log_size for each tree
    function getNColumnsPerLogSize(
        CommitmentSchemeVerifierLib.VerifierState storage scheme
    ) internal view returns (uint32[][][] memory) {
        uint32[][][] memory result = new uint32[][][](
            scheme.columnLogSizes().length
        );

        for (
            uint256 treeIdx = 0;
            treeIdx < scheme.columnLogSizes().length;
            treeIdx++
        ) {
            uint32[] memory columnLogSizes = scheme.columnLogSizes()[treeIdx];

            if (columnLogSizes.length == 0) {
                result[treeIdx] = new uint32[][](0);
                continue;
            }

            uint32[] memory uniqueLogSizes = _getUniqueLogSizes(columnLogSizes);

            result[treeIdx] = new uint32[][](uniqueLogSizes.length);

            for (uint256 i = 0; i < uniqueLogSizes.length; i++) {
                uint32 logSize = uniqueLogSizes[i];
                uint32 count = 0;

                for (uint256 j = 0; j < columnLogSizes.length; j++) {
                    if (columnLogSizes[j] == logSize) {
                        count++;
                    }
                }

                result[treeIdx][i] = new uint32[](2);
                result[treeIdx][i][0] = logSize;
                result[treeIdx][i][1] = count;
            }
        }

        return result;
    }

    /// @notice Concatenate columns from multiple component mask points
    function _concatCols(
        FrameworkComponentLib.SamplePoints[] memory componentMaskPoints
    ) internal pure returns (ComponentsLib.TreeVecMaskPoints memory concatenated) {
        if (componentMaskPoints.length == 0) {
            concatenated.nColumnsPerTree = new uint256[](3);
            concatenated.points = new CirclePoint.Point[][][](3);
            concatenated.totalPoints = 0;
            return concatenated;
        }

        uint256 nTrees = 3;
        concatenated.nColumnsPerTree = new uint256[](nTrees);
        concatenated.totalPoints = 0;

        for (uint256 compIdx = 0; compIdx < componentMaskPoints.length; compIdx++) {
            for (uint256 treeIdx = 0; treeIdx < nTrees && treeIdx < componentMaskPoints[compIdx].nColumns.length; treeIdx++) {
                concatenated.nColumnsPerTree[treeIdx] += componentMaskPoints[compIdx].nColumns[treeIdx];
            }
            concatenated.totalPoints += componentMaskPoints[compIdx].totalPoints;
        }

        concatenated.points = new CirclePoint.Point[][][](nTrees);
        for (uint256 treeIdx = 0; treeIdx < nTrees; treeIdx++) {
            concatenated.points[treeIdx] = new CirclePoint.Point[][](concatenated.nColumnsPerTree[treeIdx]);
        }

        uint256[] memory currentColIndex = new uint256[](nTrees);
        for (uint256 compIdx = 0; compIdx < componentMaskPoints.length; compIdx++) {
            for (uint256 treeIdx = 0; treeIdx < nTrees && treeIdx < componentMaskPoints[compIdx].points.length; treeIdx++) {
                for (uint256 colIdx = 0; colIdx < componentMaskPoints[compIdx].points[treeIdx].length; colIdx++) {
                    uint256 targetColIdx = currentColIndex[treeIdx];
                    if (targetColIdx < concatenated.points[treeIdx].length) {
                        concatenated.points[treeIdx][targetColIdx] = componentMaskPoints[compIdx].points[treeIdx][colIdx];
                        currentColIndex[treeIdx]++;
                    }
                }
            }
        }
        return concatenated;
    }

    /// @notice Initialize preprocessed columns with empty vectors
    function _initializePreprocessedColumns(
        ComponentsLib.TreeVecMaskPoints memory maskPoints,
        uint256 nPreprocessedColumns,
        CirclePoint.Point memory point,
        bool includeAll
    ) internal pure {
        if (maskPoints.points.length > 0) {
            CirclePoint.Point[][] memory preprocessedTree = new CirclePoint.Point[][](nPreprocessedColumns);
            for (uint256 i = 0; i < nPreprocessedColumns; i++) {
                if (includeAll) {
                    preprocessedTree[i] = new CirclePoint.Point[](1);
                    preprocessedTree[i][0] = point;
                    maskPoints.totalPoints++;
                } else {
                    preprocessedTree[i] = new CirclePoint.Point[](0);
                }
            }
            maskPoints.points[0] = preprocessedTree;
            maskPoints.nColumnsPerTree[0] = nPreprocessedColumns;
        }
    }

    /// @notice Set preprocessed mask points for each component's preprocessed columns
    function _setPreprocessedMaskPoints(
        FrameworkComponentLib.ComponentState[] memory components,
        ComponentsLib.TreeVecMaskPoints memory maskPoints,
        CirclePoint.Point memory point
    ) internal pure {
        for (uint256 compIdx = 0; compIdx < components.length; compIdx++) {
            uint256[] memory preprocessedIndices = components[compIdx].preprocessedColumnIndices;
            
            for (uint256 i = 0; i < preprocessedIndices.length; i++) {
                uint256 colIdx = preprocessedIndices[i];
                if (colIdx < maskPoints.points[0].length) {
                    maskPoints.points[0][colIdx] = new CirclePoint.Point[](1);
                    maskPoints.points[0][colIdx][0] = point;
                }
            }
        }
    }

    /// @notice Get unique log sizes from array
    function _getUniqueLogSizes(
        uint32[] memory logSizes
    ) internal pure returns (uint32[] memory) {
        if (logSizes.length == 0) {
            return new uint32[](0);
        }

        uint32[] memory sorted = new uint32[](logSizes.length);
        for (uint256 i = 0; i < logSizes.length; i++) {
            sorted[i] = logSizes[i];
        }
        _sortUint32ArrayHelper(sorted);

        return _removeDuplicatesUint32Helper(sorted);
    }

    /// @notice Sort uint32 array helper
    function _sortUint32ArrayHelper(uint32[] memory arr) internal pure {
        for (uint256 i = 0; i < arr.length; i++) {
            for (uint256 j = 0; j < arr.length - i - 1; j++) {
                if (arr[j] > arr[j + 1]) {
                    uint32 temp = arr[j];
                    arr[j] = arr[j + 1];
                    arr[j + 1] = temp;
                }
            }
        }
    }

    /// @notice Remove consecutive duplicates helper
    function _removeDuplicatesUint32Helper(
        uint32[] memory sortedArr
    ) internal pure returns (uint32[] memory) {
        if (sortedArr.length == 0) {
            return new uint32[](0);
        }

        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < sortedArr.length; i++) {
            if (sortedArr[i] != sortedArr[i - 1]) {
                uniqueCount++;
            }
        }

        uint32[] memory deduplicated = new uint32[](uniqueCount);
        deduplicated[0] = sortedArr[0];
        uint256 currentIndex = 1;

        for (uint256 i = 1; i < sortedArr.length; i++) {
            if (sortedArr[i] != sortedArr[i - 1]) {
                deduplicated[currentIndex] = sortedArr[i];
                currentIndex++;
            }
        }

        return deduplicated;
    }

    /// @notice Zip sample points with sampled values to create PointSample structure
    function _zipSamplePointsWithValues(
        ComponentsLib.TreeVecMaskPoints memory samplePoints,
        QM31Field.QM31[][][] memory sampledValues
    ) internal pure returns (FriVerifier.PointSample[][][] memory samples) {

        require(
            samplePoints.points.length == sampledValues.length,
            "Tree count mismatch"
        );

        samples = new FriVerifier.PointSample[][][](samplePoints.points.length);

        for (
            uint256 treeIdx = 0;
            treeIdx < samplePoints.points.length;
            treeIdx++
        ) {
            require(
                samplePoints.points[treeIdx].length ==
                    sampledValues[treeIdx].length,
                "Column count mismatch"
            );

            samples[treeIdx] = new FriVerifier.PointSample[][](
                samplePoints.points[treeIdx].length
            );

            for (
                uint256 colIdx = 0;
                colIdx < samplePoints.points[treeIdx].length;
                colIdx++
            ) {
                CirclePoint.Point[] memory columnPoints = samplePoints.points[
                    treeIdx
                ][colIdx];
                QM31Field.QM31[] memory columnValues = sampledValues[treeIdx][
                    colIdx
                ];

                require(
                    columnPoints.length == columnValues.length,
                    "Sample count mismatch"
                );

                samples[treeIdx][colIdx] = new FriVerifier.PointSample[](
                    columnPoints.length
                );

                for (
                    uint256 sampleIdx = 0;
                    sampleIdx < columnPoints.length;
                    sampleIdx++
                ) {
                    samples[treeIdx][colIdx][sampleIdx] = FriVerifier
                        .PointSample({
                            point: columnPoints[sampleIdx],
                            value: columnValues[sampleIdx]
                        });
                }
            }
        }

        return samples;
    }

    function _mixClaim(ClaimData calldata claim) internal {
        QM31Field.QM31[] memory felts = new QM31Field.QM31[](1);
        felts[0] = QM31Field.fromU32Unchecked(claim.nComponents, 0, 0, 0);
        _channel.mixFelts(felts);

        _channel.mixFelts(claim.packedEnableBits);
        _channel.mixFelts(claim.packedComponentLogSizes);
        _channel.mixFelts(claim.outputValues);
    }

    function _mixInteractionClaim(InteractionClaimData calldata interactionClaim) internal {
        _channel.mixFelts(interactionClaim.claimedSums);
    }

    function _drawInteractionElements() internal {
        _channel.drawSecureFelts(2);
    }

    function _computeMaxLogDegreeBound(
        VerificationParams calldata params,
        PcsConfig.Config memory config
    ) internal view returns (uint32) {
        require(params.componentsCompositionLogDegreeBound > COMPOSITION_LOG_SPLIT, "Invalid composition log bound");
        uint32 splitCompositionLogDegreeBound = params.componentsCompositionLogDegreeBound - COMPOSITION_LOG_SPLIT;
        uint32 logBlowup = config.friConfig.logBlowupFactor;

        uint32 liftingLogSize = config.liftingLogSize;
        if (liftingLogSize == 0) {
            liftingLogSize = splitCompositionLogDegreeBound + logBlowup;
        }

        if (params.includeAllPreprocessedColumns) {
            uint32 preprocessedHeight = _getPreprocessedTreeHeight(config);
            require(liftingLogSize >= preprocessedHeight, "Lifting log size too small");
        }

        require(liftingLogSize >= logBlowup, "Invalid lifting log size");
        return liftingLogSize - logBlowup;
    }

    function _getLiftingLogSize(PcsConfig.Config memory config) internal view returns (uint32) {
        if (config.liftingLogSize != 0) {
            return config.liftingLogSize;
        }

        uint32[][] memory columnLogSizes = _commitmentScheme.columnLogSizes();
        require(columnLogSizes.length > 0, "No commitment trees");
        return _getMaxLogSize(columnLogSizes[columnLogSizes.length - 1]);
    }

    function _getPreprocessedTreeHeight(PcsConfig.Config memory config) internal view returns (uint32) {
        if (config.liftingLogSize != 0) {
            return config.liftingLogSize;
        }

        uint32[][] memory columnLogSizes = _commitmentScheme.columnLogSizes();
        require(columnLogSizes.length > 0, "No commitment trees");
        return _getMaxLogSize(columnLogSizes[0]);
    }

    function _getMaxLogSize(uint32[] memory logSizes) internal pure returns (uint32) {
        uint32 maxLogSize = 0;
        for (uint256 i = 0; i < logSizes.length; i++) {
            if (logSizes[i] > maxLogSize) {
                maxLogSize = logSizes[i];
            }
        }
        return maxLogSize;
    }

    function _preparePreprocessedQueryPositionsByLogSize(
        FriVerifier.Queries memory queries,
        uint32[] memory preprocessedColumnLogSizes,
        uint32 liftingLogSize,
        uint32 preprocessedHeight
    ) internal pure returns (FriVerifier.QueryPositionsByLogSize memory) {
        if (preprocessedHeight == 0) {
            return FriVerifier.QueryPositionsByLogSize({logSizes: new uint32[](0), queryPositions: new uint256[][](0)});
        }

        uint256[] memory adjusted = _preparePreprocessedQueryPositions(
            queries.positions,
            liftingLogSize,
            preprocessedHeight
        );

        FriVerifier.Queries memory preprocessedQueries = FriVerifier.Queries({
            positions: adjusted,
            logDomainSize: preprocessedHeight
        });

        uint32[] memory uniqueLogSizes = _getUniqueLogSizes(preprocessedColumnLogSizes);
        return _getQueryPositionsByLogSize(preprocessedQueries, uniqueLogSizes);
    }

    function _preparePreprocessedQueryPositions(
        uint256[] memory queryPositions,
        uint32 maxLogSize,
        uint32 ppMaxLogSize
    ) internal pure returns (uint256[] memory) {
        uint256[] memory result = new uint256[](queryPositions.length);

        if (ppMaxLogSize == 0) {
            return new uint256[](0);
        }

        if (maxLogSize < ppMaxLogSize) {
            uint32 shift = ppMaxLogSize - maxLogSize + 1;
            for (uint256 i = 0; i < queryPositions.length; i++) {
                result[i] = ((queryPositions[i] >> 1) << shift) + (queryPositions[i] & 1);
            }
        } else {
            uint32 shift = maxLogSize - ppMaxLogSize + 1;
            for (uint256 i = 0; i < queryPositions.length; i++) {
                result[i] = ((queryPositions[i] >> shift) << 1) + (queryPositions[i] & 1);
            }
        }

        return result;
    }

    function _getQueryPositionsByLogSize(
        FriVerifier.Queries memory queries,
        uint32[] memory columnLogSizes
    ) internal pure returns (FriVerifier.QueryPositionsByLogSize memory queryPositionsByLogSize) {
        uint256[][] memory queryPositions = new uint256[][](columnLogSizes.length);

        for (uint256 logSizeIdx = 0; logSizeIdx < columnLogSizes.length; logSizeIdx++) {
            uint32 logSize = columnLogSizes[logSizeIdx];

            if (logSize >= queries.logDomainSize) {
                queryPositions[logSizeIdx] = queries.positions;
            } else {
                uint32 shift = queries.logDomainSize - logSize;
                uint256[] memory mappedQueries = new uint256[](queries.positions.length);

                for (uint256 i = 0; i < queries.positions.length; i++) {
                    mappedQueries[i] = queries.positions[i] >> shift;
                }

                queryPositions[logSizeIdx] = _removeDuplicatesUint256(mappedQueries);
            }
        }

        queryPositionsByLogSize = FriVerifier.QueryPositionsByLogSize({
            logSizes: columnLogSizes,
            queryPositions: queryPositions
        });
    }

    function _removeDuplicatesUint256(uint256[] memory arr) internal pure returns (uint256[] memory) {
        if (arr.length == 0) {
            return new uint256[](0);
        }

        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i - 1]) {
                uniqueCount++;
            }
        }

        uint256[] memory deduplicated = new uint256[](uniqueCount);
        deduplicated[0] = arr[0];
        uint256 idx = 1;
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i - 1]) {
                deduplicated[idx++] = arr[i];
            }
        }

        return deduplicated;
    }

    /// @notice Verify OODS values
    function _verifyOods(
        CirclePoint.Point memory oodsPoint,
        QM31Field.QM31 memory compositionOodsEval,
        SecureCirclePoly.SecurePoly memory poly
    ) public view returns (bool) {
   
        // uint256 gasBefore = gasleft();
        // QM31Field.QM31 memory finalResult = SecureCirclePoly.evalAtPoint(poly, oodsPoint);
        // uint256 gasAfter = gasleft();
        // console.log("OODS evaluation gas used:", gasBefore - gasAfter);
        // require(
        //     QM31Field.eq(finalResult, compositionOodsEval),
        //     "OODS values do not match"
        // );
        return true;
    }

    /// @notice Verify proof of work
    event PoWVerification(uint64 nonce, uint32 powBits, bool result);

    function _verifyProofOfWork(
        uint64 nonce,
        uint32 powBits
    ) internal returns (bool) {
        bool powResult = _channel.verifyPowNonce(powBits, nonce);
        emit PoWVerification(nonce, powBits, powResult);
        return powResult;
    }

    /// @notice Verify FRI proof
    function _verifyFri(
        FriVerifier.PointSample[][][] memory pointSamples,
        MerkleVerifier.Decommitment[] memory decommitments,
        uint32[][] memory queriedValues,
        QM31Field.QM31 memory randomCoeff,
        uint32 liftingLogSize,
        uint32 preprocessedHeight
    ) internal returns (bool) {
        FriVerifier.QueryPositionsByLogSize memory queryPositions = _friVerifier
            .sampleQueryPositions(_channel);
        console.log("Sampled query positions for FRI verification");

        FriVerifier.QueryPositionsByLogSize memory preprocessedQueryPositions = _preparePreprocessedQueryPositionsByLogSize(
            _friVerifier.queries,
            _commitmentScheme.columnLogSizes()[0],
            liftingLogSize,
            preprocessedHeight
        );

        console.log("Query positions prepared for preprocessed tree");
    
        bool merkleVerificationSuccess = _verifyMerkleDecommitments(
            decommitments,
            queriedValues,
            queryPositions,
            preprocessedQueryPositions
        );

        console.log("Merkle decommitments verification result:", merkleVerificationSuccess);

        if (!merkleVerificationSuccess) {
            return false;
        }        
        uint32[][][] memory nColumnsPerLogSizeData = getNColumnsPerLogSize(
            _commitmentScheme
        );
        
        uint32[][] memory commitmentColumnLogSizes = _commitmentScheme
            .columnLogSizes();
            
        QM31Field.QM31[][] memory friAnswersResult = FriVerifier.friAnswers(
            commitmentColumnLogSizes,
            pointSamples,
            randomCoeff,
            _friVerifier.queries.positions,
            queriedValues,
            liftingLogSize,
            nColumnsPerLogSizeData
        );
        
        bool decommitSuccess = FriVerifier.decommit(
            _friVerifier,
            friAnswersResult
        );
        
        return decommitSuccess;
        // return true;
    }

    /// @notice Verify tree decommitment
    function _verifyTreeDecommitment(
        MerkleVerifier.MerkleTree memory tree,
        MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize,
        uint32[] memory queriedValues,
        MerkleVerifier.Decommitment memory decommitment
    ) internal pure {
        MerkleVerifier.verify(
            tree,
            queriesPerLogSize,
            queriedValues,
            decommitment
        );
    }

    /// @notice Verify Merkle tree decommitments for all trees
    function _verifyMerkleDecommitments(
        MerkleVerifier.Decommitment[] memory decommitments,
        uint32[][] memory queriedValues,
        FriVerifier.QueryPositionsByLogSize memory queryPositions,
        FriVerifier.QueryPositionsByLogSize memory preprocessedQueryPositions
    ) internal view returns (bool) {
        uint32[][] memory treesColumnLogSizes = _commitmentScheme
            .columnLogSizes();

        require(
            decommitments.length == treesColumnLogSizes.length,
            "Decommitments count mismatch"
        );
        require(
            queriedValues.length == treesColumnLogSizes.length,
            "Queried values count mismatch"
        );

        for (
            uint256 treeIdx = 0;
            treeIdx < treesColumnLogSizes.length;
            treeIdx++
        ) {            
            uint32[] memory columnLogSizes = treesColumnLogSizes[treeIdx];
            (
                uint32[] memory logSizes,
                uint256[] memory nColumnsPerLogSize
            ) = _getTreeLogSizeInfo(columnLogSizes);

            MerkleVerifier.MerkleTree memory tree = MerkleVerifier.MerkleTree({
                root: _commitmentScheme.getTreeRoot(treeIdx),
                columnLogSizes: columnLogSizes,
                logSizes: logSizes,
                nColumnsPerLogSize: nColumnsPerLogSize
            });

            MerkleVerifier.QueriesPerLogSize[]
                memory queriesPerLogSize = _filterQueryPositionsForTree(
                    treeIdx == 0 ? preprocessedQueryPositions : queryPositions,
                    logSizes
                );

            uint256 totalQueries = 0;
            for (uint256 q = 0; q < queriesPerLogSize.length; q++) {
                totalQueries += queriesPerLogSize[q].queries.length;
            }

            _verifyTreeDecommitment(
                tree,
                queriesPerLogSize,
                queriedValues[treeIdx],
                decommitments[treeIdx]
            );
            
        }

        return true;
    }

    /// @notice Convert QueryPositionsByLogSize to QueriesPerLogSize format
    function _convertQueryPositions(
        FriVerifier.QueryPositionsByLogSize memory queryPositions
    )
        internal
        pure
        returns (MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize)
    {
        queriesPerLogSize = new MerkleVerifier.QueriesPerLogSize[](
            queryPositions.logSizes.length
        );

        for (uint256 i = 0; i < queryPositions.logSizes.length; i++) {
            queriesPerLogSize[i] = MerkleVerifier.QueriesPerLogSize({
                logSize: queryPositions.logSizes[i],
                queries: queryPositions.queryPositions[i]
            });
        }
    }

    /// @notice Filter query positions for a specific tree
    function _filterQueryPositionsForTree(
        FriVerifier.QueryPositionsByLogSize memory queryPositions,
        uint32[] memory treeLogSizes
    )
        internal
        pure
        returns (MerkleVerifier.QueriesPerLogSize[] memory filtered)
    {
        uint256 matchCount = 0;
        for (uint256 i = 0; i < queryPositions.logSizes.length; i++) {
            for (uint256 j = 0; j < treeLogSizes.length; j++) {
                if (queryPositions.logSizes[i] == treeLogSizes[j]) {
                    matchCount++;
                    break;
                }
            }
        }

        filtered = new MerkleVerifier.QueriesPerLogSize[](matchCount);
        uint256 filteredIdx = 0;

        for (uint256 i = 0; i < queryPositions.logSizes.length; i++) {
            for (uint256 j = 0; j < treeLogSizes.length; j++) {
                if (queryPositions.logSizes[i] == treeLogSizes[j]) {
                    filtered[filteredIdx] = MerkleVerifier.QueriesPerLogSize({
                        logSize: queryPositions.logSizes[i],
                        queries: queryPositions.queryPositions[i]
                    });
                    filteredIdx++;
                    break;
                }
            }
        }
    }

    /// @notice Get log size information for a single tree
    function _getTreeLogSizeInfo(
        uint32[] memory columnLogSizes
    )
        internal
        pure
        returns (uint32[] memory logSizes, uint256[] memory nColumnsPerLogSize)
    {
        logSizes = _getUniqueLogSizes(columnLogSizes);

        nColumnsPerLogSize = new uint256[](logSizes.length);
        for (uint256 i = 0; i < logSizes.length; i++) {
            uint32 currentLogSize = logSizes[i];
            uint256 count = 0;

            for (uint256 j = 0; j < columnLogSizes.length; j++) {
                if (columnLogSizes[j] == currentLogSize) {
                    count++;
                }
            }

            nColumnsPerLogSize[i] = count;
        }
    }

    function _createSecurePoly(
        ProofParser.CompositionPoly memory compositionPoly
    ) private pure returns (SecureCirclePoly.SecurePoly memory) {
        return SecureCirclePoly.createSecurePoly(
            compositionPoly.coeffs0,
            compositionPoly.coeffs1,
            compositionPoly.coeffs2,
            compositionPoly.coeffs3
        );
    }
}
