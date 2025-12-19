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


    struct ComponentParams{
        uint32 logSize;
        QM31Field.QM31 claimedSum;
        FrameworkComponentLib.ComponentInfo info;
    }

    /// @notice Parameters needed for verification
    struct VerificationParams {
        ComponentParams[] componentParams;
        uint256 nPreprocessedColumns;
        uint32 componentsCompositionLogDegreeBound;
    }

    /// @notice Verify a STARK proof
    function verify(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        bytes32[] memory treeRoots,
        uint32[][] memory treeColumnLogSizes,
        bytes32 digest,
        uint32 nDraws
    ) external returns (bool) {
        console.log("Starting STWO proof verification...");
        return _verifyProof(proof, params, treeRoots, treeColumnLogSizes, digest, nDraws);
    }

    function _verifyProof(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        bytes32[] memory treeRoots,
        uint32[][] memory treeColumnLogSizes,
        bytes32 digest,
        uint32 nDraws
    ) private returns (bool) {
        uint256 gasStart = gasleft();
        console.log("[GAS PROFILING] Starting _verifyProof");
        
        if (_components.isInitialized) {
            _components.reset();
        }
        
        uint256 gasBeforePoly = gasleft();
        SecureCirclePoly.SecurePoly memory poly = _createSecurePoly(proof.compositionPoly);
        console.log("[GAS] _createSecurePoly:", gasBeforePoly - gasleft());
        
        uint256 gasBeforeInit = gasleft();
        _initializeVerification(proof, treeRoots, treeColumnLogSizes, digest, nDraws);
        console.log("[GAS] _initializeVerification:", gasBeforeInit - gasleft());
        
        uint256 gasBeforeSteps = gasleft();
        bool result = _performVerificationSteps(proof, params, poly);
        console.log("[GAS] _performVerificationSteps:", gasBeforeSteps - gasleft());
        console.log("[GAS PROFILING] Total _verifyProof:", gasStart - gasleft());
        
        return result;
    }

    function _initializeVerification(
        ProofParser.Proof calldata proof,
        bytes32[] memory treeRoots,
        uint32[][] memory treeColumnLogSizes,
        bytes32 digest,
        uint32 nDraws
    ) private {
        KeccakChannelLib.initializeWith(_channel, digest, nDraws);
        CommitmentSchemeVerifierLib.initialize(
            _commitmentScheme,
            proof.config,
            treeRoots,
            treeColumnLogSizes
        );        
        _channel.drawSecureFelt();

    }

    function _performVerificationSteps(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params,
        SecureCirclePoly.SecurePoly memory poly
    ) private returns (bool) {
        uint256 gasStart = gasleft();
        console.log("[GAS PROFILING] Starting verification steps");
        
        uint256 gasBeforeCommit = gasleft();
        if (!_performCompositionCommit(proof, params)) return false;
        console.log("[GAS] _performCompositionCommit:", gasBeforeCommit - gasleft());
        
        uint256 gasBeforeOodsPoint = gasleft();
        CirclePoint.Point memory oodsPoint = CirclePoint.getRandomPointFromState(_channel);
        console.log("[GAS] getRandomPointFromState:", gasBeforeOodsPoint - gasleft());
        
        uint256 gasBeforeSamples = gasleft();
        ComponentsLib.TreeVecMaskPoints memory samplePoints = _computeSamplePoints(
            oodsPoint,
            proof.commitments.length - 1,
            params
        );
        console.log("[GAS] _computeSamplePoints:", gasBeforeSamples - gasleft());
        
        uint256 gasBeforeOods = gasleft();
        if (!_performOodsVerification(proof, poly, oodsPoint)) return false;
        console.log("[GAS] _performOodsVerification:", gasBeforeOods - gasleft());
        
        uint256 gasBeforeFri = gasleft();
        bool result = _performFriVerification(proof, samplePoints);
        console.log("[GAS] _performFriVerification:", gasBeforeFri - gasleft());
        console.log("[GAS PROFILING] Total verification steps:", gasStart - gasleft());
        
        return result;
    }

    function _performCompositionCommit(
        ProofParser.Proof calldata proof,
        VerificationParams calldata params
    ) private returns (bool) {
        uint32[] memory compositionSizes = new uint32[](4);
        for (uint256 i = 0; i < 4; i++) {
            compositionSizes[i] = params.componentsCompositionLogDegreeBound;
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
        CirclePoint.Point memory oodsPoint
    ) private pure returns (bool) {
        (QM31Field.QM31 memory compositionOodsEval, bool extractSuccess) = ProofParser.extractCompositionOodsEval(proof);
        require(extractSuccess, "Failed to extract composition OODS eval");
        
        return _verifyOods(oodsPoint, compositionOodsEval, poly);
    }

    function _performFriVerification(
        ProofParser.Proof calldata proof,
        ComponentsLib.TreeVecMaskPoints memory samplePoints
    ) private returns (bool) {
        uint256 gasStart = gasleft();
        console.log("[GAS PROFILING] Starting FRI verification");
        
        uint256 gasBeforeFlatten = gasleft();
        QM31Field.QM31[] memory flattenedSampledValues = ProofParser.flattenCols(proof.sampledValues);
        console.log("[GAS] flattenCols:", gasBeforeFlatten - gasleft());
        
        uint256 gasBeforeMix = gasleft();
        _channel.mixFelts(flattenedSampledValues);
        console.log("[GAS] mixFelts:", gasBeforeMix - gasleft());

        uint256 gasBeforeDraw = gasleft();
        QM31Field.QM31 memory randomCoeff2 = _channel.drawSecureFelt();
        console.log("[GAS] drawSecureFelt:", gasBeforeDraw - gasleft());

        uint256 gasBeforeBounds = gasleft();
        CirclePolyDegreeBound.Bound[] memory bounds = _commitmentScheme.calculateBounds();
        console.log("[GAS] calculateBounds:", gasBeforeBounds - gasleft());

        uint256 gasBeforeCommit = gasleft();
        _friVerifier = FriVerifier.commit(
            _channel,
            _commitmentScheme.config.friConfig,
            proof.friProof,
            bounds
        );
        console.log("[GAS] FriVerifier.commit:", gasBeforeCommit - gasleft());

        uint256 gasBeforePow = gasleft();
        if (!_verifyProofOfWork(proof.proofOfWork, proof.config.powBits)) {
            return false;
        }
        console.log("[GAS] _verifyProofOfWork:", gasBeforePow - gasleft());

        uint256 gasBeforeMixU64 = gasleft();
        _channel.mixU64(proof.proofOfWork);
        console.log("[GAS] mixU64:", gasBeforeMixU64 - gasleft());

        uint256 gasBeforeFinalCheck = gasleft();
        bool result = _performFinalFriCheck(proof, randomCoeff2, samplePoints);
        console.log("[GAS] _performFinalFriCheck:", gasBeforeFinalCheck - gasleft());
        console.log("[GAS PROFILING] Total FRI verification:", gasStart - gasleft());
        
        return result;
    }

    function _performFinalFriCheck(
        ProofParser.Proof calldata proof,
        QM31Field.QM31 memory randomCoeff2,
        ComponentsLib.TreeVecMaskPoints memory samplePoints
    ) private returns (bool) {
        FriVerifier.PointSample[][][] memory pointSamples = _zipSamplePointsWithValues(
            samplePoints,
            proof.sampledValues
        );

        return _verifyFri(
            pointSamples,
            proof.decommitments,
            proof.queriedValues,
            randomCoeff2
        );
    }
    /// @notice Compute sample points for OODS evaluation
    function _computeSamplePoints(
        CirclePoint.Point memory oodsPoint,
        uint256 nTrees,
        VerificationParams calldata params
    ) internal returns (ComponentsLib.TreeVecMaskPoints memory) {
        uint256 gasStart = gasleft();
        console.log("[GAS PROFILING] Starting _computeSamplePoints");
        
        FrameworkComponentLib.ComponentState[] memory componentStates = new FrameworkComponentLib.ComponentState[](params.componentParams.length);

        if (TraceLocationAllocatorLib.isInitialized(_allocator)) {
            TraceLocationAllocatorLib.reset(_allocator);
        }
        TraceLocationAllocatorLib.initialize(_allocator);
        
        for (uint256 i = 0; i < params.componentParams.length; i++) {
            if (i > 0) {
                TraceLocationAllocatorLib.reset(_allocator);
                TraceLocationAllocatorLib.initialize(_allocator);
            }
            
            FrameworkComponentLib.ComponentState memory componentState = FrameworkComponentLib.createComponent(_allocator, params.componentParams[i].logSize, params.componentParams[i].claimedSum, params.componentParams[i].info);
            componentStates[i] = componentState;
        }

        _components.initialize(componentStates, params.nPreprocessedColumns);

        FrameworkComponentLib.SamplePoints[] memory componentMaskPoints = _components.maskPoints(oodsPoint);

        ComponentsLib.TreeVecMaskPoints memory maskPoints = _concatCols(componentMaskPoints);
        
        uint256 actualPreprocessedColumns = 0;
        for (uint256 i = 0; i < componentStates.length; i++) {
            actualPreprocessedColumns += componentStates[i].preprocessedColumnIndices.length;
        }
        
        _initializePreprocessedColumns(maskPoints, params.nPreprocessedColumns);

        _setPreprocessedMaskPoints(componentStates, maskPoints, oodsPoint);

        CirclePoint.Point[][][] memory newPoints = new CirclePoint.Point[][][](
            nTrees + 1
        );
        uint256[] memory newNColumns = new uint256[](nTrees + 1);

        for (uint256 i = 0; i < maskPoints.points.length; i++) {
            newPoints[i] = maskPoints.points[i];
            newNColumns[i] = maskPoints.nColumnsPerTree[i];
        }

        uint256 compositionTreeIdx = nTrees;
        uint256 SECURE_EXTENSION_DEGREE = 4;
        newPoints[compositionTreeIdx] = new CirclePoint.Point[][](SECURE_EXTENSION_DEGREE);
        newNColumns[compositionTreeIdx] = SECURE_EXTENSION_DEGREE;

        for (uint256 colIdx = 0; colIdx < SECURE_EXTENSION_DEGREE; colIdx++) {
            newPoints[compositionTreeIdx][colIdx] = new CirclePoint.Point[](1);
            newPoints[compositionTreeIdx][colIdx][0] = oodsPoint;
            maskPoints.totalPoints++;
        }

        maskPoints.points = newPoints;
        maskPoints.nColumnsPerTree = newNColumns;
        
        console.log("[GAS PROFILING] Total _computeSamplePoints:", gasStart - gasleft());
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
        uint256 nPreprocessedColumns
    ) internal pure {
        if (maskPoints.points.length > 0) {
            CirclePoint.Point[][] memory preprocessedTree = new CirclePoint.Point[][](nPreprocessedColumns);
            for (uint256 i = 0; i < nPreprocessedColumns; i++) {
                preprocessedTree[i] = new CirclePoint.Point[](0);
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

    /// @notice Verify OODS values
    function _verifyOods(
        CirclePoint.Point memory oodsPoint,
        QM31Field.QM31 memory compositionOodsEval,
        SecureCirclePoly.SecurePoly memory poly
    ) internal pure returns (bool) {
   
    
        QM31Field.QM31 memory finalResult = SecureCirclePoly.evalAtPoint(poly, oodsPoint);
        
        require(
            QM31Field.eq(finalResult, compositionOodsEval),
            "OODS values do not match"
        );
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
        QM31Field.QM31 memory randomCoeff
    ) internal returns (bool) {
        uint256 gasStart = gasleft();
        console.log("[GAS PROFILING] Starting _verifyFri");
        
        uint256 gasBeforeSample = gasleft();
        FriVerifier.QueryPositionsByLogSize memory queryPositions = _friVerifier
            .sampleQueryPositions(_channel);
        console.log("[GAS] sampleQueryPositions:", gasBeforeSample - gasleft());

        uint256 gasBeforeMerkle = gasleft();
        bool merkleVerificationSuccess = _verifyMerkleDecommitments(
            decommitments,
            queriedValues,
            queryPositions
        );
        console.log("[GAS] _verifyMerkleDecommitments:", gasBeforeMerkle - gasleft());

        if (!merkleVerificationSuccess) {
            return false;
        }        
        
        uint256 gasBeforeNColumns = gasleft();
        uint32[][][] memory nColumnsPerLogSizeData = getNColumnsPerLogSize(
            _commitmentScheme
        );
        console.log("[GAS] getNColumnsPerLogSize:", gasBeforeNColumns - gasleft());
        
        uint256 gasBeforeColumnLogSizes = gasleft();
        uint32[][] memory commitmentColumnLogSizes = _commitmentScheme
            .columnLogSizes();
        console.log("[GAS] columnLogSizes:", gasBeforeColumnLogSizes - gasleft());
            
        uint256 gasBeforeFriAnswers = gasleft();
        QM31Field.QM31[][] memory friAnswersResult = FriVerifier.friAnswers(
            commitmentColumnLogSizes,
            pointSamples,
            randomCoeff,
            queryPositions,
            queriedValues,
            nColumnsPerLogSizeData
        );
        console.log("[GAS] friAnswers:", gasBeforeFriAnswers - gasleft());
        
        uint256 gasBeforeDecommit = gasleft();
        bool decommitSuccess = FriVerifier.decommit(
            _friVerifier,
            friAnswersResult
        );
        console.log("[GAS] FriVerifier.decommit:", gasBeforeDecommit - gasleft());
        console.log("[GAS PROFILING] Total _verifyFri:", gasStart - gasleft());
        
        return decommitSuccess;
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
        FriVerifier.QueryPositionsByLogSize memory queryPositions
    ) internal view returns (bool) {
        uint256 gasStart = gasleft();
        console.log("[GAS PROFILING] Starting _verifyMerkleDecommitments");
        console.log("[INFO] Number of trees:", decommitments.length);
        
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
            uint256 gasBeforeTree = gasleft();
            console.log("[GAS] Processing tree:", treeIdx);
            
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
                    queryPositions,
                    logSizes
                );
            
            uint256 gasBeforeVerify = gasleft();
            _verifyTreeDecommitment(
                tree,
                queriesPerLogSize,
                queriedValues[treeIdx],
                decommitments[treeIdx]
            );
            console.log("[GAS] Tree", treeIdx, "verification:", gasBeforeVerify - gasleft());
            console.log("[GAS] Tree", treeIdx, "total:", gasBeforeTree - gasleft());
        }

        console.log("[GAS PROFILING] Total _verifyMerkleDecommitments:", gasStart - gasleft());
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
