// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "../pcs/PcsConfig.sol";
import "../circle/CirclePolyDegreeBound.sol";
import "../circle/CircleDomainM31.sol";
import "../cosets/CanonicCosetM31.sol";
import "../cosets/CosetM31.sol";
import "../circle/CirclePoint.sol";
import "../circle/CirclePointM31.sol";
import "../fields/QM31Field.sol";
import "../fields/CM31Field.sol";
import "../fields/M31Field.sol";
import "../core/KeccakChannelLib.sol";
import "../vcs/MerkleVerifier.sol";

/// @title FriVerifier
/// @notice Library for FRI (Fast Reed-Solomon Interactive) proximity proof verification
/// @dev Implements the verifier side of FRI protocol using Keccak-based Merkle channel
library FriVerifier {
    using PcsConfig for PcsConfig.FriConfig;
    using CirclePolyDegreeBound for CirclePolyDegreeBound.Bound;
    using QM31Field for QM31Field.QM31;
    using CM31Field for CM31Field.CM31;
    using CirclePointM31 for CirclePointM31.Point;
    using KeccakChannelLib for KeccakChannelLib.ChannelState;
    using MerkleVerifier for MerkleVerifier.Verifier;

    /// @notice Secure extension degree for field operations (matches Rust SECURE_EXTENSION_DEGREE)
    uint32 constant SECURE_EXTENSION_DEGREE = 4;

    /// @notice Query structure for FRI decommitment
    /// @param positions Query positions sorted in ascending order
    /// @param logDomainSize Size of the domain from which queries were sampled
    struct Queries {
        uint256[] positions;
        uint32 logDomainSize;
    }

    /// @notice Mapping of log sizes to query positions
    /// @param logSizes Array of unique log sizes
    /// @param queryPositions Array of query position arrays, indexed by logSizes
    struct QueryPositionsByLogSize {
        uint32[] logSizes;
        uint256[][] queryPositions;
    }

    /// @notice FRI verifier state for commitment phase
    /// @param config FRI configuration parameters
    /// @param firstLayer First layer verifier state
    /// @param innerLayers Array of inner layer verifier states
    /// @param lastLayerDomainLogSize Log size of last layer domain
    /// @param lastLayerPoly Coefficients of last layer polynomial
    /// @param queries Generated queries (set after sampling)
    /// @param queryPositionsByLogSize Query positions organized by log size
    struct FriVerifierState {
        PcsConfig.FriConfig config;
        FriFirstLayerVerifier firstLayer;
        FriInnerLayerVerifier[] innerLayers;
        uint32 lastLayerDomainLogSize;
        QM31Field.QM31[] lastLayerPoly;
        CosetM31.CosetStruct lastLayerDomain;
        Queries queries; // Set when queries are sampled
        QueryPositionsByLogSize queryPositionsByLogSize;
        bool queriesSampled;
    }

    /// @notice First layer verifier containing column degree bounds and domains
    /// @param columnBounds Circle polynomial degree bounds in descending order
    /// @param columnCommitmentDomains Commitment domains for each column
    /// @param foldingAlpha Random folding coefficient from channel
    /// @param proof First layer proof data
    struct FriFirstLayerVerifier {
        CirclePolyDegreeBound.Bound[] columnBounds;
        CircleDomain.CircleDomainStruct[] columnCommitmentDomains;
        QM31Field.QM31 foldingAlpha;
        FriLayerProof proof;
    }

    /// @notice Inner layer verifier for FRI intermediate layers
    /// @param degreeBound Degree bound for this layer
    /// @param domainLogSize Log size of layer domain
    /// @param foldingAlpha Random folding coefficient from channel
    /// @param layerIndex Index of this layer (for error reporting)
    /// @param proof Layer proof data
    /// @notice Inner layer verifier state (matches Rust FriInnerLayerVerifier)
    /// @param degreeBound Degree bound for this layer
    /// @param domain Line domain for this layer (full coset, not just log size)
    /// @param foldingAlpha Folding alpha for this layer
    /// @param layerIndex Index of this layer
    /// @param proof Proof data for this layer
    struct FriInnerLayerVerifier {
        uint32 degreeBound;
        CosetM31.CosetStruct domain;  // Changed from domainLogSize to full domain
        QM31Field.QM31 foldingAlpha;
        uint256 layerIndex;
        FriLayerProof proof;
    }

    /// @notice Proof for individual FRI layer
    /// @param friWitness Values needed by verifier that cannot be deduced
    /// @param decommitment Merkle decommitment proof
    /// @param commitment Merkle tree root commitment
    struct FriLayerProof {
        QM31Field.QM31[] friWitness;
        bytes decommitment; // Encoded MerkleDecommitment
        bytes32 commitment;
    }

    /// @notice Complete FRI proof structure
    /// @param firstLayer First layer proof
    /// @param innerLayers Array of inner layer proofs
    /// @param lastLayerPoly Last layer polynomial coefficients
    struct FriProof {
        FriLayerProof firstLayer;
        FriLayerProof[] innerLayers;
        QM31Field.QM31[] lastLayerPoly;
    }

    /// @notice Point sample structure for FRI answers
    /// @param point Circle point where sample was taken
    /// @param value QM31 value at the point
    struct PointSample {
        CirclePoint.Point point;
        QM31Field.QM31 value;
    }

    /// @notice Column sample batch for efficient quotient evaluation
    /// @param point Circle point for this batch
    /// @param columnsAndValues Array of (columnIndex, sampledValue) pairs
    struct ColumnSampleBatch {
        CirclePoint.Point point;
        ColumnAndValue[] columnsAndValues;
    }

    /// @notice Column index and value pair
    /// @param columnIndex Index of the column
    /// @param value Sampled value at the column
    struct ColumnAndValue {
        uint256 columnIndex;
        QM31Field.QM31 value;
    }

    /// @notice Quotient constants for FRI answers
    /// @param lineCoeffs Precomputed line coefficients for each batch and column
    struct QuotientConstants {
        QM31Field.QM31[][][] lineCoeffs; // [batch][column][3] for (a, b, c) coefficients
    }

    /// @notice FRI verification error types
    error InvalidNumFriLayers();
    error FirstLayerEvaluationsInvalid();
    error FirstLayerCommitmentInvalid();
    error InnerLayerEvaluationsInvalid(uint256 layerIndex);
    error InnerLayerCommitmentInvalid(uint256 layerIndex);
    error LastLayerDegreeInvalid();
    error LastLayerEvaluationsInvalid();
    error ColumnBoundsNotSorted();
    error EmptyColumnBounds();

    /// @notice Events for debugging and monitoring
    event FriCommitmentStarted(uint256 indexed numLayers);
    event FriLayerCommitted(
        uint256 indexed layerIndex,
        bytes32 indexed commitment
    );
    event FriCommitmentCompleted(bool indexed success);

    /// @notice FRI constants
    uint32 public constant FOLD_STEP = 1;
    uint32 public constant CIRCLE_TO_LINE_FOLD_STEP = 1;

    /// @notice Verify the commitment stage of FRI
    /// @dev Verifies FRI commitments and prepares verifier state for decommitment
    /// @param channelState Keccak channel state for Fiat-Shamir
    /// @param config FRI configuration parameters
    /// @param proof Complete FRI proof
    /// @param columnBounds Circle polynomial degree bounds in descending order
    /// @return friVerifierState Initialized verifier state for decommitment
    function commit(
        KeccakChannelLib.ChannelState storage channelState,
        PcsConfig.FriConfig memory config,
        FriProof memory proof,
        CirclePolyDegreeBound.Bound[] memory columnBounds
    ) internal returns (FriVerifierState memory friVerifierState) {
        emit FriCommitmentStarted(proof.innerLayers.length + 1);

        // Validate inputs
        if (columnBounds.length == 0) {
            revert EmptyColumnBounds();
        }

        // Verify column bounds are sorted in descending order
        for (uint256 i = 1; i < columnBounds.length; i++) {
            if (
                columnBounds[i - 1].logDegreeBound <
                columnBounds[i].logDegreeBound
            ) {
                revert ColumnBoundsNotSorted();
            }
        }

        // Mix first layer commitment into channel
        channelState.mixRoot(channelState.digest, proof.firstLayer.commitment);
        emit FriLayerCommitted(0, proof.firstLayer.commitment);

        // Calculate column commitment domains
        CircleDomain.CircleDomainStruct[]
            memory columnCommitmentDomains = new CircleDomain.CircleDomainStruct[](
                columnBounds.length
            );

        for (uint256 i = 0; i < columnBounds.length; i++) {
            uint32 commitmentDomainLogSize = columnBounds[i].logDegreeBound +
                config.logBlowupFactor;
            CanonicCosetM31.CanonicCosetStruct
                memory canonicCoset = CanonicCosetM31.newCanonicCoset(
                    commitmentDomainLogSize
                );
            CosetM31.CosetStruct memory halfCoset = CanonicCosetM31.halfCoset(
                canonicCoset
            );
            columnCommitmentDomains[i] = CircleDomain.newCircleDomain(
                halfCoset
            );
        }

        // Create first layer verifier
        FriFirstLayerVerifier memory firstLayer = FriFirstLayerVerifier({
            columnBounds: columnBounds,
            columnCommitmentDomains: columnCommitmentDomains,
            foldingAlpha: channelState.drawSecureFelt(),
            proof: proof.firstLayer
        });

        // Process inner layers
        FriInnerLayerVerifier[]
            memory innerLayers = new FriInnerLayerVerifier[](
                proof.innerLayers.length
            );

        // Start with max column bound folded to line
        uint32 layerBound = columnBounds[0].logDegreeBound -
            CIRCLE_TO_LINE_FOLD_STEP;
        uint32 layerDomainLogSize = layerBound + config.logBlowupFactor;
        
  
        
        CosetM31.CosetStruct memory layerDomain = CosetM31.halfOdds(layerDomainLogSize);
        
 

        for (uint256 i = 0; i < proof.innerLayers.length; i++) {
            // Mix layer commitment into channel
            channelState.mixRoot(
                channelState.digest,
                proof.innerLayers[i].commitment
            );
            emit FriLayerCommitted(i + 1, proof.innerLayers[i].commitment);

            // Create inner layer verifier
            innerLayers[i] = FriInnerLayerVerifier({
                degreeBound: layerBound,
                domain: layerDomain,
                foldingAlpha: channelState.drawSecureFelt(),
                layerIndex: i,
                proof: proof.innerLayers[i]
            });

            // Fold for next layer
            if (layerBound < FOLD_STEP) {
                revert InvalidNumFriLayers();
            }
            layerBound -= FOLD_STEP;
            layerDomainLogSize = layerBound + config.logBlowupFactor;
            
            layerDomain = CosetM31.double(layerDomain);
  
        }

        // Verify final layer bound matches config
        if (layerBound != config.logLastLayerDegreeBound) {
            revert InvalidNumFriLayers();
        }

        // Verify last layer polynomial degree
        uint256 maxLastLayerSize = 1 << config.logLastLayerDegreeBound;
        if (proof.lastLayerPoly.length > maxLastLayerSize) {
            revert LastLayerDegreeInvalid();
        }
        
        channelState.mixFelts(proof.lastLayerPoly);

        // Initialize verifier state
        friVerifierState = FriVerifierState({
            config: config,
            firstLayer: firstLayer,
            innerLayers: innerLayers,
            lastLayerDomainLogSize: layerDomainLogSize,
            lastLayerDomain: layerDomain,
            lastLayerPoly: proof.lastLayerPoly,
            queries: Queries({positions: new uint256[](0), logDomainSize: 0}),
            queryPositionsByLogSize: QueryPositionsByLogSize({
                logSizes: new uint32[](0),
                queryPositions: new uint256[][](0)
            }),
            queriesSampled: false
        });

        emit FriCommitmentCompleted(true);
    }

    /// @notice Sample query positions for FRI decommitment
    /// @dev Matches Rust implementation: generates unique queries and maps them by log size
    /// @param friVerifierState FRI verifier state
    /// @param channelState Keccak channel for randomness
    /// @return queryPositionsByLogSize Mapping of log sizes to query positions (equivalent to Rust BTreeMap)
    function sampleQueryPositions(
        FriVerifierState storage friVerifierState,
        KeccakChannelLib.ChannelState storage channelState
    )
        internal
        returns (QueryPositionsByLogSize memory queryPositionsByLogSize)
    {
        
        // Collect unique column log sizes (equivalent to Rust BTreeSet)
        uint32[] memory columnLogSizes = _getUniqueColumnLogSizes(
            friVerifierState
        );


        // Find maximum column log size
        uint32 maxColumnLogSize = 0;
        for (uint256 i = 0; i < columnLogSizes.length; i++) {
            if (columnLogSizes[i] > maxColumnLogSize) {
                maxColumnLogSize = columnLogSizes[i];
            }
        }

        // Generate queries (equivalent to Queries::generate)
        Queries memory queries = _generateQueries(
            channelState,
            maxColumnLogSize,
            uint32(friVerifierState.config.nQueries)
        );

 
        // Get query positions by log size (equivalent to get_query_positions_by_log_size)
        queryPositionsByLogSize = _getQueryPositionsByLogSize(
            queries,
            columnLogSizes
        );


        // Store in verifier state
        friVerifierState.queries = queries;
        friVerifierState.queryPositionsByLogSize = queryPositionsByLogSize;
        friVerifierState.queriesSampled = true;
        
    }

    /// @notice Mix QM31 array into channel
    /// @dev Helper function to mix polynomial coefficients
    /// @param channelState Channel state for mixing
    /// @param values Array of QM31 values to mix
    function _mixQM31Array(
        KeccakChannelLib.ChannelState storage channelState,
        QM31Field.QM31[] memory values
    ) private {
        for (uint256 i = 0; i < values.length; i++) {
            uint32[4] memory components = QM31Field.toM31Array(values[i]);
            uint32[] memory componentsArray = new uint32[](4);
            componentsArray[0] = components[0];
            componentsArray[1] = components[1];
            componentsArray[2] = components[2];
            componentsArray[3] = components[3];
            channelState.mixU32s(componentsArray);
        }
    }

    /// @notice Get maximum column log size from first layer domains
    /// @param friVerifierState FRI verifier state
    /// @return maxLogSize Maximum log size among all column domains
    function getMaxColumnLogSize(
        FriVerifierState memory friVerifierState
    ) internal pure returns (uint32 maxLogSize) {
        maxLogSize = 0;
        for (
            uint256 i = 0;
            i < friVerifierState.firstLayer.columnCommitmentDomains.length;
            i++
        ) {
            uint32 logSize = CircleDomain.logSize(
                friVerifierState.firstLayer.columnCommitmentDomains[i]
            );
            if (logSize > maxLogSize) {
                maxLogSize = logSize;
            }
        }
    }

    /// @notice Get number of expected inner layers based on degree bounds and config
    /// @param maxColumnBound Maximum column degree bound
    /// @param config FRI configuration
    /// @return expectedLayers Number of expected inner layers
    function getExpectedInnerLayers(
        CirclePolyDegreeBound.Bound memory maxColumnBound,
        PcsConfig.FriConfig memory config
    ) internal pure returns (uint256 expectedLayers) {
        uint32 currentBound = maxColumnBound.logDegreeBound -
            CIRCLE_TO_LINE_FOLD_STEP;
        expectedLayers = 0;

        while (currentBound > config.logLastLayerDegreeBound) {
            if (currentBound < FOLD_STEP) break;
            currentBound -= FOLD_STEP;
            expectedLayers++;
        }
    }

    /// @notice Validate FRI configuration parameters
    /// @param config FRI configuration to validate
    /// @return valid True if configuration is valid
    function validateConfig(
        PcsConfig.FriConfig memory config
    ) internal pure returns (bool valid) {
        // Validate blowup factor range (1 to 16)
        if (config.logBlowupFactor < 1 || config.logBlowupFactor > 16) {
            return false;
        }

        // Validate last layer degree bound (0 to 10)
        if (config.logLastLayerDegreeBound > 10) {
            return false;
        }

        // Validate non-zero queries
        if (config.nQueries == 0) {
            return false;
        }

        return true;
    }

    /// @notice Calculate security level in bits
    /// @param config FRI configuration
    /// @return securityBits Estimated security level
    function getSecurityBits(
        PcsConfig.FriConfig memory config
    ) internal pure returns (uint32 securityBits) {
        return config.logBlowupFactor * uint32(config.nQueries);
    }

    /// @notice Get unique column log sizes from first layer domains
    /// @dev Equivalent to Rust BTreeSet collection
    /// @param friVerifierState FRI verifier state
    /// @return uniqueLogSizes Array of unique log sizes in ascending order
    function _getUniqueColumnLogSizes(
        FriVerifierState storage friVerifierState
    ) private view returns (uint32[] memory uniqueLogSizes) {
        uint32[] memory allLogSizes = new uint32[](
            friVerifierState.firstLayer.columnCommitmentDomains.length
        );

        // Collect all log sizes
        for (
            uint256 i = 0;
            i < friVerifierState.firstLayer.columnCommitmentDomains.length;
            i++
        ) {
            allLogSizes[i] = CircleDomain.logSize(
                friVerifierState.firstLayer.columnCommitmentDomains[i]
            );
        }

        // Sort array
        _sortUint32Array(allLogSizes);

        // Remove duplicates
        return _removeDuplicatesUint32(allLogSizes);
    }

    /// @notice Generate unique query positions (equivalent to Queries::generate)
    /// @dev Uses BTreeSet-like logic to ensure uniqueness
    /// @param channelState Channel state for randomness
    /// @param logDomainSize Log size of domain to sample from
    /// @param nQueries Number of unique queries to generate
    /// @return queries Generated queries structure
    function _generateQueries(
        KeccakChannelLib.ChannelState storage channelState,
        uint32 logDomainSize,
        uint32 nQueries
    ) private returns (Queries memory queries) {

        uint256 maxQuery = (1 << logDomainSize) - 1;
        
        // CRITICAL: Draw EXACTLY nQueries values (not unique count!)
        // This matches Rust behavior where BTreeSet.insert() is called nQueries times
        // even if some inserts are duplicates
        uint256[] memory drawnQueries = new uint256[](nQueries);
        uint256 queryDrawCount = 0;
        uint256 drawCallCount = 0;
        
        while (queryDrawCount < nQueries) {
            uint32[] memory randomWords = channelState.drawU32s();

            for (
                uint256 i = 0;
                i < randomWords.length && queryDrawCount < nQueries;
                i++
            ) {
                uint256 candidateQuery = randomWords[i] & maxQuery;
                drawnQueries[queryDrawCount] = candidateQuery;
                queryDrawCount++;
            }
            drawCallCount++;
        }

        // Now deduplicate and sort (mimics BTreeSet behavior)
        uint256[] memory uniqueQueries = _deduplicateAndSort(drawnQueries);

        queries = Queries({
            positions: uniqueQueries,
            logDomainSize: logDomainSize
        });
    }

    /// @notice Map query positions by log size (equivalent to get_query_positions_by_log_size)
    /// @param queries Generated queries
    /// @param columnLogSizes Unique column log sizes
    /// @return queryPositionsByLogSize Mapped query positions
    function _getQueryPositionsByLogSize(
        Queries memory queries,
        uint32[] memory columnLogSizes
    )
        private
        pure
        returns (QueryPositionsByLogSize memory queryPositionsByLogSize)
    {
        uint256[][] memory queryPositions = new uint256[][](
            columnLogSizes.length
        );

        for (
            uint256 logSizeIdx = 0;
            logSizeIdx < columnLogSizes.length;
            logSizeIdx++
        ) {
            uint32 logSize = columnLogSizes[logSizeIdx];

            if (logSize >= queries.logDomainSize) {
                // Same size or larger domain - use all queries
                queryPositions[logSizeIdx] = queries.positions;
            } else {
                // Smaller domain - map queries down by shifting and remove duplicates
                uint32 shift = queries.logDomainSize - logSize;
                uint256[] memory mappedQueries = new uint256[](
                    queries.positions.length
                );

                for (uint256 i = 0; i < queries.positions.length; i++) {
                    mappedQueries[i] = queries.positions[i] >> shift;
                }

                // Remove duplicates (queries are already sorted, so we just need to remove consecutive duplicates)
                queryPositions[logSizeIdx] = _removeDuplicatesUint256(
                    mappedQueries
                );
            }
        }

        queryPositionsByLogSize = QueryPositionsByLogSize({
            logSizes: columnLogSizes,
            queryPositions: queryPositions
        });
    }

    /// @notice Sort uint32 array in ascending order (bubble sort)
    /// @param arr Array to sort in-place
    function _sortUint32Array(uint32[] memory arr) private pure {
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

    /// @notice Sort uint256 array in ascending order (bubble sort)
    /// @param arr Array to sort in-place
    function _sortUint256Array(uint256[] memory arr) private pure {
        for (uint256 i = 0; i < arr.length; i++) {
            for (uint256 j = 0; j < arr.length - i - 1; j++) {
                if (arr[j] > arr[j + 1]) {
                    uint256 temp = arr[j];
                    arr[j] = arr[j + 1];
                    arr[j + 1] = temp;
                }
            }
        }
    }

    /// @notice Deduplicate and sort uint256 array
    /// @dev Mimics Rust BTreeSet behavior: sorts and removes duplicates
    /// @param arr Array potentially with duplicates
    /// @return deduplicated Sorted array without duplicates
    function _deduplicateAndSort(uint256[] memory arr) private pure returns (uint256[] memory) {
        if (arr.length == 0) {
            return arr;
        }
        
        // First sort
        _sortUint256Array(arr);
        
        // Count unique elements
        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i-1]) {
                uniqueCount++;
            }
        }
        
        // Create deduplicated array
        uint256[] memory deduplicated = new uint256[](uniqueCount);
        deduplicated[0] = arr[0];
        uint256 writeIdx = 1;
        
        for (uint256 i = 1; i < arr.length; i++) {
            if (arr[i] != arr[i-1]) {
                deduplicated[writeIdx] = arr[i];
                writeIdx++;
            }
        }
        
        return deduplicated;
    }

    /// @notice Remove consecutive duplicates from sorted uint32 array
    /// @param sortedArr Sorted array with potential duplicates
    /// @return deduplicated Array without consecutive duplicates
    function _removeDuplicatesUint32(
        uint32[] memory sortedArr
    ) private pure returns (uint32[] memory deduplicated) {
        if (sortedArr.length == 0) {
            return new uint32[](0);
        }

        // Count unique elements
        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < sortedArr.length; i++) {
            if (sortedArr[i] != sortedArr[i - 1]) {
                uniqueCount++;
            }
        }

        // Create deduplicated array
        deduplicated = new uint32[](uniqueCount);
        deduplicated[0] = sortedArr[0];
        uint256 currentIndex = 1;

        for (uint256 i = 1; i < sortedArr.length; i++) {
            if (sortedArr[i] != sortedArr[i - 1]) {
                deduplicated[currentIndex] = sortedArr[i];
                currentIndex++;
            }
        }
    }

    /// @notice Remove consecutive duplicates from sorted uint256 array
    /// @param sortedArr Sorted array with potential duplicates
    /// @return deduplicated Array without consecutive duplicates
    function _removeDuplicatesUint256(
        uint256[] memory sortedArr
    ) private pure returns (uint256[] memory deduplicated) {
        if (sortedArr.length == 0) {
            return new uint256[](0);
        }

        // Count unique elements
        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < sortedArr.length; i++) {
            if (sortedArr[i] != sortedArr[i - 1]) {
                uniqueCount++;
            }
        }

        // Create deduplicated array
        deduplicated = new uint256[](uniqueCount);
        deduplicated[0] = sortedArr[0];
        uint256 currentIndex = 1;

        for (uint256 i = 1; i < sortedArr.length; i++) {
            if (sortedArr[i] != sortedArr[i - 1]) {
                deduplicated[currentIndex] = sortedArr[i];
                currentIndex++;
            }
        }
    }

    /// @notice Calculate FRI answers for quotient polynomials
    /// @dev Equivalent to Rust fri_answers function - computes quotient evaluations at query positions
    /// @param columnLogSizes Array of log sizes for each tree and column
    /// @param samples Point samples organized by tree, column and point
    /// @param randomCoeff Random coefficient for linear combination
    /// @param queryPositionsByLogSize Query positions mapped by log size
    /// @param queriedValues Queried values from each tree
    /// @param nColumnsPerLogSize Number of columns per log size for each tree
    /// @return result 2D array of quotient evaluations for FRI decommitment (columns x query values)
    function friAnswers(
        uint32[][] memory columnLogSizes, // TreeVec<Vec<u32>>
        PointSample[][][] memory samples, // TreeVec<Vec<Vec<PointSample>>>
        QM31Field.QM31 memory randomCoeff, // SecureField
        QueryPositionsByLogSize memory queryPositionsByLogSize, // &BTreeMap<u32, Vec<usize>>
        uint32[][] memory queriedValues, // TreeVec<Vec<BaseField>> (BaseField = M31 = uint32)
        uint32[][][] memory nColumnsPerLogSize // TreeVec<&BTreeMap<u32, usize>>
    ) internal pure returns (QM31Field.QM31[][] memory result) {

        // Flatten column log sizes and create (logSize, samples) pairs
        LogSizeAndSamples[] memory flattenedData = _flattenAndCreatePairs(
            columnLogSizes,
            samples
        );

        // Sort by log size in DESCENDING order (matches Rust: sorted_by_key(|(log_size, ..)| Reverse(*log_size)))
        _sortByLogSizeAscending(flattenedData);
        
        // Get unique log sizes from flattened data in descending order
        uint32[] memory uniqueLogSizes = _getUniqueLogSizesFromFlattened(flattenedData);

        
        result = new QM31Field.QM31[][](uniqueLogSizes.length);

        // Create mutable iterator state for queried values
        QueriedValuesIterator memory queriedValuesIter = QueriedValuesIterator({
            data: queriedValues,
            positions: new uint256[](queriedValues.length)
        });

        // Process each unique log size (already in descending order from sorting)
        for (uint256 i = 0; i < uniqueLogSizes.length; i++) {
            uint32 logSize = uniqueLogSizes[i];
            
            // Find this logSize in queryPositionsByLogSize
            uint256[] memory queryPositions;
            for (uint256 j = 0; j < queryPositionsByLogSize.logSizes.length; j++) {
                if (queryPositionsByLogSize.logSizes[j] == logSize) {
                    queryPositions = queryPositionsByLogSize.queryPositions[j];
                    break;
                }
            }

            // Get samples for this log size
            PointSample[][] memory samplesForLogSize = _getSamplesForLogSize(
                flattenedData,
                logSize
            );

            // Get n_columns for this log size from each tree
            uint256[] memory nColumnsForLogSize = _getNColumnsForLogSize(
                nColumnsPerLogSize,
                logSize
            );

            // Calculate answers for this log size
            // In Rust: fri_answers_for_log_size returns Result<Vec<SecureField>, VerificationError>
            // This becomes one column in our 2D array
            QM31Field.QM31[] memory answersForLogSize = friAnswersForLogSize(
                logSize,
                samplesForLogSize,
                randomCoeff,
                queryPositions,
                queriedValuesIter,
                nColumnsForLogSize
            );

            // Store this group's answers as one column
            result[i] = answersForLogSize;
      

        }


    }

    /// @notice Calculate FRI answers for a specific log size
    /// @dev Equivalent to Rust fri_answers_for_log_size function
    /// @param logSize Log size of the domain
    /// @param samples Point samples for this log size
    /// @param randomCoeff Random coefficient for linear combination
    /// @param queryPositions Query positions for this log size
    /// @param queriedValuesIter Iterator over queried values (mutable)
    /// @param nColumns Number of columns per tree for this log size
    /// @return answersForLogSize Quotient evaluations at query positions
    function friAnswersForLogSize(
        uint32 logSize,
        PointSample[][] memory samples,
        QM31Field.QM31 memory randomCoeff,
        uint256[] memory queryPositions,
        QueriedValuesIterator memory queriedValuesIter,
        uint256[] memory nColumns
    ) internal pure returns (QM31Field.QM31[] memory answersForLogSize) {
        // Create sample batches (equivalent to ColumnSampleBatch::new_vec)
        ColumnSampleBatch[] memory sampleBatches = _createColumnSampleBatches(
            samples
        );
        // Calculate quotient constants
        QuotientConstants
            memory quotientConstants = _calculateQuotientConstants(
                sampleBatches,
                randomCoeff
            );
        // Create commitment domain
        CircleDomain.CircleDomainStruct
            memory commitmentDomain = _createCommitmentDomain(logSize);

        // Calculate quotient evaluations at each query position
        answersForLogSize = new QM31Field.QM31[](queryPositions.length);

        for (uint256 i = 0; i < queryPositions.length; i++) {
            uint256 queryPosition = queryPositions[i];

            // Get domain point at bit-reversed query position
            CirclePointM31.Point memory domainPoint = _getDomainPointAtQuery(
                commitmentDomain,
                queryPosition,
                logSize
            );

            // Get queried values at this row
            uint32[] memory queriedValuesAtRow = _getQueriedValuesAtRow(
                queriedValuesIter,
                nColumns
            );

            // Accumulate row quotients
            answersForLogSize[i] = _accumulateRowQuotients(
                sampleBatches,
                queriedValuesAtRow,
                quotientConstants,
                domainPoint
            );
        }

    }

    /// @notice Accumulate quotient contributions from all sample batches at a domain point
    /// @dev Equivalent to Rust accumulate_row_quotients function
    /// @param sampleBatches Array of column sample batches
    /// @param queriedValuesAtRow Queried values for this row
    /// @param quotientConstants Precomputed quotient constants
    /// @param domainPoint Domain point where quotients are evaluated
    /// @return accumulator Sum of all quotient contributions
    function _accumulateRowQuotients(
        ColumnSampleBatch[] memory sampleBatches,
        uint32[] memory queriedValuesAtRow,
        QuotientConstants memory quotientConstants,
        CirclePointM31.Point memory domainPoint
    ) internal pure returns (QM31Field.QM31 memory accumulator) {

        
        // Calculate denominator inverses for all sample batches
        CM31Field.CM31[]
            memory denominatorInverses = _calculateDenominatorInverses(
                sampleBatches,
                domainPoint
            );

        accumulator = QM31Field.zero();

        // Process each sample batch
        for (
            uint256 batchIdx = 0;
            batchIdx < sampleBatches.length;
            batchIdx++
        ) {
            ColumnSampleBatch memory sampleBatch = sampleBatches[batchIdx];
            QM31Field.QM31[][] memory batchLineCoeffs = quotientConstants
                .lineCoeffs[batchIdx];
            CM31Field.CM31 memory denominatorInverse = denominatorInverses[
                batchIdx
            ];

            QM31Field.QM31 memory numerator = QM31Field.zero();

            // Process each column in the batch
            for (
                uint256 colIdx = 0;
                colIdx < sampleBatch.columnsAndValues.length;
                colIdx++
            ) {
                ColumnAndValue memory columnAndValue = sampleBatch
                    .columnsAndValues[colIdx];
                QM31Field.QM31[] memory lineCoeffs = batchLineCoeffs[colIdx]; // [a, b, c]

                // Get queried value for this column and convert to QM31
                QM31Field.QM31 memory queriedValue = QM31Field.fromM31(
                    queriedValuesAtRow[columnAndValue.columnIndex],
                    0,
                    0,
                    0
                );

                QM31Field.QM31 memory value = QM31Field.mul(
                    queriedValue,
                    lineCoeffs[2] // c coefficient
                );



                // Calculate linear term: a * domain_point.y + b
                QM31Field.QM31 memory linearTerm = QM31Field.add(
                    QM31Field.mul(
                        lineCoeffs[0],
                        QM31Field.fromM31(domainPoint.y, 0, 0, 0)
                    ), // a * domain_point.y
                    lineCoeffs[1] // b
                );

                // Add to numerator: value - linear_term
                numerator = QM31Field.add(
                    numerator,
                    QM31Field.sub(value, linearTerm)
                );
            }

            // Multiply numerator by denominator inverse and add to accumulator
            QM31Field.QM31 memory contribution = QM31Field.mulCM31(
                numerator,
                denominatorInverse
            );
            accumulator = QM31Field.add(accumulator, contribution);
        }
    }

    // Helper data structures for fri_answers implementation

    /// @notice Pair of log size and corresponding samples for sorting/grouping
    struct LogSizeAndSamples {
        uint32 logSize;
        PointSample[] samples;
    }

    /// @notice Iterator state for queried values
    struct QueriedValuesIterator {
        uint32[][] data;
        uint256[] positions; // Current position in each tree's data
    }

    // Helper functions (implementation details follow)

    function _flattenAndCreatePairs(
        uint32[][] memory columnLogSizes,
        PointSample[][][] memory samples
    ) private pure returns (LogSizeAndSamples[] memory pairs) {
        // Flatten column_log_sizes: TreeVec<Vec<u32>> -> ColumnVec<u32>
        uint256 totalLogSizes = 0;
        for (uint256 i = 0; i < columnLogSizes.length; i++) {
            totalLogSizes += columnLogSizes[i].length;
        }
        
        // Flatten samples: TreeVec<Vec<Vec<PointSample>>> -> ColumnVec<Vec<PointSample>>
        uint256 totalSampleVecs = 0;
        for (uint256 i = 0; i < samples.length; i++) {
            totalSampleVecs += samples[i].length;
        }
        
        require(totalLogSizes == totalSampleVecs, "Mismatch between log sizes and samples count");
        
        // Create pairs equivalent to izip!(column_log_sizes.flatten(), samples.flatten().iter())
        pairs = new LogSizeAndSamples[](totalLogSizes);
        
        uint256 pairIndex = 0;
        for (uint256 treeIdx = 0; treeIdx < columnLogSizes.length; treeIdx++) {
            for (uint256 colIdx = 0; colIdx < columnLogSizes[treeIdx].length; colIdx++) {
                pairs[pairIndex] = LogSizeAndSamples({
                    logSize: columnLogSizes[treeIdx][colIdx],
                    samples: samples[treeIdx][colIdx]
                });
                pairIndex++;
            }
        }
    }

    function _sortByLogSizeAscending(
        LogSizeAndSamples[] memory data
    ) private pure {
        // Bubble sort by log size in DESCENDING order (Reverse in Rust: sorted_by_key(|(log_size, ..)| Reverse(*log_size)))
        for (uint256 i = 0; i < data.length; i++) {
            for (uint256 j = 0; j < data.length - i - 1; j++) {
                if (data[j].logSize < data[j + 1].logSize) {  // Changed from > to < for descending
                    LogSizeAndSamples memory temp = data[j];
                    data[j] = data[j + 1];
                    data[j + 1] = temp;
                }
            }
        }
    }

    /// @notice Get unique log sizes from flattened data (already sorted descending)
    /// @param flattenedData Flattened and sorted data
    /// @return uniqueLogSizes Array of unique log sizes in descending order
    function _getUniqueLogSizesFromFlattened(
        LogSizeAndSamples[] memory flattenedData
    ) private pure returns (uint32[] memory uniqueLogSizes) {
        if (flattenedData.length == 0) {
            return new uint32[](0);
        }

        // Count unique log sizes
        uint256 uniqueCount = 1;
        uint32 prevLogSize = flattenedData[0].logSize;
        for (uint256 i = 1; i < flattenedData.length; i++) {
            if (flattenedData[i].logSize != prevLogSize) {
                uniqueCount++;
                prevLogSize = flattenedData[i].logSize;
            }
        }

        // Extract unique log sizes (maintain descending order from sort)
        uniqueLogSizes = new uint32[](uniqueCount);
        uniqueLogSizes[0] = flattenedData[0].logSize;
        uint256 uniqueIdx = 1;
        prevLogSize = flattenedData[0].logSize;
        
        for (uint256 i = 1; i < flattenedData.length; i++) {
            if (flattenedData[i].logSize != prevLogSize) {
                uniqueLogSizes[uniqueIdx] = flattenedData[i].logSize;
                uniqueIdx++;
                prevLogSize = flattenedData[i].logSize;
            }
        }
    }

    function _getSamplesForLogSize(
        LogSizeAndSamples[] memory flattenedData,
        uint32 logSize
    ) private pure returns (PointSample[][] memory samplesForLogSize) {
        // Count samples matching the given log size (equivalent to group_by in Rust)
        uint256 matchCount = 0;
        for (uint256 i = 0; i < flattenedData.length; i++) {
            if (flattenedData[i].logSize == logSize) {
                matchCount++;
            }
        }
        
        // Extract samples matching the given log size (equivalent to multiunzip(tuples))
        samplesForLogSize = new PointSample[][](matchCount);
        uint256 matchIndex = 0;
        for (uint256 i = 0; i < flattenedData.length; i++) {
            if (flattenedData[i].logSize == logSize) {
                samplesForLogSize[matchIndex] = flattenedData[i].samples;
                matchIndex++;
            }
        }
    }

    function _getUniqueLogSizesAscending(
        LogSizeAndSamples[] memory flattenedData
    ) private pure returns (uint32[] memory uniqueLogSizes) {
        if (flattenedData.length == 0) {
            return new uint32[](0);
        }

        // Count unique log sizes
        uint256 uniqueCount = 1;
        for (uint256 i = 1; i < flattenedData.length; i++) {
            if (flattenedData[i].logSize != flattenedData[i - 1].logSize) {
                uniqueCount++;
            }
        }

        // Extract unique log sizes
        uniqueLogSizes = new uint32[](uniqueCount);
        uniqueLogSizes[0] = flattenedData[0].logSize;
        uint256 idx = 1;
        for (uint256 i = 1; i < flattenedData.length; i++) {
            if (flattenedData[i].logSize != flattenedData[i - 1].logSize) {
                uniqueLogSizes[idx] = flattenedData[i].logSize;
                idx++;
            }
        }
    }

    function _sortQueriesPerLogSizeAscending(
        MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize
    ) private pure {
        // Bubble sort by logSize in ascending order
        for (uint256 i = 0; i < queriesPerLogSize.length; i++) {
            for (uint256 j = 0; j < queriesPerLogSize.length - i - 1; j++) {
                if (queriesPerLogSize[j].logSize > queriesPerLogSize[j + 1].logSize) {
                    MerkleVerifier.QueriesPerLogSize memory temp = queriesPerLogSize[j];
                    queriesPerLogSize[j] = queriesPerLogSize[j + 1];
                    queriesPerLogSize[j + 1] = temp;
                }
            }
        }
    }

    function _getQueryPositionsForLogSize(
        QueryPositionsByLogSize memory queryPositionsByLogSize,
        uint32 logSize
    ) private pure returns (uint256[] memory queryPositions) {
        // Find the query positions for this log size
        for (uint256 i = 0; i < queryPositionsByLogSize.logSizes.length; i++) {
            if (queryPositionsByLogSize.logSizes[i] == logSize) {
                return queryPositionsByLogSize.queryPositions[i];
            }
        }
        return new uint256[](0);
    }

    function _getNColumnsForLogSize(
        uint32[][][] memory nColumnsPerLogSize,
        uint32 logSize
    ) private pure returns (uint256[] memory nColumnsForLogSize) {
        nColumnsForLogSize = new uint256[](nColumnsPerLogSize.length);
        for (
            uint256 treeIdx = 0;
            treeIdx < nColumnsPerLogSize.length;
            treeIdx++
        ) {
            // Find the entry for this log size in the tree's data
            for (uint256 i = 0; i < nColumnsPerLogSize[treeIdx].length; i++) {
                if (
                    nColumnsPerLogSize[treeIdx][i].length >= 2 &&
                    nColumnsPerLogSize[treeIdx][i][0] == logSize
                ) {
                    nColumnsForLogSize[treeIdx] = nColumnsPerLogSize[treeIdx][
                        i
                    ][1];
                    break;
                }
            }
        }
    }

    function _createColumnSampleBatches(
        PointSample[][] memory samples
    ) private pure returns (ColumnSampleBatch[] memory batches) {
        // Rust: Groups column samples by sampled point using IndexMap
        // Maintains stable ordering of points and columns
        
        // Count total samples
        uint256 totalSamples = 0;
        for (uint256 i = 0; i < samples.length; i++) {
            totalSamples += samples[i].length;
        }
        
        if (totalSamples == 0) {
            return new ColumnSampleBatch[](0);
        }
        
        // Collect all (point, column_index, value) tuples
        CirclePoint.Point[] memory allPoints = new CirclePoint.Point[](totalSamples);
        uint256[] memory allColumnIndices = new uint256[](totalSamples);
        QM31Field.QM31[] memory allValues = new QM31Field.QM31[](totalSamples);
        
        uint256 sampleIdx = 0;
        for (uint256 colIdx = 0; colIdx < samples.length; colIdx++) {
            for (uint256 i = 0; i < samples[colIdx].length; i++) {
                allPoints[sampleIdx] = samples[colIdx][i].point;
                allColumnIndices[sampleIdx] = colIdx;
                allValues[sampleIdx] = samples[colIdx][i].value;
                sampleIdx++;
            }
        }
        
        // Find unique points (stable ordering - first occurrence)
        CirclePoint.Point[] memory uniquePoints = new CirclePoint.Point[](totalSamples);
        uint256[] memory pointFirstIndex = new uint256[](totalSamples);
        uint256 numUniquePoints = 0;
        
        for (uint256 i = 0; i < totalSamples; i++) {
            bool found = false;
            for (uint256 j = 0; j < numUniquePoints; j++) {
                if (_pointsEqual(allPoints[i], uniquePoints[j])) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                uniquePoints[numUniquePoints] = allPoints[i];
                pointFirstIndex[numUniquePoints] = i;
                numUniquePoints++;
            }
        }
        
        // Create batches - one per unique point
        batches = new ColumnSampleBatch[](numUniquePoints);
        
        for (uint256 batchIdx = 0; batchIdx < numUniquePoints; batchIdx++) {
            CirclePoint.Point memory currentPoint = uniquePoints[batchIdx];
            
            // Count samples for this point
            uint256 samplesForPoint = 0;
            for (uint256 i = 0; i < totalSamples; i++) {
                if (_pointsEqual(allPoints[i], currentPoint)) {
                    samplesForPoint++;
                }
            }
            
            // Collect (column_index, value) pairs for this point
            ColumnAndValue[] memory columnsAndValues = new ColumnAndValue[](samplesForPoint);
            uint256 colValIdx = 0;
            for (uint256 i = 0; i < totalSamples; i++) {
                if (_pointsEqual(allPoints[i], currentPoint)) {
                    columnsAndValues[colValIdx] = ColumnAndValue({
                        columnIndex: allColumnIndices[i],
                        value: allValues[i]
                    });
                    colValIdx++;
                }
            }
            
            batches[batchIdx] = ColumnSampleBatch({
                point: currentPoint,
                columnsAndValues: columnsAndValues
            });
        }
    }
    
    /// @notice Check if two CirclePoints are equal
    function _pointsEqual(
        CirclePoint.Point memory a,
        CirclePoint.Point memory b
    ) private pure returns (bool) {
        return QM31Field.eq(a.x, b.x) && QM31Field.eq(a.y, b.y);
    }

    function _calculateQuotientConstants(
        ColumnSampleBatch[] memory sampleBatches,
        QM31Field.QM31 memory randomCoeff
    ) private pure returns (QuotientConstants memory constants) {
        // Calculate line coefficients for each batch and column
        constants.lineCoeffs = new QM31Field.QM31[][][](sampleBatches.length);
        QM31Field.QM31 memory alpha = QM31Field.one();

        for (
            uint256 batchIdx = 0;
            batchIdx < sampleBatches.length;
            batchIdx++
        ) {
            ColumnSampleBatch memory batch = sampleBatches[batchIdx];
            constants.lineCoeffs[batchIdx] = new QM31Field.QM31[][](
                batch.columnsAndValues.length
            );

            for (
                uint256 colIdx = 0;
                colIdx < batch.columnsAndValues.length;
                colIdx++
            ) {
                PointSample memory sample = PointSample({
                    point: batch.point,
                    value: batch.columnsAndValues[colIdx].value
                });

                constants.lineCoeffs[batchIdx][
                    colIdx
                ] = _complexConjugateLineCoeffs(sample, alpha);
                alpha = QM31Field.mul(alpha, randomCoeff);
            }
        }
    }

    function _createCommitmentDomain(
        uint32 logSize
    ) private pure returns (CircleDomain.CircleDomainStruct memory domain) {
        CanonicCosetM31.CanonicCosetStruct memory canonicCoset = CanonicCosetM31
            .newCanonicCoset(logSize);
        CosetM31.CosetStruct memory halfCoset = CanonicCosetM31.halfCoset(
            canonicCoset
        );

        domain = CircleDomain.newCircleDomain(halfCoset);
    }

    function _getDomainPointAtQuery(
        CircleDomain.CircleDomainStruct memory domain,
        uint256 queryPosition,
        uint32 logSize
    ) private pure returns (CirclePointM31.Point memory point) {
        uint256 bitReversedIndex = _bitReverseIndex(queryPosition, logSize);
        point = CircleDomain.at(domain, bitReversedIndex);
    }

    function _getQueriedValuesAtRow(
        QueriedValuesIterator memory iter,
        uint256[] memory nColumns
    ) private pure returns (uint32[] memory valuesAtRow) {
        // Calculate total values needed
        uint256 totalValues = 0;
        for (uint256 i = 0; i < nColumns.length; i++) {
            totalValues += nColumns[i];
        }

        valuesAtRow = new uint32[](totalValues);
        uint256 valueIndex = 0;

        // Take specified number of values from each tree's iterator
        for (uint256 treeIdx = 0; treeIdx < nColumns.length; treeIdx++) {
            uint256 nCols = nColumns[treeIdx];
            for (uint256 i = 0; i < nCols; i++) {
                if (iter.positions[treeIdx] < iter.data[treeIdx].length) {
                    valuesAtRow[valueIndex] = iter.data[treeIdx][
                        iter.positions[treeIdx]
                    ];
                    iter.positions[treeIdx]++;
                } else {
                    valuesAtRow[valueIndex] = 0; // Use 0 instead of QM31Field.zero()
                }
                valueIndex++;
            }
        }
    }

    function _calculateDenominatorInverses(
        ColumnSampleBatch[] memory sampleBatches,
        CirclePointM31.Point memory domainPoint
    ) private pure returns (CM31Field.CM31[] memory inverses) {
        CM31Field.CM31[] memory denominators = new CM31Field.CM31[](
            sampleBatches.length
        );

        for (uint256 i = 0; i < sampleBatches.length; i++) {
            CirclePoint.Point memory samplePoint = sampleBatches[i].point;

            CM31Field.CM31 memory prx = samplePoint.x.first;
            CM31Field.CM31 memory pry = samplePoint.y.first;
            CM31Field.CM31 memory pix = samplePoint.x.second;
            CM31Field.CM31 memory piy = samplePoint.y.second;
            // Calculate: (prx - domain_point.x) * piy - (pry - domain_point.y) * pix
            CM31Field.CM31 memory term1 = CM31Field.mul(
                CM31Field.sub(prx, CM31Field.fromM31(domainPoint.x, 0)),
                piy
            );
            CM31Field.CM31 memory term2 = CM31Field.mul(
                CM31Field.sub(pry, CM31Field.fromM31(domainPoint.y, 0)),
                pix
            );
            denominators[i] = CM31Field.sub(term1, term2);
        }

        // Batch inverse
        inverses = CM31Field.batchInverse(denominators);
    }

    function _complexConjugateLineCoeffs(
        PointSample memory sample,
        QM31Field.QM31 memory alpha
    ) private pure returns (QM31Field.QM31[] memory coeffs) {
        coeffs = new QM31Field.QM31[](3);
        QM31Field.QM31 memory valueConj = _conjugateQM31(sample.value);
        QM31Field.QM31 memory a = QM31Field.sub(valueConj, sample.value);
    
        // Calculate c = point.conjugate().y - point.y
        CirclePoint.Point memory pointConj = CirclePoint.complexConjugate(sample.point);
        
        QM31Field.QM31 memory c = QM31Field.sub(pointConj.y, sample.point.y);
        
        // Calculate b = value * c - a * point.y
        QM31Field.QM31 memory valueMulC = QM31Field.mul(sample.value, c);
        QM31Field.QM31 memory aMulY = QM31Field.mul(a, sample.point.y);
        QM31Field.QM31 memory b = QM31Field.sub(valueMulC, aMulY);


        // Return (alpha * a, alpha * b, alpha * c)
        coeffs[0] = QM31Field.mul(alpha, a);
        coeffs[1] = QM31Field.mul(alpha, b);
        coeffs[2] = QM31Field.mul(alpha, c);
    }
    
    /// @notice Complex conjugate for QM31 (negates second component)
    /// @dev Equivalent to Rust ComplexConjugate trait for QM31
    /// @param a QM31 element to conjugate
    /// @return Conjugated element (first, -second)
    function _conjugateQM31(QM31Field.QM31 memory a) private pure returns (QM31Field.QM31 memory) {
        return QM31Field.QM31({
            first: a.first,
            second: CM31Field.neg(a.second)
        });
    }

    function _bitReverseIndex(
        uint256 index,
        uint32 logSize
    ) private pure returns (uint256 reversed) {
        reversed = 0;
        for (uint256 i = 0; i < logSize; i++) {
            reversed = (reversed << 1) | (index & 1);
            index >>= 1;
        }
    }

    // =============================================================================
    // FRI DECOMMITMENT FUNCTIONS
    // =============================================================================

    /// @notice Verifies the decommitment stage of FRI
    /// @dev The query evals need to be provided in the same order as their commitment
    /// @param friVerifierState FRI verifier state with sampled queries
    /// @param firstLayerQueryEvals Query evaluations for the first layer columns
    /// @return success True if decommitment verification passes
    function decommit(
        FriVerifierState memory friVerifierState,
        QM31Field.QM31[][] memory firstLayerQueryEvals
    ) internal pure returns (bool success) {
        // Ensure queries were sampled
        if (!friVerifierState.queriesSampled) {
            revert("Queries not sampled");
        }

        return
            decommitOnQueries(
                friVerifierState,
                friVerifierState.queries,
                firstLayerQueryEvals
            );
    }

    /// @notice Internal decommitment orchestrator
    /// @dev Coordinates first layer, inner layers, and last layer verification
    /// @param friVerifierState FRI verifier state
    /// @param queries Query positions for decommitment
    /// @param firstLayerQueryEvals Query evaluations for the first layer
    /// @return success True if all layers verify successfully
    function decommitOnQueries(
        FriVerifierState memory friVerifierState,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals
    ) internal pure returns (bool success) {

        // Step 1: Verify first layer and get sparse evaluations
        (
            bool firstLayerSuccess,
            SparseEvaluation[] memory firstLayerSparseEvals
        ) = decommitFirstLayer(friVerifierState, queries, firstLayerQueryEvals);
        if (!firstLayerSuccess) {
            revert(
                "FRI decommit failed at STEP 1: First layer verification failed"
            );
        }

        // Step 2: Fold queries for inner layers (equivalent to queries.fold(CIRCLE_TO_LINE_FOLD_STEP))
        Queries memory innerLayerQueries = foldQueries(
            queries,
            CIRCLE_TO_LINE_FOLD_STEP
        );

        // Step 3: Verify inner layers
        (
            bool innerLayersSuccess,
            Queries memory lastLayerQueries,
            QM31Field.QM31[] memory lastLayerQueryEvals
        ) = decommitInnerLayers(
                friVerifierState,
                innerLayerQueries,
                firstLayerSparseEvals
            );
        if (!innerLayersSuccess) {
            revert("FRI decommit failed at STEP 3: Inner layers verification failed");
        }

        

        // Step 4: Verify last layer
        bool lastLayerSuccess = decommitLastLayer(friVerifierState, lastLayerQueries, lastLayerQueryEvals);
        if (!lastLayerSuccess) {
            revert("FRI decommit failed at STEP 4: Last layer verification failed");
        }

        return true;
    }

    /// @notice Verifies the first layer decommitment
    /// @dev Returns the queries and first layer folded column evaluations for remaining layers
    /// @param friVerifierState FRI verifier state
    /// @param queries Query positions
    /// @param firstLayerQueryEvals Query evaluations for first layer columns
    /// @return success True if first layer verification passes
    /// @return sparseEvalsResult Sparse evaluations for use in inner layers
    function decommitFirstLayer(
        FriVerifierState memory friVerifierState,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals
    )
        internal
        pure
        returns (bool success, SparseEvaluation[] memory sparseEvalsResult)
    {
        // Verify first layer using the first layer verifier
        return
            verifyFirstLayer(
                friVerifierState.firstLayer,
                queries,
                firstLayerQueryEvals
            );
    }

    /// @notice Verifies the first layer of FRI
    /// @param firstLayer First layer verifier state
    /// @param queries Query positions
    /// @param firstLayerQueryEvals Query evaluations for first layer columns
    /// @return success True if verification passes
    /// @return sparseEvalsResult Sparse evaluations for inner layers
    function verifyFirstLayer(
        FriFirstLayerVerifier memory firstLayer,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals
    )
        internal
        pure
        returns (bool success, SparseEvaluation[] memory sparseEvalsResult)
    {
        _validateFirstLayerInputs(firstLayer, queries, firstLayerQueryEvals);
        return _verifyFirstLayerMain(firstLayer, queries, firstLayerQueryEvals);
    }

    function _verifyFirstLayerMain(
        FriFirstLayerVerifier memory firstLayer,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals
    )
        private
        pure
        returns (bool success, SparseEvaluation[] memory sparseEvalsResult)
    {
        WitnessIterator memory witnessIter = WitnessIterator({
            witness: firstLayer.proof.friWitness,
            index: 0
        });

        sparseEvalsResult = new SparseEvaluation[](firstLayer.columnBounds.length);
        QM31Field.QM31[][] memory sparseEvals = new QM31Field.QM31[][](firstLayer.columnBounds.length);

        (
            uint256 numUniqueLogSizes,
            uint256 totalDecommittedM31Values,
            uint32[] memory uniqueLogSizes,
            uint256[][] memory decommitmentsByLogSize
        ) = _processColumnsLoop(
            firstLayer, queries, firstLayerQueryEvals, witnessIter, sparseEvalsResult, sparseEvals
        );

        require(witnessIter.index == witnessIter.witness.length, "Not all witness consumed");

        _verifyMerkleProof(
            firstLayer, sparseEvals, totalDecommittedM31Values, numUniqueLogSizes, uniqueLogSizes, decommitmentsByLogSize
        );

        return (true, sparseEvalsResult);
    }

    function _processColumnsLoop(
        FriFirstLayerVerifier memory firstLayer,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals,
        WitnessIterator memory witnessIter,
        SparseEvaluation[] memory sparseEvalsResult,
        QM31Field.QM31[][] memory sparseEvals
    ) private pure returns (
        uint256 numUniqueLogSizes,
        uint256 totalDecommittedM31Values,
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize
    ) {
        uniqueLogSizes = new uint32[](firstLayer.columnCommitmentDomains.length);
        decommitmentsByLogSize = new uint256[][](firstLayer.columnCommitmentDomains.length);
        numUniqueLogSizes = 0;
        totalDecommittedM31Values = 0;

        for (uint256 colIdx = 0; colIdx < firstLayer.columnCommitmentDomains.length; colIdx++) {
            uint32 columnLogSize = CircleDomain.logSize(firstLayer.columnCommitmentDomains[colIdx]);
            uint32 foldSteps = queries.logDomainSize - columnLogSize;
            Queries memory columnQueries = foldQueries(queries, foldSteps);

            (uint256[] memory positions, SparseEvaluation memory sparse) = 
                computeDecommitmentPositionsAndRebuildEvals(
                    columnQueries, firstLayerQueryEvals[colIdx], witnessIter, CIRCLE_TO_LINE_FOLD_STEP
                );

            bool found = false;
            for (uint256 i = 0; i < numUniqueLogSizes; i++) {
                if (uniqueLogSizes[i] == columnLogSize) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                uniqueLogSizes[numUniqueLogSizes] = columnLogSize;
                decommitmentsByLogSize[numUniqueLogSizes] = positions;
                numUniqueLogSizes++;
            }

            sparseEvalsResult[colIdx] = sparse;
            sparseEvals[colIdx] = _flattenSparseEval(sparse);
            totalDecommittedM31Values += _countM31Values(sparse);
        }
    }

    function _verifyMerkleProof(
        FriFirstLayerVerifier memory firstLayer,
        QM31Field.QM31[][] memory sparseEvals,
        uint256 totalDecommittedM31Values,
        uint256 numUniqueLogSizes,
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize
    ) private pure {
        uint32[] memory decommittedValues = _extractDecommittedValues(sparseEvals, totalDecommittedM31Values);
        _verifyMerkleProofFinal(firstLayer, decommittedValues, numUniqueLogSizes, uniqueLogSizes, decommitmentsByLogSize);
    }

    function _verifyMerkleProofFinal(
        FriFirstLayerVerifier memory firstLayer,
        uint32[] memory decommittedValues,
        uint256 numUniqueLogSizes,
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize
    ) private pure {
        uint32[] memory columnLogSizes = _createColumnLogSizes(firstLayer);
        
        MerkleVerifier.MerkleTree memory verifier = MerkleVerifier.createMerkleTree(
            firstLayer.proof.commitment, columnLogSizes
        );

        MerkleVerifier.Decommitment memory decommitment = _decodeDecommitment(firstLayer.proof.decommitment);
        
        // Prepare queries per log size from decommitment positions
        MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize = new MerkleVerifier.QueriesPerLogSize[](numUniqueLogSizes);
        for (uint256 i = 0; i < numUniqueLogSizes; i++) {
            queriesPerLogSize[i] = MerkleVerifier.QueriesPerLogSize({
                logSize: uniqueLogSizes[i],
                queries: decommitmentsByLogSize[i]
            });
        }
        
        // Sort queriesPerLogSize by logSize in ascending order to match Rust behavior
        _sortQueriesPerLogSizeAscending(queriesPerLogSize);
        
        MerkleVerifier.verify(verifier, queriesPerLogSize, decommittedValues, decommitment);
    }

    /// @notice Flatten sparse evaluation to 1D array
    function _flattenSparseEval(
        SparseEvaluation memory sparseEval
    ) private pure returns (QM31Field.QM31[] memory flattened) {
        uint256 totalCount = 0;
        for (uint256 i = 0; i < sparseEval.subsetEvals.length; i++) {
            totalCount += sparseEval.subsetEvals[i].length;
        }
        flattened = new QM31Field.QM31[](totalCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < sparseEval.subsetEvals.length; i++) {
            for (uint256 j = 0; j < sparseEval.subsetEvals[i].length; j++) {
                flattened[idx++] = sparseEval.subsetEvals[i][j];
            }
        }
    }

    /// @notice Count total M31 values in sparse evaluation
    function _countM31Values(
        SparseEvaluation memory sparseEval
    ) private pure returns (uint256 count) {
        for (uint256 i = 0; i < sparseEval.subsetEvals.length; i++) {
            count += sparseEval.subsetEvals[i].length * 4; // Each QM31 = 4 M31 values
        }
    }

    /// @notice Verifies all inner layer decommitments
    /// @dev Returns the queries and query evaluations needed for verifying the last FRI layer
    /// @param friVerifierState FRI verifier state
    /// @param queries Query positions for inner layers
    /// @param firstLayerSparseEvals Sparse evaluations from first layer
    /// @return success True if all inner layers verify
    /// @return lastLayerQueries Query positions for last layer
    /// @return lastLayerQueryEvals Query evaluations for last layer
    function decommitInnerLayers(
        FriVerifierState memory friVerifierState,
        Queries memory queries,
        SparseEvaluation[] memory firstLayerSparseEvals
    )
        internal
        pure
        returns (
            bool success,
            Queries memory lastLayerQueries,
            QM31Field.QM31[] memory lastLayerQueryEvals
        )
    {
        Queries memory layerQueries = queries;
        QM31Field.QM31[] memory layerQueryEvals = new QM31Field.QM31[](
            layerQueries.positions.length
        );

        // Initialize layer query evals to zero
        for (uint256 i = 0; i < layerQueryEvals.length; i++) {
            layerQueryEvals[i] = QM31Field.zero();
        }

        uint256 sparseEvalsIndex = 0;
        uint256 columnBoundIndex = 0;
        QM31Field.QM31 memory previousFoldingAlpha = friVerifierState
            .firstLayer
            .foldingAlpha;

        // Process each inner layer
        for (
            uint256 layerIndex = 0;
            layerIndex < friVerifierState.innerLayers.length;
            layerIndex++
        ) {
            FriInnerLayerVerifier memory layer = friVerifierState.innerLayers[
                layerIndex
            ];

            // Check for evals committed in the first layer that need to be folded into this layer
            while (
                columnBoundIndex <
                friVerifierState.firstLayer.columnBounds.length
            ) {
                CirclePolyDegreeBound.Bound memory bound = friVerifierState
                    .firstLayer
                    .columnBounds[columnBoundIndex];

                uint32 foldedBound = bound.logDegreeBound > 0
                    ? bound.logDegreeBound - CIRCLE_TO_LINE_FOLD_STEP
                    : 0;

                if (foldedBound != layer.degreeBound) {
                    break;
                }

                // Use the previous layer's folding alpha to fold the circle's sparse evals
                CircleDomain.CircleDomainStruct
                    memory columnDomain = friVerifierState
                        .firstLayer
                        .columnCommitmentDomains[columnBoundIndex];


                QM31Field.QM31[]
                    memory foldedColumnEvals = foldCircleSparseEvals(
                        firstLayerSparseEvals[sparseEvalsIndex],
                        previousFoldingAlpha,
                        columnDomain
                    );

                // Update layerQueryEvals with accumulated values
                layerQueryEvals = accumulateLine(
                    layerQueryEvals,
                    foldedColumnEvals,
                    previousFoldingAlpha
                );

                sparseEvalsIndex++;
                columnBoundIndex++;
            }

            // Verify the layer and fold it using the current layer's folding alpha
            (
                bool layerSuccess,
                Queries memory newLayerQueries,
                QM31Field.QM31[] memory newLayerQueryEvals
            ) = verifyAndFoldLayer(layer, layerQueries, layerQueryEvals);

            if (!layerSuccess) {
                return (false, layerQueries, layerQueryEvals);
            }

            layerQueries = newLayerQueries;
            layerQueryEvals = newLayerQueryEvals;
            previousFoldingAlpha = layer.foldingAlpha;
        }

        // Ensure all values have been consumed

        require(
            columnBoundIndex == friVerifierState.firstLayer.columnBounds.length,
            "Not all column bounds consumed"
        );
        require(
            sparseEvalsIndex == firstLayerSparseEvals.length,
            "Not all sparse evals consumed"
        );

        return (true, layerQueries, layerQueryEvals);
    }

    /// @notice Verifies the last layer
    /// @dev Evaluates the last layer polynomial at query positions and compares with expected values
    /// @dev Matches Rust decommit_last_layer: uses LineDomain.at() which returns x-coordinate (M31)
    /// @param friVerifierState FRI verifier state
    /// @param queries Query positions for last layer
    /// @param queryEvals Expected query evaluations
    /// @return success True if last layer verification passes
    function decommitLastLayer(
        FriVerifierState memory friVerifierState,
        Queries memory queries,
        QM31Field.QM31[] memory queryEvals
    ) internal pure returns (bool success) {
        // Get last layer domain and polynomial
        // Rust: let Self { last_layer_domain: domain, last_layer_poly, .. } = self;
        uint32 lastLayerDomainLogSize = friVerifierState.lastLayerDomainLogSize;
        QM31Field.QM31[] memory lastLayerPoly = friVerifierState.lastLayerPoly;

        // Create line domain for last layer (matches Rust LineDomain)
        CosetM31.CosetStruct memory domain = friVerifierState.lastLayerDomain;

        // Verify each query evaluation
        // Rust: for (&query, query_eval) in zip(&*queries, query_evals)
        for (uint256 i = 0; i < queries.positions.length; i++) {
            uint256 query = queries.positions[i];
            QM31Field.QM31 memory queryEval = queryEvals[i];
            
            // Get domain point at bit-reversed query position
            // Rust: let x = domain.at(bit_reverse_index(query, domain.log_size()));
            // Note: LineDomain.at() returns BaseField (M31), not CirclePoint!
            // LineDomain.at(i) = self.coset.at(i).x
            uint256 reversedIndex = _bitReverseIndex(
                query,
                lastLayerDomainLogSize
            );

            CirclePointM31.Point memory circlePoint = CosetM31.at(domain, reversedIndex);
            uint32 x = circlePoint.x; // Extract x-coordinate (M31)

            // Convert M31 to QM31 (matches Rust x.into())
            QM31Field.QM31 memory xAsQM31 = QM31Field.fromM31(x, 0, 0, 0);

            // Evaluate polynomial at point x
            // Rust: if query_eval != last_layer_poly.eval_at_point(x.into())
            QM31Field.QM31 memory expectedEval = evaluatePolynomialAtPoint(
                lastLayerPoly,
                xAsQM31
            );

            // Compare with provided evaluation
            if (!QM31Field.eq(queryEval, expectedEval)) {
                return false; // LastLayerEvaluationsInvalid
            }
        }
        
        return true;
    }

    // =============================================================================
    // SUPPORTING FUNCTIONS FOR DECOMMITMENT
    // =============================================================================

    function foldQueries(
        Queries memory queries,
        uint32 foldStep
    ) internal pure returns (Queries memory foldedQueries) {
        if (foldStep == 0) {
            return queries;
        }

        // Fold all positions
        uint256[] memory foldedPositions = new uint256[](
            queries.positions.length
        );
        for (uint256 i = 0; i < queries.positions.length; i++) {
            foldedPositions[i] = queries.positions[i] >> foldStep;
        }

        // Remove consecutive duplicates (equivalent to Rust .dedup())
        // Queries are already sorted, so we only need to remove consecutive duplicates
        foldedPositions = _removeDuplicatesUint256(foldedPositions);

        foldedQueries = Queries({
            positions: foldedPositions,
            logDomainSize: queries.logDomainSize - foldStep
        });
    }

    /// @notice Folds circle sparse evaluations into line evaluations
    /// @dev Matches Rust SparseEvaluation::fold_circle implementation
    /// @param sparseEval Sparse evaluation structure to fold
    /// @param foldingAlpha Folding coefficient
    /// @param columnDomain Source circle domain
    /// @return foldedEvals Folded evaluations (one per subset)
    function foldCircleSparseEvals(
        SparseEvaluation memory sparseEval,
        QM31Field.QM31 memory foldingAlpha,
        CircleDomain.CircleDomainStruct memory columnDomain
    ) internal pure returns (QM31Field.QM31[] memory foldedEvals) {
        
        // Result has one value per subset (matches Rust: .map().collect())
        foldedEvals = new QM31Field.QM31[](sparseEval.subsetEvals.length);

        // Iterate through pairs (subset_evals, subset_domain_initial_indexes)
        for (uint256 i = 0; i < sparseEval.subsetEvals.length; i++) {
            QM31Field.QM31[] memory subsetEval = sparseEval.subsetEvals[i];
            uint256 domainInitialIndex = sparseEval.subsetDomainIndexInitials[
                i
            ];

            // Get the domain point at the initial index
            // Rust: let fold_domain_initial = source_domain.index_at(domain_initial_index);
            CosetM31.CirclePointIndex memory foldDomainInitial = CircleDomain.indexAt(
                columnDomain,
                domainInitialIndex
            );

            // Create fold domain (shifted by CIRCLE_TO_LINE_FOLD_STEP - 1)
            // Rust: CircleDomain::new(Coset::new(fold_domain_initial, CIRCLE_TO_LINE_FOLD_STEP - 1))
            // Since CIRCLE_TO_LINE_FOLD_STEP = 1, this is log_size = 0 (single point)
            uint32 foldDomainLogSize = 0; // CIRCLE_TO_LINE_FOLD_STEP - 1 = 1 - 1 = 0

            // Create buffer for folded result (size = 2^foldDomainLogSize = 1)
            // Rust: let mut buffer = vec![SecureField::zero(); fold_domain.half_coset.size()];
            uint256 bufferSize = 1 << foldDomainLogSize; // 2^0 = 1
            QM31Field.QM31[] memory buffer = new QM31Field.QM31[](bufferSize);
            for (uint256 j = 0; j < bufferSize; j++) {
                buffer[j] = QM31Field.zero();
            }

            // Create fold domain for this subset
            // Rust: CircleDomain::new(Coset::new(fold_domain_initial, CIRCLE_TO_LINE_FOLD_STEP - 1))
            // Since CIRCLE_TO_LINE_FOLD_STEP = 1, log_size = 0, which means single point domain
            // For log_size = 0, step_size = subgroup_gen(0) = identity index (0)
       
            CosetM31.CosetStruct memory foldDomainCoset = CosetM31.newCoset(
                foldDomainInitial,
                0 
            );
            
            CircleDomain.CircleDomainStruct memory foldDomain = CircleDomain.CircleDomainStruct({
                halfCoset: foldDomainCoset
            });

            // Fold circle into line
            // Rust: fold_circle_into_line(&mut buffer, &eval, fold_domain, fold_alpha);
            foldedEvals[i] = _foldCircleIntoLineForSubset(buffer, subsetEval, foldDomain, foldingAlpha);

        
        }
    }

    /// @notice Helper to fold a single subset's circle evaluations into line
    /// @dev Full implementation of fold_circle_into_line matching Rust
    /// @param dst Destination buffer (modified in place)
    /// @param src Source evaluations from subset
    /// @param srcDomain Source circle domain
    /// @param alpha Folding coefficient
    function _foldCircleIntoLineForSubset(
        QM31Field.QM31[] memory dst,
        QM31Field.QM31[] memory src,
        CircleDomain.CircleDomainStruct memory srcDomain,
        QM31Field.QM31 memory alpha
    ) internal pure returns (QM31Field.QM31 memory) {

        // Rust: assert_eq!(src.len() >> CIRCLE_TO_LINE_FOLD_STEP, dst.len());
        require(
            src.length >> CIRCLE_TO_LINE_FOLD_STEP == dst.length,
            "Invalid fold sizes"
        );

        // Rust: let alpha_sq = alpha * alpha;
        QM31Field.QM31 memory alphaSq = QM31Field.mul(alpha, alpha);

        // Fold pairs: (f_p, f_neg_p) -> f_prime
        // Rust: src.iter().tuples().enumerate().for_each(|(i, (&f_p, &f_neg_p))| { ... })
        for (uint256 i = 0; i < src.length / 2; i++) {
            QM31Field.QM31 memory f_p = src[i * 2];
            QM31Field.QM31 memory f_neg_p = src[i * 2 + 1];



            // Rust: let p = src_domain.at(bit_reverse_index(i << CIRCLE_TO_LINE_FOLD_STEP, src_domain.log_size()));
            uint256 bitReversedIndex = _bitReverseIndex(
                i << CIRCLE_TO_LINE_FOLD_STEP,
                CircleDomain.logSize(srcDomain)
            );
            CirclePointM31.Point memory p = CircleDomain.at(srcDomain, bitReversedIndex);
            


            // Rust: let (mut f0_px, mut f1_px) = (f_p, f_neg_p);
            // Rust: ibutterfly(&mut f0_px, &mut f1_px, p.y.inverse());
            uint32 p_y_inverse = M31Field.inverse(p.y);
            
            // ibutterfly: (a, b) <- (a + b, (a - b) * twiddle_inverse)
            (QM31Field.QM31 memory f0_px, QM31Field.QM31 memory f1_px) = _ibutterfly(f_p, f_neg_p, p_y_inverse);
            
  
            // Rust: let f_prime = alpha * f1_px + f0_px;
            QM31Field.QM31 memory alpha_mul_f1 = QM31Field.mul(alpha, f1_px);
            QM31Field.QM31 memory f_prime = QM31Field.add(alpha_mul_f1, f0_px);


            // Rust: dst[i] = dst[i] * alpha_sq + f_prime;
            dst[i] = QM31Field.add(
                QM31Field.mul(dst[i], alphaSq),
                f_prime
            );
            

        }
        return dst[0]; // Since dst size is 1, return the single folded evaluation
    }
    
    /// @notice Inverse butterfly operation for QM31 field elements
    /// @dev Matches Rust ibutterfly: (a, b) <- (a + b, (a - b) * twiddle_inverse)
    /// @param a First element (modified in place - but Solidity doesn't support this, so we'll need workaround)
    /// @param b Second element (modified in place)
    /// @param twiddleInverse Twiddle factor inverse (M31)
    function _ibutterfly(
        QM31Field.QM31 memory a,
        QM31Field.QM31 memory b,
        uint32 twiddleInverse
    ) private pure returns (QM31Field.QM31 memory, QM31Field.QM31 memory) {
        // Rust: *a, *b = *a + *b, (*a - *b) * twiddle_inverse
        QM31Field.QM31 memory sum = QM31Field.add(a, b);
        QM31Field.QM31 memory diff = QM31Field.sub(a, b);
        QM31Field.QM31 memory twiddleQM31 = QM31Field.fromM31(twiddleInverse, 0, 0, 0);
        QM31Field.QM31 memory diffMulTwiddle = QM31Field.mul(diff, twiddleQM31);
        
        return (sum, diffMulTwiddle);
    }

    /// @notice Accumulates line evaluations with a folding alpha
    /// @dev Matches Rust accumulate_line: layer_query_evals *= alpha^2, then += column_query_evals
    /// @param layerQueryEvals Existing layer query evaluations
    /// @param foldedColumnEvals Folded column evaluations to accumulate
    /// @param foldingAlpha Folding coefficient
    /// @return Updated layer query evaluations
    function accumulateLine(
        QM31Field.QM31[] memory layerQueryEvals,
        QM31Field.QM31[] memory foldedColumnEvals,
        QM31Field.QM31 memory foldingAlpha
    ) internal pure returns (QM31Field.QM31[] memory) {

        require(
            layerQueryEvals.length == foldedColumnEvals.length,
            "Array length mismatch"
        );

        QM31Field.QM31 memory foldingAlphaSquared = QM31Field.mul(foldingAlpha, foldingAlpha);


        for (uint256 i = 0; i < layerQueryEvals.length; i++) {
            
  
            // // Rust: *curr_layer_eval *= folding_alpha_squared;
            layerQueryEvals[i] = QM31Field.mul(layerQueryEvals[i], foldingAlphaSquared);

            // Rust: *curr_layer_eval += *folded_column_eval;
            layerQueryEvals[i] = QM31Field.add(
                layerQueryEvals[i],
                foldedColumnEvals[i]
            );
        
        }
        
        return layerQueryEvals;
    }

    /// @notice Folds line sparse evaluations (matches Rust SparseEvaluation::fold_line)
    /// @dev For each subset: creates fold domain, calls fold_line, returns first folded value
    /// @param sparseEval Sparse evaluation structure to fold
    /// @param foldingAlpha Folding coefficient
    /// @param sourceDomain Source line domain (coset)
    /// @return foldedEvals Folded evaluations (one per subset)
    function foldLineSparseEvals(
        SparseEvaluation memory sparseEval,
        QM31Field.QM31 memory foldingAlpha,
        CosetM31.CosetStruct memory sourceDomain
    ) internal pure returns (QM31Field.QM31[] memory foldedEvals) {
        // Result has one value per subset
        foldedEvals = new QM31Field.QM31[](sparseEval.subsetEvals.length);

        // Use the provided source domain directly
        // Rust: LineDomain wraps a Coset
        CosetM31.CosetStruct memory sourceCoset = sourceDomain;

        // Iterate through pairs (subset_evals, subset_domain_initial_indexes)
        for (uint256 i = 0; i < sparseEval.subsetEvals.length; i++) {
            QM31Field.QM31[] memory subsetEval = sparseEval.subsetEvals[i];
            uint256 domainInitialIndex = sparseEval.subsetDomainIndexInitials[i];

            // Rust: let fold_domain_initial = source_domain.coset().index_at(domain_initial_index);
            // This returns CirclePointIndex, not a point!
            CosetM31.CirclePointIndex memory foldDomainInitialIndex = CosetM31.indexAt(
                sourceCoset,
                domainInitialIndex
            );

            // Rust: let fold_domain = LineDomain::new(Coset::new(fold_domain_initial, FOLD_STEP));
            // Coset::new creates a coset with:
            //   - initial_index = fold_domain_initial
            //   - step_size = CirclePointIndex::subgroup_gen(FOLD_STEP)
            //   - initial = initial_index.to_point()
            //   - step = step_size.to_point()
            CosetM31.CosetStruct memory foldCoset = CosetM31.newCoset(
                foldDomainInitialIndex,
                FOLD_STEP
            );

            // Rust: let (_, folded_values) = fold_line(&eval, fold_domain, fold_alpha);
            // Returns (new_domain, folded_values)
            QM31Field.QM31[] memory foldedValues = _foldLineForSubset(
                subsetEval,
                foldCoset,
                foldingAlpha
            );

            // Rust: folded_values[0]
            foldedEvals[i] = foldedValues[0];
        }
    }

    /// @notice Helper to fold a single subset's line evaluations
    /// @dev Implements the fold_line logic from Rust
    /// @param eval Evaluations from subset
    /// @param domain Line domain for folding
    /// @param alpha Folding coefficient
    /// @return foldedValues Folded evaluation array
    function _foldLineForSubset(
        QM31Field.QM31[] memory eval,
        CosetM31.CosetStruct memory domain,
        QM31Field.QM31 memory alpha
    ) private pure returns (QM31Field.QM31[] memory foldedValues) {
        require(eval.length >= 2, "Evaluation too small");

        // Rust: folded_values has length n/2 where n is eval.length
        uint256 foldedLength = eval.length >> FOLD_STEP; // eval.length / 2
        foldedValues = new QM31Field.QM31[](foldedLength);

        // Rust: eval.iter().tuples().enumerate().map(|(i, (&f_x, &f_neg_x))| { ... })
        for (uint256 i = 0; i < foldedLength; i++) {
            QM31Field.QM31 memory f_x = eval[i * 2];
            QM31Field.QM31 memory f_neg_x = eval[i * 2 + 1];

            // Rust: let x = domain.at(bit_reverse_index(i << FOLD_STEP, domain.log_size()));
            uint256 bitReversedIndex = _bitReverseIndex(
                i << FOLD_STEP,
                domain.logSize + FOLD_STEP
            );
            CirclePointM31.Point memory x = CosetM31.at(domain, bitReversedIndex);

            // Rust: ibutterfly(&mut f0, &mut f1, x.inverse());
            // f0 + alpha * f1
            QM31Field.QM31 memory f0 = f_x;
            QM31Field.QM31 memory f1 = f_neg_x;

            // Apply ibutterfly: (f0, f1) <- ((f0 + f1) / 2, (f0 - f1) / (2 * x))
            // Simplified version for now - would need proper implementation
            // For now use: f0 = (f_x + f_neg_x), f1 = (f_x - f_neg_x) / x_inv
            
            // Compute x_inverse (for M31 point)
            uint32 xInverse = M31Field.inverse(x.x);
            QM31Field.QM31 memory xInvQM31 = QM31Field.fromM31(xInverse, 0, 0, 0);

            // ibutterfly computation
            QM31Field.QM31 memory sum = QM31Field.add(f_x, f_neg_x);
            QM31Field.QM31 memory diff = QM31Field.sub(f_x, f_neg_x);
            
            f0 = sum;
            f1 = QM31Field.mul(diff, xInvQM31);

            // Rust: f0 + alpha * f1
            foldedValues[i] = QM31Field.add(f0, QM31Field.mul(alpha, f1));
        }
    }

    /// @notice Verifies and folds a single inner layer
    /// @dev Full implementation matching Rust verify_and_fold:
    ///      1. Compute decommitment positions and rebuild evals
    ///      2. Verify Merkle decommitment
    ///      3. Fold sparse evaluations using fold_line
    ///      4. Return folded queries and evals
    /// @param layer Inner layer verifier
    /// @param layerQueries Current layer queries
    /// @param layerQueryEvals Current layer query evaluations
    /// @return success True if layer verification passes
    /// @return newQueries Folded queries for next layer
    /// @return newQueryEvals Folded evaluations for next layer
    function verifyAndFoldLayer(
        FriInnerLayerVerifier memory layer,
        Queries memory layerQueries,
        QM31Field.QM31[] memory layerQueryEvals
    )
        internal
        pure
        returns (
            bool success,
            Queries memory newQueries,
            QM31Field.QM31[] memory newQueryEvals
        )
    {

        // Rust: assert_eq!(queries.log_domain_size, self.domain.log_size());
        require(
            layerQueries.logDomainSize == layer.domain.logSize,
            "Queries sampled on wrong domain for inner layer"
        );

        // Initialize witness iterator
        WitnessIterator memory witnessIter = WitnessIterator({
            witness: layer.proof.friWitness,
            index: 0
        });

        // Rust: compute_decommitment_positions_and_rebuild_evals(&queries, &evals_at_queries, &mut fri_witness, FOLD_STEP)
        (
            uint256[] memory decommitmentPositions,
            SparseEvaluation memory sparseEvaluation
        ) = computeDecommitmentPositionsAndRebuildEvals(
                layerQueries,
                layerQueryEvals,
                witnessIter,
                FOLD_STEP
            );


        // Rust: Check all proof evals have been consumed
        if (witnessIter.index != witnessIter.witness.length) {
            return (false, layerQueries, layerQueryEvals);
        }

        // Rust: Extract decommitted M31 values
        // sparse_evaluation.subset_evals.iter().flatten().flat_map(|qm31| qm31.to_m31_array()).collect_vec()
        uint256 totalM31Values = 0;
        for (uint256 i = 0; i < sparseEvaluation.subsetEvals.length; i++) {
            totalM31Values += sparseEvaluation.subsetEvals[i].length * 4; // 4 M31 per QM31
        }
        
        uint32[] memory decommittedValues = new uint32[](totalM31Values);
        uint256 valueIdx = 0;
        for (uint256 i = 0; i < sparseEvaluation.subsetEvals.length; i++) {
            for (uint256 j = 0; j < sparseEvaluation.subsetEvals[i].length; j++) {
                QM31Field.QM31 memory qm31 = sparseEvaluation.subsetEvals[i][j];
                decommittedValues[valueIdx++] = qm31.first.real;
                decommittedValues[valueIdx++] = qm31.first.imag;
                decommittedValues[valueIdx++] = qm31.second.real;
                decommittedValues[valueIdx++] = qm31.second.imag;
            }
        }

        // Rust: Create MerkleVerifier with column log sizes (4 columns of same log size)
        // vec![self.domain.log_size(); SECURE_EXTENSION_DEGREE]
        uint32[] memory columnLogSizes = new uint32[](SECURE_EXTENSION_DEGREE);
        for (uint256 i = 0; i < SECURE_EXTENSION_DEGREE; i++) {
            columnLogSizes[i] = layer.domain.logSize;
        }

        MerkleVerifier.MerkleTree memory verifier = MerkleVerifier.createMerkleTree(
            layer.proof.commitment,
            columnLogSizes
        );

        // Decode decommitment proof
        MerkleVerifier.Decommitment memory decommitment = _decodeDecommitment(
            layer.proof.decommitment
        );

        // Rust: Verify Merkle proof with single log size
        // BTreeMap::from_iter([(self.domain.log_size(), decommitment_positions)])
        MerkleVerifier.QueriesPerLogSize[]
            memory queriesPerLogSize = new MerkleVerifier.QueriesPerLogSize[](1);
        queriesPerLogSize[0] = MerkleVerifier.QueriesPerLogSize({
            logSize: layer.domain.logSize,
            queries: decommitmentPositions
        });

        // Verify - MerkleVerifier.verify will revert on failure
        MerkleVerifier.verify(
            verifier,
            queriesPerLogSize,
            decommittedValues,
            decommitment
        );

        // If we get here, verification succeeded

        // Rust: Fold queries for next layer
        // let folded_queries = queries.fold(FOLD_STEP);
        newQueries = foldQueries(layerQueries, FOLD_STEP);

        // Rust: Fold sparse evaluations using fold_line
        // let folded_evals = sparse_evaluation.fold_line(self.folding_alpha, self.domain);
        newQueryEvals = foldLineSparseEvals(
            sparseEvaluation,
            layer.foldingAlpha,
            layer.domain
        );

        return (true, newQueries, newQueryEvals);
    }

    /// @notice Evaluates a polynomial at a given point using hierarchical folding
    /// @dev Matches Rust LinePoly.eval_at_point(x: SecureField)
    /// Uses ITERATIVE implementation to avoid expensive recursion in Solidity
    /// Rust uses bit-reversed coefficients and hierarchical folding with doublings
    /// @param poly Polynomial coefficients in bit-reversed order (as stored in LinePoly)
    /// @param x Evaluation point (QM31)
    /// @return result Polynomial evaluation result
    function evaluatePolynomialAtPoint(
        QM31Field.QM31[] memory poly,
        QM31Field.QM31 memory x
    ) internal pure returns (QM31Field.QM31 memory result) {
        if (poly.length == 0) {
            return QM31Field.zero();
        }

        // Rust: let mut doublings = Vec::new();
        // for _ in 0..self.log_size {
        //     doublings.push(x);
        //     x = CirclePoint::double_x(x);
        // }
        uint32 logSize = _log2(poly.length);
        QM31Field.QM31[] memory doublings = new QM31Field.QM31[](logSize);
        
        QM31Field.QM31 memory currentX = x;
        for (uint256 i = 0; i < logSize; i++) {
            doublings[i] = currentX;
            // CirclePoint::double_x(x) = 2*x^2 - 1
            QM31Field.QM31 memory xSquared = QM31Field.mul(currentX, currentX);
            QM31Field.QM31 memory twoXSquared = QM31Field.add(xSquared, xSquared); // 2*x^2
            currentX = QM31Field.sub(twoXSquared, QM31Field.one()); // 2*x^2 - 1
        }
        
        // Rust: fold(&self.coeffs, &doublings)
        // ITERATIVE hierarchical folding (much cheaper than recursion in Solidity)
        result = _foldPolynomialIterative(poly, doublings);
    }
    
    /// @notice ITERATIVE hierarchical folding for polynomial evaluation
    /// @dev Iterative version of Rust fold() - avoids expensive recursion
    /// Processes folding factors from last to first (bottom-up)
    /// fold(values, [x, y, z]) computes tree: ((a+z*b)+(c+z*d)*y)+((e+z*f)+(g+z*h)*y)*x
    /// @param values Polynomial coefficients (bit-reversed)
    /// @param foldingFactors Doubling sequence [x, double_x(x), ...]
    /// @return result Folded result
    function _foldPolynomialIterative(
        QM31Field.QM31[] memory values,
        QM31Field.QM31[] memory foldingFactors
    ) private pure returns (QM31Field.QM31 memory result) {
        uint256 n = values.length;
        require(n == (1 << foldingFactors.length), "Invalid folding factors length");
        
        // Create working buffer - we'll fold in place
        QM31Field.QM31[] memory buffer = new QM31Field.QM31[](n);
        for (uint256 i = 0; i < n; i++) {
            buffer[i] = values[i];
        }
        
        // Process each folding factor from last to first (bottom-up)
        // Level 0 (last factor): pairs of values
        // Level 1: pairs of results from level 0
        // etc.
        uint256 currentSize = n;
        for (uint256 level = foldingFactors.length; level > 0; level--) {
            QM31Field.QM31 memory factor = foldingFactors[level - 1];
            uint256 halfSize = currentSize / 2;
            
            // Fold pairs: buffer[i] = buffer[2*i] + buffer[2*i+1] * factor
            for (uint256 i = 0; i < halfSize; i++) {
                QM31Field.QM31 memory lhs = buffer[i * 2];
                QM31Field.QM31 memory rhs = buffer[i * 2 + 1];
                // lhs + rhs * factor
                buffer[i] = QM31Field.add(lhs, QM31Field.mul(rhs, factor));
            }
            
            currentSize = halfSize;
        }
        
        return buffer[0];
    }
    
    /// @notice Helper to calculate log2 of a power of 2
    function _log2(uint256 n) private pure returns (uint32) {
        require(n > 0 && (n & (n - 1)) == 0, "Not a power of 2");
        uint32 log = 0;
        while (n > 1) {
            n >>= 1;
            log++;
        }
        return log;
    }

    /// @notice Extract column log sizes from circle polynomial degree bounds
    /// @param columnBounds Array of degree bounds
    /// @return logSizes Array of corresponding log sizes
    function _extractColumnLogSizes(
        CirclePolyDegreeBound.Bound[] memory columnBounds
    ) internal pure returns (uint32[] memory logSizes) {
        logSizes = new uint32[](columnBounds.length);
        for (uint256 i = 0; i < columnBounds.length; i++) {
            logSizes[i] = columnBounds[i].logDegreeBound;
        }
    }

    /// @notice Decode Merkle decommitment from bytes
    /// @param encodedDecommitment Encoded decommitment data
    /// @return decommitment Decoded Merkle decommitment
    function _decodeDecommitment(
        bytes memory encodedDecommitment
    ) internal pure returns (MerkleVerifier.Decommitment memory decommitment) {
        // For now, assume the encoded data is structured as:
        // [hashWitnessLength(32)] + [hashWitness...] + [columnWitnessLength(32)] + [columnWitness...]

        require(encodedDecommitment.length >= 64, "Decommitment too short");

        uint256 offset = 0;

        // Decode hash witness length
        uint256 hashWitnessLength;
        assembly {
            hashWitnessLength := mload(
                add(add(encodedDecommitment, 0x20), offset)
            )
        }
        offset += 32;

        // Decode hash witness
        decommitment.hashWitness = new bytes32[](hashWitnessLength);
        for (uint256 i = 0; i < hashWitnessLength; i++) {
            assembly {
                let value := mload(add(add(encodedDecommitment, 0x20), offset))
                mstore(
                    add(
                        add(mload(add(decommitment, 0x00)), 0x20),
                        mul(i, 0x20)
                    ),
                    value
                )
            }
            offset += 32;
        }

        // Decode column witness length
        uint256 columnWitnessLength;
        assembly {
            columnWitnessLength := mload(
                add(add(encodedDecommitment, 0x20), offset)
            )
        }
        offset += 32;

        // Decode column witness
        decommitment.columnWitness = new uint32[](columnWitnessLength);
        for (uint256 i = 0; i < columnWitnessLength; i++) {
            uint32 value;
            assembly {
                value := mload(add(add(encodedDecommitment, 0x20), offset))
            }
            decommitment.columnWitness[i] = value;
            offset += 32;
        }
    }

    /// @notice Extract decommitted values from sparse evaluations (matches Rust)
    /// @dev Rust: decommitmented_values.extend(sparse_evaluation.subset_evals.iter().flatten().flat_map(|qm31| qm31.to_m31_array()));
    /// @param sparseEvals Sparse evaluations from first layer
    /// @return decommittedValues M31 field elements as uint32 array
    function _extractDecommittedValues(
        QM31Field.QM31[][] memory sparseEvals
    ) internal pure returns (uint32[] memory decommittedValues) {
        // Count total number of M31 elements (each QM31 has 4 M31 elements)
        uint256 totalM31s = 0;
        for (uint256 i = 0; i < sparseEvals.length; i++) {
            totalM31s += sparseEvals[i].length * 4; // 4 M31 per QM31
        }

        decommittedValues = new uint32[](totalM31s);
        uint256 index = 0;

        // Extract M31 values from each QM31 in sparse evaluations
        for (uint256 i = 0; i < sparseEvals.length; i++) {
            for (uint256 j = 0; j < sparseEvals[i].length; j++) {
                QM31Field.QM31 memory qm31 = sparseEvals[i][j];
                // Convert QM31 to M31 array (matches Rust qm31.to_m31_array())
                decommittedValues[index++] = qm31.first.real;
                decommittedValues[index++] = qm31.first.imag;
                decommittedValues[index++] = qm31.second.real;
                decommittedValues[index++] = qm31.second.imag;
            }
        }

        return decommittedValues;
    }

    /// @notice Prepare decommitment positions by log size (matches Rust decommitment_positions_by_log_size)
    /// @param columnCommitmentDomains Column domains
    /// @param queries Query positions
    /// @return queriesPerLogSize Queries organized by log size
    function _prepareDecommitmentPositions(
        CircleDomain.CircleDomainStruct[] memory columnCommitmentDomains,
        Queries memory queries
    )
        internal
        pure
        returns (MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize)
    {
        // Group queries by unique log sizes (matches Rust decommitment_positions_by_log_size.insert)
        // Count unique log sizes first
        uint256 uniqueLogSizes = 0;
        for (uint256 i = 0; i < columnCommitmentDomains.length; i++) {
            uint32 logSize = CircleDomain.logSize(columnCommitmentDomains[i]);
            bool found = false;
            for (uint256 j = 0; j < i; j++) {
                if (
                    CircleDomain.logSize(columnCommitmentDomains[j]) == logSize
                ) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                uniqueLogSizes++;
            }
        }

        queriesPerLogSize = new MerkleVerifier.QueriesPerLogSize[](
            uniqueLogSizes
        );
        uint256 outputIndex = 0;

        for (uint256 i = 0; i < columnCommitmentDomains.length; i++) {
            uint32 columnLogSize = CircleDomain.logSize(
                columnCommitmentDomains[i]
            );

            // Check if we already processed this log size
            bool alreadyProcessed = false;
            for (uint256 j = 0; j < outputIndex; j++) {
                if (queriesPerLogSize[j].logSize == columnLogSize) {
                    alreadyProcessed = true;
                    break;
                }
            }

            if (!alreadyProcessed) {
                // Fold queries for this column's log size if needed
                // Rust: let column_queries = queries.fold(queries.log_domain_size - column_domain.log_size());
                uint256[] memory columnQueries;
                if (queries.logDomainSize >= columnLogSize) {
                    uint32 foldSteps = queries.logDomainSize - columnLogSize;
                    columnQueries = _foldQueriesForLogSize(
                        queries.positions,
                        foldSteps
                    );
                } else {
                    columnQueries = queries.positions;
                }

                queriesPerLogSize[outputIndex] = MerkleVerifier
                    .QueriesPerLogSize({
                        logSize: columnLogSize,
                        queries: columnQueries
                    });
                outputIndex++;
            }
        }

        return queriesPerLogSize;
    }

    /// @notice Fold query positions for specific log size
    /// @param positions Original query positions
    /// @param foldSteps Number of fold steps
    /// @return foldedPositions Folded query positions
    function _foldQueriesForLogSize(
        uint256[] memory positions,
        uint32 foldSteps
    ) internal pure returns (uint256[] memory foldedPositions) {
        if (foldSteps == 0) {
            return positions;
        }

        uint256 divisor = 1 << foldSteps; // 2^foldSteps

        // First pass: fold all positions
        uint256[] memory tempFolded = new uint256[](positions.length);
        for (uint256 i = 0; i < positions.length; i++) {
            tempFolded[i] = positions[i] / divisor;
        }

        // Second pass: deduplicate (like Rust BTreeSet)
        uint256[] memory uniquePositions = new uint256[](positions.length);
        uint256 uniqueCount = 0;

        for (uint256 i = 0; i < tempFolded.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < uniqueCount; j++) {
                if (uniquePositions[j] == tempFolded[i]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                uniquePositions[uniqueCount] = tempFolded[i];
                uniqueCount++;
            }
        }

        // Copy to correctly sized array
        foldedPositions = new uint256[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; i++) {
            foldedPositions[i] = uniquePositions[i];
        }

        return foldedPositions;
    }

    // =============================================================================
    // COMPUTE DECOMMITMENT POSITIONS AND REBUILD EVALS
    // =============================================================================

    /// @notice Sparse evaluation structure (matches Rust SparseEvaluation)
    struct SparseEvaluation {
        QM31Field.QM31[][] subsetEvals; // subset_evals: Vec<Vec<SecureField>>
        uint256[] subsetDomainIndexInitials; // subset_domain_initial_indexes: Vec<usize>
    }

    /// @notice Iterator for witness evaluations
    struct WitnessIterator {
        QM31Field.QM31[] witness;
        uint256 index;
    }

    /// @notice Computes decommitment positions and rebuilds evaluations (matches Rust compute_decommitment_positions_and_rebuild_evals)
    /// @dev Groups queries by subset, fills in witness values where needed
    /// @param queries Query positions (already folded to appropriate domain size)
    /// @param queryEvals Evaluations at query positions
    /// @param witnessIter Iterator over witness evaluations
    /// @param foldStep Fold step (typically CIRCLE_TO_LINE_FOLD_STEP = 1)
    /// @return decommitmentPositions All positions that need to be decommitted
    /// @return sparseEval Sparse evaluation structure for folding
    function computeDecommitmentPositionsAndRebuildEvals(
        Queries memory queries,
        QM31Field.QM31[] memory queryEvals,
        WitnessIterator memory witnessIter,
        uint32 foldStep
    )
        internal
        pure
        returns (
            uint256[] memory decommitmentPositions,
            SparseEvaluation memory sparseEval
        )
    {
        require(
            queries.positions.length == queryEvals.length,
            "Query/eval length mismatch"
        );

        uint256 subsetSize = 1 << foldStep; // 2^fold_step

        // Count number of subsets by grouping queries
        uint256 numSubsets = 0;
        uint256 i = 0;
        while (i < queries.positions.length) {
            uint256 subsetId = queries.positions[i] >> foldStep;
            numSubsets++;
            // Skip all queries in same subset
            while (
                i < queries.positions.length &&
                (queries.positions[i] >> foldStep) == subsetId
            ) {
                i++;
            }
        }

        // Allocate arrays
        uint256[] memory allDecommitmentPositions = new uint256[](
            numSubsets * subsetSize
        );
        QM31Field.QM31[][] memory subsetEvals = new QM31Field.QM31[][](
            numSubsets
        );
        uint256[] memory subsetDomainIndexInitials = new uint256[](numSubsets);

        uint256 queryIdx = 0;
        uint256 decommitPosIdx = 0;
        uint256 subsetIdx = 0;

        // Group queries by subset
        while (queryIdx < queries.positions.length) {
            uint256 firstQueryInSubset = queries.positions[queryIdx];
            uint256 subsetId = firstQueryInSubset >> foldStep;
            uint256 subsetStart = subsetId << foldStep;

            // Allocate this subset's evaluations
            subsetEvals[subsetIdx] = new QM31Field.QM31[](subsetSize);

            // Fill in all positions in this subset
            for (uint256 pos = 0; pos < subsetSize; pos++) {
                uint256 position = subsetStart + pos;
                allDecommitmentPositions[decommitPosIdx++] = position;

                // Check if this position matches a query
                if (
                    queryIdx < queries.positions.length &&
                    queries.positions[queryIdx] == position
                ) {
                    // Use query eval
                    subsetEvals[subsetIdx][pos] = queryEvals[queryIdx];
                    queryIdx++;
                } else {
                    // Use witness eval
                    require(
                        witnessIter.index < witnessIter.witness.length,
                        "Insufficient witness"
                    );
                    subsetEvals[subsetIdx][pos] = witnessIter.witness[
                        witnessIter.index
                    ];
                    witnessIter.index++;
                }
            }

            // Store bit-reversed subset start as domain index initial
            subsetDomainIndexInitials[subsetIdx] = _bitReverseIndex(
                subsetStart,
                queries.logDomainSize
            );

            subsetIdx++;
        }

        decommitmentPositions = allDecommitmentPositions;
        sparseEval = SparseEvaluation({
            subsetEvals: subsetEvals,
            subsetDomainIndexInitials: subsetDomainIndexInitials
        });
    }

    // Helper functions to reduce stack depth in verifyFirstLayer
    
    function _validateFirstLayerInputs(
        FriFirstLayerVerifier memory firstLayer,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals
    ) private pure {
        if (firstLayerQueryEvals.length != firstLayer.columnBounds.length) {
            revert("FIRST LAYER COLUMN COUNT MISMATCH");
        }
        uint32 maxColumnLogSize = CircleDomain.logSize(firstLayer.columnCommitmentDomains[0]);
        require(queries.logDomainSize == maxColumnLogSize, "Queries sampled on wrong domain");
    }

    function _processAllColumns(
        FriFirstLayerVerifier memory firstLayer,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals,
        WitnessIterator memory witnessIter,
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize,
        SparseEvaluation[] memory sparseEvalsResult,
        QM31Field.QM31[][] memory sparseEvals
    ) private pure returns (uint256 numUniqueLogSizes, uint256 totalDecommittedM31Values) {
        numUniqueLogSizes = 0;
        totalDecommittedM31Values = 0;

        for (uint256 colIdx = 0; colIdx < firstLayer.columnCommitmentDomains.length; colIdx++) {
            (numUniqueLogSizes, totalDecommittedM31Values) = _processColumnInternal(
                firstLayer, queries, firstLayerQueryEvals, witnessIter, colIdx,
                uniqueLogSizes, decommitmentsByLogSize, sparseEvalsResult, sparseEvals,
                numUniqueLogSizes, totalDecommittedM31Values
            );
        }

        return (numUniqueLogSizes, totalDecommittedM31Values);
    }

    function _processColumnInternal(
        FriFirstLayerVerifier memory firstLayer,
        Queries memory queries,
        QM31Field.QM31[][] memory firstLayerQueryEvals,
        WitnessIterator memory witnessIter,
        uint256 colIdx,
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize,
        SparseEvaluation[] memory sparseEvalsResult,
        QM31Field.QM31[][] memory sparseEvals,
        uint256 numUniqueLogSizes,
        uint256 totalDecommittedM31Values
    ) private pure returns (uint256, uint256) {
        uint32 columnLogSize = CircleDomain.logSize(firstLayer.columnCommitmentDomains[colIdx]);
        uint32 foldSteps = queries.logDomainSize - columnLogSize;
        Queries memory columnQueries = foldQueries(queries, foldSteps);

        (uint256[] memory columnDecommitmentPositions, SparseEvaluation memory sparseEval) = 
            computeDecommitmentPositionsAndRebuildEvals(
                columnQueries, firstLayerQueryEvals[colIdx], witnessIter, CIRCLE_TO_LINE_FOLD_STEP
            );

        // Store decommitment positions
        bool found = false;
        for (uint256 i = 0; i < numUniqueLogSizes; i++) {
            if (uniqueLogSizes[i] == columnLogSize) {
                found = true;
                break;
            }
        }
        if (!found) {
            uniqueLogSizes[numUniqueLogSizes] = columnLogSize;
            decommitmentsByLogSize[numUniqueLogSizes] = columnDecommitmentPositions;
            numUniqueLogSizes++;
        }

        sparseEvalsResult[colIdx] = sparseEval;
        sparseEvals[colIdx] = _flattenSparseEval(sparseEval);
        totalDecommittedM31Values += _countM31Values(sparseEval);

        return (numUniqueLogSizes, totalDecommittedM31Values);
    }

    function _extractDecommittedValues(
        QM31Field.QM31[][] memory sparseEvals,
        uint256 totalDecommittedM31Values
    ) private pure returns (uint32[] memory decommittedValues) {
        decommittedValues = new uint32[](totalDecommittedM31Values);
        uint256 valueIdx = 0;
        for (uint256 colIdx = 0; colIdx < sparseEvals.length; colIdx++) {
            for (uint256 i = 0; i < sparseEvals[colIdx].length; i++) {
                QM31Field.QM31 memory qm31 = sparseEvals[colIdx][i];
                decommittedValues[valueIdx++] = qm31.first.real;
                decommittedValues[valueIdx++] = qm31.first.imag;
                decommittedValues[valueIdx++] = qm31.second.real;
                decommittedValues[valueIdx++] = qm31.second.imag;
            }
        }
    }

    function _createColumnLogSizes(
        FriFirstLayerVerifier memory firstLayer
    ) private pure returns (uint32[] memory columnLogSizes) {
        columnLogSizes = new uint32[](
            firstLayer.columnCommitmentDomains.length * SECURE_EXTENSION_DEGREE
        );
        for (uint256 i = 0; i < firstLayer.columnCommitmentDomains.length; i++) {
            uint32 logSize = CircleDomain.logSize(firstLayer.columnCommitmentDomains[i]);
            for (uint256 j = 0; j < SECURE_EXTENSION_DEGREE; j++) {
                columnLogSizes[i * SECURE_EXTENSION_DEGREE + j] = logSize;
            }
        }
    }

    function _createQueriesPerLogSize(
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize,
        uint256 numUniqueLogSizes
    ) private pure returns (MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize) {
        queriesPerLogSize = new MerkleVerifier.QueriesPerLogSize[](numUniqueLogSizes);
        for (uint256 i = 0; i < numUniqueLogSizes; i++) {
            queriesPerLogSize[i] = MerkleVerifier.QueriesPerLogSize({
                logSize: uniqueLogSizes[i],
                queries: decommitmentsByLogSize[i]
            });
        }
    }

    function _verifyMerkleProofWithValues(
        FriFirstLayerVerifier memory firstLayer,
        QM31Field.QM31[][] memory sparseEvals,
        uint256 totalDecommittedM31Values,
        uint32[] memory uniqueLogSizes,
        uint256[][] memory decommitmentsByLogSize,
        uint256 numUniqueLogSizes
    ) private pure {
        uint32[] memory decommittedValues = _extractDecommittedValues(sparseEvals, totalDecommittedM31Values);
        uint32[] memory columnLogSizes = _createColumnLogSizes(firstLayer);
        
        MerkleVerifier.MerkleTree memory verifier = MerkleVerifier.createMerkleTree(
            firstLayer.proof.commitment, columnLogSizes
        );

        MerkleVerifier.Decommitment memory decommitment = _decodeDecommitment(firstLayer.proof.decommitment);
        MerkleVerifier.QueriesPerLogSize[] memory queriesPerLogSize = 
            _createQueriesPerLogSize(uniqueLogSizes, decommitmentsByLogSize, numUniqueLogSizes);
        _sortQueriesPerLogSizeAscending(queriesPerLogSize);
        MerkleVerifier.verify(verifier, queriesPerLogSize, decommittedValues, decommitment);
    }
}
