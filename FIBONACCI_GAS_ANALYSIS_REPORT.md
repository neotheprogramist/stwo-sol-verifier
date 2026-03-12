# 📊 STWO Verifier - Raport Analizy Zużycia Gazu Fibonacci circuit

**Źródło danych:** gas_profiling_logs.txt

---

## 🎯 Podsumowanie Wykonawcze

**Całkowite zużycie gazu: 16,296,961 gas**

### Top 3 Komponenty (według zużycia):
1. **FRI Verification:** 12,648,215 gas (77.6%)
2. **OODS Verification:** 2,423,970 gas (14.9%)
3. **Sample Points Computation:** 601,181 gas (3.7%)

---

## 📈 Analiza Top-Level - Główne Komponenty

### Weryfikacja zgodnie z logami `gas_profiling_logs.txt`:

| Komponent | Gas (z logów) | % całości | Status |
|-----------|---------------|-----------|---------|
| **_performVerificationSteps** | 15,928,434 | 97.7% | ✅ Potwierdzone |
| _initializeVerification | 342,492 | 2.1% | ✅ Potwierdzone |
| _createSecurePoly | 19,191 | 0.1% | ✅ Potwierdzone |
| Overhead | 6,844 | 0.04% | Różnica pomiarowa |
| **TOTAL** | **16,296,961** | **100%** | ✅ |

---

## 🔬 Dekompozycja: _performVerificationSteps (15.9M gas)

### Podział na fazy weryfikacji:

```
├─ _performFriVerification        12,648,215 gas (79.4%)  🔥 NAJWIĘKSZY
├─ _performOodsVerification         2,423,970 gas (15.2%)  
├─ _computeSamplePoints               601,181 gas ( 3.8%)  
├─ _performCompositionCommit          181,608 gas ( 1.1%)  
├─ getRandomPointFromState             63,918 gas ( 0.4%)  
└─ Overhead                             9,542 gas ( 0.06%)
```

**Kontrakt:** `contracts/verifier/StwoVerifier.sol`
- Główny koordynator weryfikacji STARK
- Zarządza przepływem między komponentami
- Integruje FRI, OODS, Merkle verification

---

## 🔥 Deep Dive #1: FRI Verification (12.6M gas - 77.6%)

### Breakdown _performFriVerification:

| Operacja | Gas | % FRI | % Total | Kontrakt |
|----------|-----|-------|---------|----------|
| **_performFinalFriCheck** | 9,100,409 | 71.9% | 55.8% | StwoVerifier.sol |
| **FriVerifier.commit** | 3,363,215 | 26.6% | 20.6% | pcs/FriVerifier.sol |
| flattenCols | 34,775 | 0.3% | 0.2% | verifier/ProofParser.sol |
| mixFelts | 54,185 | 0.4% | 0.3% | core/KeccakChannelLib.sol |
| drawSecureFelt | 38,705 | 0.3% | 0.2% | core/KeccakChannelLib.sol |
| calculateBounds | 25,194 | 0.2% | 0.2% | core/CommitmentSchemeVerifierLib.sol |
| _verifyProofOfWork | 11,824 | 0.1% | 0.1% | core/KeccakChannelLib.sol |
| mixU64 | 4,314 | 0.03% | 0.03% | core/KeccakChannelLib.sol |
| Overhead | 15,594 | 0.1% | 0.1% | - |

### 📦 Opis komponentów FRI:

#### **FriVerifier.sol** (`contracts/pcs/FriVerifier.sol`)
- Implementacja Fast Reed-Solomon IOP (Interactive Oracle Proof)
- **commit()**: Buduje commitment tree dla FRI
- **decommit()**: Weryfikuje decommitment queries
- **friAnswers()**: Oblicza quotient polynomials
- Wykorzystuje folding do redukcji degree bounds

#### **KeccakChannelLib.sol** (`contracts/core/KeccakChannelLib.sol`)
- Fiat-Shamir transform przez Keccak256
- Generuje losowość dla protokołu
- Weryfikacja Proof-of-Work
- Mixing operations dla security

---

## 🎯 Deep Dive #2: _performFinalFriCheck (9.1M gas - 55.8%)

### Struktura _verifyFri (9.0M gas):

```
_verifyFri (9,018,655 gas)
├─ FriVerifier.decommit          5,436,220 gas (60.3%)  🔥 KRYTYCZNY
├─ friAnswers                    2,508,260 gas (27.8%)  🔥 
├─ _verifyMerkleDecommitments      566,559 gas ( 6.3%)  
├─ sampleQueryPositions            421,756 gas ( 4.7%)  
├─ getNColumnsPerLogSize            68,420 gas ( 0.8%)  
└─ columnLogSizes                    5,709 gas ( 0.06%)
```

### 📦 Komponenty MerkleVerifier:

#### **MerkleVerifier.sol** (`contracts/vcs/MerkleVerifier.sol`)
- Vector Commitment Scheme przez Merkle trees
- Weryfikacja decommitment paths
- Obsługa multiple log sizes per tree
- Batch verification dla efficiency

**_verifyMerkleDecommitments breakdown:**
- Tree 0: 6,982 gas (verification: 302 gas)
- Tree 1: 242,562 gas (verification: 226,808 gas) 🔥
- Tree 2: 299,269 gas (verification: 280,538 gas) 🔥

---

## 🔬 Ultra Deep: FriVerifier.decommit (5.4M gas - 33.4%)

### 4-Step Decommitment Process:

```
decommitOnQueries (5,344,182 gas)
├─ STEP 3: decommitInnerLayers    4,548,936 gas (85.1%)  🔥 BOTTLENECK
├─ STEP 1: decommitFirstLayer       568,162 gas (10.6%)  
├─ STEP 4: decommitLastLayer        208,235 gas ( 3.9%)  
└─ STEP 2: foldQueries                5,567 gas ( 0.1%)  
```

### 🎯 Critical Path: decommitInnerLayers (4.5M gas - 27.9% całości)

**Struktura 3 warstw:**

| Layer | Total Gas | % Inner | Operacje |
|-------|-----------|---------|----------|
| Layer 0 | 1,793,588 | 39.4% | Największa, pierwsze folding |
| Layer 1 | 1,854,560 | 40.8% | Największa, środkowe folding |
| Layer 2 | 867,074 | 19.1% | Najmniejsza, końcowe folding |

### Dekompozycja operacji per-layer:

```
verifyAndFoldLayer (średnio 889,551 gas/layer):

1. foldLineSparseEvals        576,549 gas (64.8%)  🔥 GŁÓWNY KOSZT
   │  └─ _foldLineForSubset    (algebraic folding)
   │     └─ _ibutterfly         (FFT butterfly operations)
   
2. MerkleVerifier.verify       234,552 gas (26.4%)  🔥 DRUGI KOSZT
   │  └─ Hash computations      (keccak256 on paths)
   
3. computeDecommitment          27,066 gas ( 3.0%)
   │  └─ Rebuild evaluations
   
4. extract M31 values           13,105 gas ( 1.5%)
   │  └─ QM31 → M31 conversion
   
5. create tree & decode         12,539 gas ( 1.4%)
   │  └─ Merkle tree setup
   
6. foldQueries                   5,944 gas ( 0.7%)
   │  └─ Query position folding
   
7. init witness                    539 gas ( 0.1%)
   └─ Witness initialization
```

### 📦 Kluczowe biblioteki używane:

#### **CircleDomain / CosetM31** (`contracts/cosets/`)
- Circle polynomial domains
- Fast coset operations
- Bit-reversal indexing
- Half-coset dla FRI

#### **QM31Field / CM31Field / M31Field** (`contracts/fields/`)
- **M31Field**: Pole Mersenne (2³¹-1)
- **CM31Field**: Complex extension (M31²)
- **QM31Field**: Quaternion extension (M31⁴)
- Batch inverse dla denominators

---

## 🔬 Deep Dive #3: friAnswers (2.5M gas - 15.4%)

### Struktura obliczania quotients:

```
friAnswers (2,506,397 gas)
├─ friAnswersForLogSize (logSize 6)   1,256,942 gas (50.1%)
├─ friAnswersForLogSize (logSize 5)   1,168,111 gas (46.6%)
├─ _sortByLogSizeAscending               19,196 gas ( 0.8%)
├─ _flattenAndCreatePairs                13,181 gas ( 0.5%)
├─ _getUniqueLogSizesFromFlattened        3,972 gas ( 0.2%)
└─ Overhead                              44,995 gas ( 1.8%)
```

### Operacje w friAnswersForLogSize:

1. **_createColumnSampleBatches**: Grupuje samples według punktów
2. **_calculateQuotientConstants**: Line coefficients dla każdego batch
3. **_accumulateRowQuotients**: Suma quotient contributions
   - Oblicza denominator inverses (batch)
   - Oblicza numerator dla każdego sample
   - Akumuluje contributions

**Wykorzystywane komponenty:**
- `CirclePoint.sol`: Reprezentacja punktów na circle
- `SecureCirclePoly.sol`: Secure polynomial evaluation
- `PolyUtils.sol`: Utility functions dla polynomials

---

## 🔬 Deep Dive #4: FriVerifier.commit (3.4M gas - 20.6%)

### Internal Breakdown:

```
FriVerifier.commit (702,115 gas wewnętrzny + overhead)

Faza 1: First Layer Setup
├─ Calculate domains            369,191 gas (52.6%)  🔥 GŁÓWNY KOSZT
├─ halfOdds first layer          89,181 gas (12.7%)
├─ drawSecureFelt first layer    39,183 gas ( 5.6%)
├─ mixRoot first layer              924 gas ( 0.1%)
├─ Create first layer verifier      541 gas ( 0.1%)
└─ Bounds validation                434 gas ( 0.1%)

Faza 2: Inner Layers (3 layers)
├─ Inner layers total           146,905 gas (20.9%)
│  ├─ draw secure felt sum      118,014 gas (80.3%)
│  └─ mix sum                     2,967 gas ( 2.0%)

Faza 3: Last Layer
├─ mixFelts lastLayerPoly        17,139 gas ( 2.4%)
└─ Create state                   2,566 gas ( 0.4%)
```

### Operacje calculate domains (369K gas):

Loop przez `columnBounds` dla każdego column:
1. `getMaxColumnLogSize()` - znajdź max log size
2. `CanonicCosetM31.newCanonicCoset()` - utwórz canonical coset
3. `CircleDomain.newCircleDomain()` - utwórz circle domain
4. Repeat dla każdego column bound

**Optymalizacja:** Można cachować domeny dla powtarzających się log sizes

---

## 🔬 Deep Dive #5: OODS Verification (2.4M gas - 14.9%)

### _performOodsVerification:

```
_performOodsVerification (2,423,970 gas)
└─ _verifyOods
   └─ SecureCirclePoly.evalAtPoint
      ├─ Polynomial evaluation at oodsPoint
      ├─ 4 coefficients (secure extension)
      └─ Comparison z compositionOodsEval
```

**Wykorzystane biblioteki:**
- `SecureCirclePoly.sol`: Secure polynomial operations
- `CirclePoint.sol`: OODS point handling
- `QM31Field.sol`: Field arithmetic

**Brak szczegółowego profilingu** - wymaga dodania logów:
- Czas na evalAtPoint
- Overhead comparison
- Field operations breakdown

---

## 🔬 Deep Dive #6: Sample Points (601K gas - 3.7%)

### _computeSamplePoints breakdown:

```
_computeSamplePoints (599,851 gas wewnętrzny)

1. Component initialization:
   ├─ TraceLocationAllocatorLib    (allocation state)
   ├─ FrameworkComponentLib        (component states)
   └─ ComponentsLib                (aggregation)

2. Mask points computation:
   ├─ maskPoints() dla każdego component
   └─ _concatCols() - konkatenacja columns

3. Preprocessed columns:
   ├─ _initializePreprocessedColumns
   └─ _setPreprocessedMaskPoints

4. Composition tree points:
   └─ Add oodsPoint dla 4 columns (SECURE_EXTENSION_DEGREE)
```

**Wykorzystane moduły:**
- `FrameworkComponentLib.sol`: Framework component logic
- `ComponentsLib.sol`: Components aggregation
- `TraceLocationAllocatorLib.sol`: Trace memory allocation

---

## 📊 Ranking Najdroższych Operacji

### Top 10 Absolute Values:

| # | Operacja | Gas | % Total | Lokalizacja |
|---|----------|-----|---------|-------------|
| 1 | **decommitInnerLayers** | 4,548,936 | 27.9% | FriVerifier.sol:decommitOnQueries |
| 2 | **FriVerifier.commit** | 3,363,215 | 20.6% | FriVerifier.sol:commit |
| 3 | **friAnswers** | 2,508,260 | 15.4% | FriVerifier.sol:friAnswers |
| 4 | **OODS Verification** | 2,423,970 | 14.9% | StwoVerifier.sol:_verifyOods |
| 5 | **foldLineSparseEvals (Σ)** | 1,729,646 | 10.6% | FriVerifier.sol (3 layers) |
| 6 | **MerkleVerifier.verify (Σ)** | 703,655 | 4.3% | MerkleVerifier.sol (3 layers) |
| 7 | **_computeSamplePoints** | 601,181 | 3.7% | StwoVerifier.sol |
| 8 | **decommitFirstLayer** | 568,162 | 3.5% | FriVerifier.sol:decommitOnQueries |
| 9 | **_verifyMerkleDecommitments** | 566,559 | 3.5% | StwoVerifier.sol |
| 10 | **sampleQueryPositions** | 421,756 | 2.6% | FriVerifier.sol |

### Top 10 Per-Operation (intensywność):

| # | Operacja | Gas/call | Calls | Total | Optymalizacja |
|---|----------|----------|-------|-------|---------------|
| 1 | foldLineSparseEvals | 576,549 | 3 | 1,729,646 | 🔥 Assembly |
| 2 | MerkleVerifier.verify | 234,552 | 3 | 703,655 | 🔥 Assembly hash |
| 3 | Calculate domains | 369,191 | 1 | 369,191 | ✅ Cache domains |
| 4 | friAnswersForLogSize | 1,212,527 | 2 | 2,425,053 | 🔥 Batch ops |
| 5 | Tree 2 verification | 280,538 | 1 | 280,538 | 🔥 Optimize path |
| 6 | Tree 1 verification | 226,808 | 1 | 226,808 | 🔥 Optimize path |
| 7 | Inner layers draw | 118,014 | 1 | 118,014 | ✅ Optimize RNG |
| 8 | halfOdds first layer | 89,181 | 1 | 89,181 | ✅ Optimize odds |
| 9 | getNColumnsPerLogSize | 68,420 | 1 | 68,420 | ✅ Cache result |
| 10 | drawSecureFelt (FRI) | 39,183 | 1 | 39,183 | ✅ Optimize draw |

---

## 🎯 Priorytety Optymalizacji

### 🔥 PRIORITY 1: decommitInnerLayers (4.5M gas = 27.9%)

**Target A: foldLineSparseEvals - 1.73M gas (10.6% całości)**

**Funkcje do optymalizacji:**
```solidity
// FriVerifier.sol
function _foldLineForSubset() - Assembly rewrite
function _ibutterfly() - Assembly FFT butterfly
function foldLineSparseEvals() - Batch optimization
```

**Strategia:**
- ✅ Assembly dla loop-heavy operations
- ✅ Unchecked arithmetic gdzie bezpieczne
- ✅ Memory optimization (redukcja copies)
- ✅ Inline małe funkcje

**Potencjał:** 40-60% redukcji = **692K-1.04M gas savings**

**Target B: MerkleVerifier.verify - 704K gas (4.3% całości)**

**Funkcje do optymalizacji:**
```solidity
// MerkleVerifier.sol
function verify() - Główna weryfikacja
function _verifyPath() - Hash path verification
```

**Strategia:**
- ✅ Assembly dla keccak256 operations
- ✅ Optimize tree traversal
- ✅ Batch hash computations

**Potencjał:** 30-50% redukcji = **211K-352K gas savings**

---

### 🔥 PRIORITY 2: FriVerifier.commit (3.4M gas = 20.6%)

**Target: Calculate domains - 369K gas (5.3% całości)**

**Funkcje do optymalizacji:**
```solidity
// FriVerifier.sol:commit()
Loop przez columnBounds:
  - CanonicCosetM31.newCanonicCoset()
  - CircleDomain.newCircleDomain()
```

**Strategia:**
- ✅ Cache domains dla powtarzających się log sizes
- ✅ Precompute common cosets
- ✅ Assembly dla coset operations

**Potencjał:** 30-50% redukcji = **111K-185K gas savings**

**Target: Inner layers - 147K gas (2.1% całości)**

**Strategia:**
- ✅ Optimize drawSecureFelt loop (118K gas)
- ✅ Batch mixing operations

**Potencjał:** 25-40% redukcji = **37K-59K gas savings**

---

### 🔥 PRIORITY 3: friAnswers (2.5M gas = 15.4%)

**Target: friAnswersForLogSize - 2.4M gas (14.8% całości)**

**Funkcje do optymalizacji:**
```solidity
// FriVerifier.sol
function friAnswersForLogSize()
function _accumulateRowQuotients() - 🔥 Hot path
function _createColumnSampleBatches()
function _calculateQuotientConstants()
```

**Strategia:**
- ✅ Assembly dla _accumulateRowQuotients
- ✅ Optimize batch inverse computation
- ✅ Reduce memory allocations
- ✅ Inline helper functions

**Potencjał:** 30-45% redukcji = **720K-1.08M gas savings**

---

### 🟡 PRIORITY 4: OODS Verification (2.4M gas = 14.9%)

**Target: SecureCirclePoly.evalAtPoint**

**Wymaga głębszego profilingu:**
```solidity
// Dodać logi w:
function evalAtPoint() - polynomial evaluation
function _evaluateSinglePoly() - per-coefficient eval
```

**Strategia (po profilingu):**
- Assembly dla polynomial evaluation
- Optimize field operations (QM31)
- Batch operations gdzie możliwe

**Potencjał:** 20-35% redukcji = **485K-848K gas savings**

---

### 🟢 PRIORITY 5: Smaller Optimizations

**A. _computeSamplePoints (601K gas = 3.7%)**
- Cache mask points
- Optimize ComponentsLib operations
- Reduce memory allocations

**Potencjał:** 15-25% = **90K-150K gas**

**B. _verifyMerkleDecommitments (567K gas = 3.5%)**
- Batch tree verifications
- Optimize queriesPerLogSize filtering

**Potencjał:** 20-30% = **113K-170K gas**

**C. Misc Operations (< 100K gas każda)**
- sampleQueryPositions: Optimize query generation
- getNColumnsPerLogSize: Cache results
- Tree verification overhead: Reduce setup cost

**Potencjał:** 10-20% = **50K-100K gas łącznie**

---

## 💰 Łączny Potencjał Optymalizacji

| Priorytet | Komponent | Obecne | Min | Max | Po opt. (min) | Po opt. (max) |
|-----------|-----------|--------|-----|-----|---------------|---------------|
| P1-A | foldLineSparseEvals | 1.73M | -692K | -1.04M | 1.04M | 690K |
| P1-B | MerkleVerifier | 704K | -211K | -352K | 493K | 352K |
| P2-A | Calculate domains | 369K | -111K | -185K | 258K | 184K |
| P2-B | Inner layers | 147K | -37K | -59K | 110K | 88K |
| P3 | friAnswers | 2.51M | -720K | -1.08M | 1.79M | 1.43M |
| P4 | OODS | 2.42M | -485K | -848K | 1.94M | 1.57M |
| P5 | Other | 1.36M | -253K | -420K | 1.11M | 940K |
| **TOTAL** | | **16.3M** | **-2.5M** | **-4.0M** | **13.8M** | **12.3M** |

### 🎯 Realistyczne Cele:

- **Konserwatywny (3 miesiące):** 12.8M gas (21% redukcja, -3.5M)
- **Optymalny (6 miesięcy):** 11.5M gas (29% redukcja, -4.8M)
- **Agresywny (12 miesięcy):** 10.2M gas (37% redukcja, -6.1M)

---

## 📋 Action Plan - Roadmap

### 🗓️ Faza 1: Quick Wins (Tydzień 1-2) - ~500K gas

**Tydzień 1:**
- ✅ Cache domains w FriVerifier.commit
- ✅ Optimize getNColumnsPerLogSize (add caching)
- ✅ Unchecked arithmetic w loops gdzie bezpieczne
- **Expected:** 150K gas savings

**Tydzień 2:**
- ✅ Inline małe helper functions
- ✅ Reduce memory allocations w hot paths
- ✅ Optimize query filtering
- **Expected:** 350K gas savings

---

### 🗓️ Faza 2: Assembly Optimizations (Tydzień 3-6) - ~2M gas

**Tydzień 3-4: foldLineSparseEvals**
- Przepisać `_foldLineForSubset` na assembly
- Zoptymalizować `_ibutterfly` (FFT operations)
- Batch field operations
- **Expected:** 800K gas savings

**Tydzień 5-6: MerkleVerifier**
- Assembly dla keccak256 hash operations
- Optimize path traversal
- Batch verifications
- **Expected:** 280K gas savings

---

### 🗓️ Faza 3: Algorithm Improvements (Tydzień 7-10) - ~1.2M gas

**Tydzień 7-8: friAnswers**
- Assembly dla `_accumulateRowQuotients`
- Optimize batch inverse
- Reduce sample batch allocations
- **Expected:** 900K gas savings

**Tydzień 9-10: FriVerifier.commit**
- Precompute common cosets
- Assembly dla domain calculations
- Optimize inner layers loop
- **Expected:** 300K gas savings

---

### 🗓️ Faza 4: Deep Optimizations (Tydzień 11-14) - ~800K gas

**Tydzień 11-12: OODS Verification**
- Profiling evalAtPoint
- Assembly dla polynomial evaluation
- Optimize QM31 field operations
- **Expected:** 550K gas savings

**Tydzień 13-14: Misc Components**
- Optimize _computeSamplePoints
- Improve _verifyMerkleDecommitments batching
- Final cleanup i optimizations
- **Expected:** 250K gas savings

---

### 📊 Progressive Milestones:

| Milestone | Tydzień | Cumulative Savings | Total Gas | % Reduction |
|-----------|---------|-------------------|-----------|-------------|
| Baseline | 0 | 0 | 16.3M | 0% |
| Quick Wins | 2 | -500K | 15.8M | 3.1% |
| Assembly Phase | 6 | -2.5M | 13.8M | 15.3% |
| Algorithm Phase | 10 | -3.7M | 12.6M | 22.7% |
| Deep Optimizations | 14 | -4.5M | 11.8M | 27.6% |

---

## 🔬 Szczegółowa Struktura Kontraktów

### Core Libraries (`contracts/core/`)

#### **KeccakChannelLib.sol**
- Fiat-Shamir transform
- Random field element generation (drawSecureFelt)
- Proof-of-Work verification
- Mixing operations dla security
- **Użycie:** 138,026 gas (mixFelts + drawSecureFelt + PoW + mixU64)

#### **CommitmentSchemeVerifierLib.sol**
- Commitment scheme coordination
- Tree root management
- Bounds calculation
- **Użycie:** 25,194 gas (calculateBounds)

#### **FrameworkComponentLib.sol**
- Component state management
- Sample points computation
- Mask points generation
- **Użycie:** Część z _computeSamplePoints (601K)

#### **ComponentsLib.sol**
- Components aggregation
- TreeVec operations
- Column concatenation
- **Użycie:** Część z _computeSamplePoints (601K)

#### **TraceLocationAllocatorLib.sol**
- Trace memory allocation
- Location tracking
- Reset i initialization
- **Użycie:** Overhead w _computeSamplePoints

---

### Field Libraries (`contracts/fields/`)

#### **M31Field.sol**
- Mersenne prime field (2³¹-1)
- Basic arithmetic (add, sub, mul, inverse)
- **Użycie:** Base dla wszystkich field operations

#### **CM31Field.sol**
- Complex extension M31²
- Complex arithmetic
- Batch inverse operations
- **Użycie:** Denominators w friAnswers

#### **QM31Field.sol**
- Quaternion extension M31⁴
- Secure field operations
- Used throughout dla secure values
- **Użycie:** Wszystkie QM31 operations w całym protokole

---

### PCS (Polynomial Commitment Scheme) (`contracts/pcs/`)

#### **FriVerifier.sol** (2,967 lines)
- Core FRI verification logic
- **commit()**: 3.4M gas
- **decommit()**: 5.4M gas
- **friAnswers()**: 2.5M gas
- Największy single contract w projekcie

#### **PcsConfig.sol**
- FRI configuration
- Security parameters
- Degree bounds
- **Użycie:** Config storage i validation

---

### VCS (Vector Commitment Scheme) (`contracts/vcs/`)

#### **MerkleVerifier.sol**
- Merkle tree verification
- Multi-logsize support
- Decommitment verification
- **Użycie:** 704K gas (3 layers w decommitInnerLayers) + 567K gas (3 trees)

---

### Cosets (`contracts/cosets/`)

#### **CosetM31.sol**
- Coset operations na M31
- Circle point generation
- Index operations
- **Użycie:** Domain operations w FRI

#### **CanonicCosetM31.sol**
- Canonical coset generation
- Half-coset operations
- Used w FRI domains
- **Użycie:** 369K gas w calculate domains

---

### Secure Polynomials (`contracts/secure_poly/`)

#### **SecureCirclePoly.sol**
- Secure polynomial evaluation
- Circle polynomial operations
- **Użycie:** 2.4M gas w OODS verification

#### **PolyUtils.sol**
- Polynomial utilities
- Evaluation helpers
- **Użycie:** Support dla SecureCirclePoly

---

### Verifier (`contracts/verifier/`)

#### **StwoVerifier.sol** (główny kontrakt)
- Orchestration całego procesu
- Integracja wszystkich komponentów
- Event emissions
- **Użycie:** Overhead + coordination (~300K)

#### **ProofParser.sol**
- Proof deserialization
- Data extraction
- Validation
- **Użycie:** 34,775 gas (flattenCols) + overhead

---

## 🎓 Kluczowe Insights

### 1. Dominacja FRI (77.6%)
FRI verification to absolutny core protokołu. Każda 1% optymalizacja FRI = 126K gas savings.

### 2. Folding Operations (10.6%)
`foldLineSparseEvals` to single najdroższa repeated operation. Assembly rewrite = biggest win.

### 3. Merkle Overhead (8.2%)
Merkle verification w różnych miejscach sumuje się do significant cost. Batch optimization kluczowa.

### 4. Field Operations
QM31/CM31/M31 operations są wszędzie. Optimizing field arithmetic ma multiplicative effect.

### 5. Memory Allocations
Dużo temporary arrays w hot paths. Memory optimization może dać 10-15% improvement.

### 6. Domain Calculations
Repeated domain calculations dla tych samych log sizes. Caching = quick win.

---

## 🚀 Następne Kroki

### Immediate (Najbliższy tydzień):

1. **Dodaj głębszy profiling dla OODS:**
   ```solidity
   // W SecureCirclePoly.sol
   console.log("[OODS] evalAtPoint start");
   // ... detailed operation logs
   console.log("[OODS] evalAtPoint total:", gasStart - gasleft());
   ```

2. **Implementuj domain caching:**
   ```solidity
   // W FriVerifier.sol:commit()
   mapping(uint32 => CircleDomain) private cachedDomains;
   ```

3. **Start assembly dla _ibutterfly:**
   ```solidity
   // W FriVerifier.sol
   function _ibutterfly() -> assembly version
   ```
