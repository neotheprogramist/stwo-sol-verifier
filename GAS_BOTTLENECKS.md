# Gas Bottlenecks Analysis - STWO Verifier

## Całkowite zużycie: ~16.7M gas

### 1. FRI Verification: ~13M gas (78% całości)

**Główne komponenty:**
- `decommit`: 5.7M gas (44%)
- `commit`: 3.4M gas (26%)
- `friAnswers`: 2.6M gas (20%)

#### Decommit breakdown (5.76M gas):
```
decommitInnerLayers:     4.86M gas (84%)
  ├─ Layer 0:            1.89M gas
  │  ├─ foldLineSparseEvals:  632k (33%)
  │  ├─ MerkleVerifier.verify: 282k (15%)
  │  └─ pozostałe:            976k (52%)
  ├─ Layer 1:            1.97M gas
  │  ├─ foldLineSparseEvals:  683k (35%)
  │  ├─ MerkleVerifier.verify: 237k (12%)
  │  └─ pozostałe:           1.05M (53%)
  └─ Layer 2:            970k gas
     ├─ foldLineSparseEvals:  697k (72%)
     ├─ MerkleVerifier.verify: 187k (19%)
     └─ pozostałe:            86k (9%)

decommitFirstLayer:      573k gas (10%)
  └─ MerkleVerifier.verify:   475k (83%)

decommitLastLayer:       212k gas (4%)
foldQueries:             6k gas (<1%)
```

#### friAnswers breakdown (2.57M gas):
```
logSize 6:               1.29M gas (50%)
  ├─ Loop (3 queries):        703k (55%)
  │  ├─ _accumulateRowQuotients: ~163k/query = 489k
  │  ├─ _getDomainPointAtQuery:   ~62k/query = 186k
  │  └─ _getQueriedValuesAtRow:    ~6k/query = 18k
  ├─ _calculateQuotientConstants: 305k (24%)
  ├─ _createCommitmentDomain:     201k (16%)
  └─ _createColumnSampleBatches:   58k (5%)

logSize 5:               1.20M gas (47%)
  ├─ Loop (3 queries):        650k (54%)
  │  ├─ _accumulateRowQuotients: ~143k/query = 429k
  │  ├─ _getDomainPointAtQuery:   ~63k/query = 189k
  │  └─ _getQueriedValuesAtRow:    ~5k/query = 15k
  ├─ _calculateQuotientConstants: 256k (21%)
  ├─ _createCommitmentDomain:     225k (19%)
  └─ _createColumnSampleBatches:   49k (4%)

overhead:                82k gas (3%)
```

---

## Krytyczne bottlenecki

### TOP 1: `foldLineSparseEvals`: ~2.01M gas total (3 warstwy × ~670k)
**Breakdown per warstwa:**
- `CosetM31.newCoset`: ~430k gas (64%) - circle point multiplication
- `_foldLineForSubset`: ~155k gas (23%) - FRI folding math
- Alokacja + overhead: ~85k gas (13%)

**Przyczyna:**
- `newCoset` wywołuje 2× `indexToPoint` (~70k każde)
- `indexToPoint` → `CirclePointM31.mul` → 31 iteracji binarnego potęgowania
- Wykonywane 3× per warstwa (po jednym na query)

**Optymalizacja:** ⚠️ Ograniczona
- Hardcoded lookup tables → zepsuta weryfikacja (testowane)
- Możliwe: intelligent caching based on access patterns

### TOP 2: `_accumulateRowQuotients`: ~918k gas total (6 wywołań)
**Breakdown:**
- Query operations: ~153k gas/call średnio
- Batch inverse denominators: ~40k gas/call
- QM31 arithmetic loops: ~113k gas/call

**Przyczyna:** 
- Intensywne operacje na polu QM31 (4× M31 components)
- Nested loops: batches → columns → coefficients
- Każde mnożenie/dodawanie QM31 = 4× operacje M31

**Optymalizacja:** ❌ Trudna
- Wymaga operacji matematycznych dla FRI
- Jedyna opcja: precompile dla QM31

### TOP 3: `MerkleVerifier.verify`: ~1.57M gas (suma wszystkich warstw)
**Breakdown:**
- First layer: 475k gas (1 tree, duży)
- Inner Layer 0: 282k gas
- Inner Layer 1: 237k gas
- Inner Layer 2: 187k gas

**Przyczyna:**
- Keccak256 hashing w pętlach
- Traversal Merkle tree paths
- Większe drzewa = więcej hashy

**Optymalizacja:** ✅ Częściowo możliwa
- Batch verification jeśli protokół pozwala
- Optymalizacja decommitment encoding

### TOP 4: `_calculateQuotientConstants`: ~561k gas (2 wywołania)
**Breakdown:**
- logSize 6: 305k gas
- logSize 5: 256k gas

**Przyczyna:**
- Obliczanie line coefficients (a, b, c) dla każdego batch/column
- Complex conjugate operations na QM31
- Mnożenia przez randomCoeff power

**Optymalizacja:** ❌ Minimalna
- Wymagane dla algorytmu FRI

### TOP 5: `_createCommitmentDomain`: ~426k gas (2 wywołania)
**Breakdown:**
- logSize 6: 201k gas (2× indexToPoint @ 43-44k każde)
- logSize 5: 225k gas (2× indexToPoint @ 48-49k każde)

**Przyczyna:**
- `newCanonicCoset` → `halfCoset` → `newCircleDomain`
- Każdy krok wywołuje `indexToPoint` (circle point operations)

**Optymalizacja:** ✅ Możliwa
- Cache domen dla powtarzających się logSize
- Precompute przy deployment dla known sizes

### TOP 6: `_getDomainPointAtQuery`: ~375k gas (6 wywołań)
**Breakdown:**
- ~62k gas per call (logSize 6)
- ~63k gas per call (logSize 5)

**Przyczyna:**
- Bit reverse index calculation
- CircleDomain.at() → coset operations
- M31 field arithmetic

**Optymalizacja:** ⚠️ Możliwa
- Precompute bit-reversed indices
- Cache domain points dla repeated queries

---

## Podsumowanie według typu operacji

### Operacje Circle Point (M31): ~3.8M gas (29%)
- `foldLineSparseEvals` newCoset: 2.01M
- `_createCommitmentDomain`: 426k
- `_getDomainPointAtQuery`: 375k
- Inne circle operations: ~1M

### Operacje QM31 Field: ~1.5M gas (11%)
- `_accumulateRowQuotients`: 918k
- `_calculateQuotientConstants`: 561k

### Merkle Verification: ~1.57M gas (12%)
- Keccak256 hashing + path traversal

### Pozostałe: ~6.1M gas (48%)
- FRI folding math, memory allocation, protocol overhead

---

## Podsumowanie optymalizacji

### ✅ Realne możliwości (małe zyski ~5-10%):
1. Cache commitment domains dla repeated logSize
2. Unchecked blocks w hot paths (już dodane)
3. Optymalizacja CirclePointM31.mul (fast paths dodane)

### ⚠️ Wymagające badań:
1. Precompute common cosets przy deployment
2. Batch processing dla multiple queries naraz
3. Analyze access patterns dla smart caching

### ❌ Niemożliwe bez zmian protokołu:
1. Uproszczenie operacji QM31 (breaking changes)
2. Redukcja liczby FRI layers (security trade-off)
3. Mniejsza liczba queries (security trade-off)

---

## Wnioski

**Główny problem:** Operacje na polach rozszerzonych (QM31) + circle point arithmetic są inherentnie kosztowne w EVM.

**Największy single bottleneck:** `foldLineSparseEvals` (2.01M gas) z którego 64% to `CosetM31.newCoset`.

**Drugi największy:** `_accumulateRowQuotients` (918k gas) - intensywne operacje QM31.

**Najbardziej realistyczna optymalizacja:** Caching commitment domains + domain points może zaoszczędzić ~400-500k gas (~2.5-3% total).

**Hard limit:** Bez precompile dla M31/QM31 operacji, trudno zejść poniżej ~15M gas przy zachowaniu bezpieczeństwa.
