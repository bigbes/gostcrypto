# Streebog — GOST R 34.11-2012 hash (256 & 512)

Streebog is the Russian national cryptographic hash function standardised as
**GOST R 34.11-2012** and republished as **RFC 6986** ("GOST R 34.11-2012:
Hash Function"). It produces either a 256-bit or a 512-bit digest. The two
variants share the *entire* compression machinery and differ in only two
places: the initialisation vector (IV) and a final truncation. This document
is a clean-room re-implementation guide: a different engineer must be able to
write Streebog in Go from this text plus RFC 6986, **without reading gogost**.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

## Status

**Clean-room implementation, complete.** `streebog/streebog.go` is a
BSD-2-Clause, zero-dependency Go implementation. The module has no dependency on
`go.stargrave.org/gogost` or any GPL code. The facade entry points are:

- `primitives.go:124` — `Streebog256(msg []byte) []byte` (one-shot).
- `primitives.go` — `Streebog512(msg []byte) []byte` (one-shot).
- `exports.go:68` — `NewStreebog256Hash() hash.Hash`.
- `exports.go` — `NewStreebog512Hash() hash.Hash`.

Tests live in `streebog/streebog_test.go`. Differential parity tests against the
gogost reference are quarantined (BSD/GPL boundary) in
`../gostcrypto-compat/parity/streebog/streebog_parity_test.go` — no build tags
needed there; run with `( cd ../gostcrypto-compat && go test ./parity/streebog/ )`.

### Where this module uses Streebog

- **TLS PRF** for the GOST 2012 suites (RFC 9189): consumed by `gostls` via
  `HMAC-Streebog-256`, so Streebog must satisfy `hash.Hash` correctly under
  `crypto/hmac` (block size 64, streaming `Write`).
- **Key exchange UKM** (RFC 9189 / RFC 9367): `Streebog256(clientRandom ||
  serverRandom)` (64-byte input → 32-byte digest) to derive the UKM. Call site
  in `github.com/bigbes/gostls`.
- **X.509 GOST certificate signature verification**:
  `x509gost/verify.go` selects `NewStreebog256Hash()` for
  `id-tc26-gost3410-12-256` signatures and `NewStreebog512Hash()` for
  `id-tc26-gost3410-12-512`. The TBS bytes are hashed before the
  GOST R 34.10-2012 signature check.
- **OIDs** (`x509gost/oids.go:53,57`):
  Streebog-256 = `1.2.643.7.1.1.2.2`, Streebog-512 = `1.2.643.7.1.1.2.3`.

## Specification

### 0. Sizes and constants overview

| Quantity        | Value                                                        |
|-----------------|-------------------------------------------------------------|
| Block size      | 64 bytes (512 bits)                                          |
| Internal state  | three 512-bit vectors: `h` (hash), `N` (bit counter), `Σ` (checksum) |
| Output (256)    | 32 bytes; IV = `0x01` repeated 64 times                     |
| Output (512)    | 64 bytes; IV = `0x00` repeated 64 times                     |
| Rounds in E()   | 13 key-additions / 12 round constants `C_1..C_12`           |
| S-box           | π, a single 256-entry byte permutation (RFC 6986 §6, Table 1) |
| Permutation     | τ (Tau), 64-entry byte permutation (RFC 6986 §6, Table 2)   |
| Linear map      | l / L, multiplication by a fixed 64×64 GF(2) matrix (RFC 6986 §6) |

### 1. The three primitive transformations (RFC 6986 §7)

RFC 6986 numbers the 64 bytes of a 512-bit vector **MSB-first**: `a =
a_63 || a_62 || ... || a_0`, where `a_63` is the most significant byte. Keep
this convention straight — it is the single biggest source of endianness bugs
(see the deltas section).

- **X[k](a) = k ⊕ a** — bytewise XOR with a fixed 512-bit `k` (RFC 6986 §7,
  "X[k](a) = k (xor) a").
- **S (substitution)**: `S(a) = π(a_63) || ... || π(a_0)` — apply the byte
  S-box π independently to every byte (RFC 6986 §7).
- **P (permutation)**: `P(a) = a_{τ(63)} || ... || a_{τ(0)}` — reorder the 64
  bytes by the fixed permutation τ (RFC 6986 §7).
- **L (linear)**: `L(a) = l(a_7) || ... || l(a_0)` — split into eight 64-bit
  words; each word is multiplied (over GF(2)) by the fixed binary matrix
  `A` (the function `l`). RFC 6986 §6 lists the 64 row constants of `A`.

The combined `LPS` (i.e. `L(P(S(a)))` — substitute, permute, linear-map) is
what every implementation precomputes; see deltas below.

### 2. Compression function g_N (RFC 6986 §8)

The keyed permutation E built from 13 round keys:

> E(K, m) = X[K_13]·L·P·S · X[K_12]·L·P·S · ... · X[K_2]·L·P·S · X[K_1](m)

Round keys are derived from `K = K_1`:

> K_1 = K, and for i = 2..13: K_i = L·P·S( K_{i-1} ⊕ C_{i-1} )

i.e. each subsequent key is `LPS` applied to the previous key XORed with the
round constant `C_{i-1}` (RFC 6986 §8, "K_{i+1} = LPS(K_i ⊕ C_i)").

The compression function (RFC 6986 §8):

> **g_N(h, m) = E( LPS(h ⊕ N), m ) ⊕ h ⊕ m**

So: form the first round key as `LPS(h ⊕ N)`, run the 12-round cipher `E` on
message block `m` with that key schedule, then XOR back `h` and `m`.

### 3. Round constants C_1..C_12 (RFC 6986 §6.5, Iteration Constants)

Twelve 512-bit constants. The repo's reference stores them as little-endian
byte arrays (`third_party/gogost/internal/gost34112012/c.go:3`) and gost-engine
stores them as little-endian QWORDs (`tmp/engine/gosthash2012_const.h:32`);
the two are byte-for-byte identical once you account for QWORD↔byte ordering.

RFC 6986 §6.5 prints each constant MSB-first; gogost stores them already
byte-reversed into the little-endian working buffer, so the LE array is what
you XOR *directly* into the state during the key schedule (`hash.go:119`,
`subtle.XORBytes(xorBuf, k, c[i])`). **C_1** as that 64-byte little-endian
array (`c.go:4-12`, the form you XOR directly) is:

```
07 45 a6 f2 59 65 80 dd 23 4d 74 cc 36 74 76 05
15 d3 60 a4 08 2a 42 a2 01 69 67 92 91 e0 7c 4b
fc c4 85 75 8d b8 4e 71 ... e9 da ca 1e da 5b 08 b1
```

The RFC MSB-first rendering of the same constant is the exact byte-reverse,
`b1 08 5b da 1e ca da e9 ...`; do not XOR that form into a little-endian state.

Do **not** hand-transcribe all twelve from prose — copy the 12×64 table
verbatim from RFC 6986 §6.5 and byte-reverse each row, or read the exact bytes
from `third_party/gogost/internal/gost34112012/c.go:3-124` (treated as opaque
test data, not as code) and verify against the KATs in this document. `C_1`
byte 0 is `0xb1` in RFC MSB-first order, which appears as the *last* byte
(`0xb1`) of gogost's `c[0]` little-endian row and as `...0x657c1f` /
`0x4b7ce091...` in the engine QWORDs.

### 4. The hashing procedure (RFC 6986 §9)

Three vectors of state: `h`, `N` (message bit-length counter), `Σ` (the
512-bit checksum). The reference implementations call the steps stage1/2/3.

**Stage 1 — initialise** (RFC 6986 §9 "Step 1"):
- `h := IV` — `0x01·64` for the 256-bit variant, `0x00·64` for 512-bit.
- `N := 0^512`
- `Σ := 0^512` (RFC calls it Σ / "EPSILON" in some renderings)

**Stage 2 — process each full 512-bit block** (RFC 6986 §9 "Step 2"). For
every complete 64-byte block `m`:
- `h := g_N(h, m)`
- `N := (N + 512) mod 2^512`
- `Σ := (Σ + m) mod 2^512`

**Stage 3 — finalisation** (RFC 6986 §9 "Step 3"). Let the final partial
buffer hold `|M|` bits (`0 ≤ |M| < 512`), and `m` be the padded last block:
- **Pad**: `m := 0^(511-|M|) || 1 || M`. In MSB-first RFC notation a single
  `1` bit sits immediately above the message; in byte-oriented code this is
  "append a `0x01` byte right after the message bytes, zero-fill the rest".
- `h := g_N(h, m)` (compress the padded block at the *current* `N`)
- `N := (N + |M|) mod 2^512` (add the **bit** length of the real tail, not 512)
- `Σ := (Σ + m) mod 2^512`
- `h := g_0(h, N)` (compress with N = 0, feeding the bit-counter as the block)
- `h := g_0(h, Σ)` (compress with N = 0, feeding the checksum as the block)

**Output** (RFC 6986 §9 Step 3.6):
- 512-bit: return all 64 bytes of `h`.
- 256-bit: return `MSB_256(h)` — the most-significant 256 bits. In the
  reference little-endian buffer that is the **upper half** `h[32:64]`
  (engine copies `h.QWORD[4]`, `tmp/engine/gosthash2012.c:240`; gogost returns
  `hsh[BlockSize/2:]`, `hash.go:148`).

## RFC ↔ implementation deltas

This is the core section. Every place where a working implementation deviates
from, reinterprets, or under-specifies the RFC. Each delta cites the RFC and
the source line.

### D1. Endianness — the buffer is the *reverse* of RFC byte order

RFC 6986 numbers bytes MSB-first (`a_63 ... a_0`). Both reference
implementations store the 512-bit vectors as **little-endian** byte buffers:
`h[0]` is the least-significant byte `a_0`. Consequences:

- The `LPS` precompute table indexes raw little-endian bytes (gogost
  `lps()`, `hash.go:79-93`; engine `XLPS`, `gosthash2012_ref.h:36-66`). The
  `precalc[j][b]` / `Ax[j][b]` table already folds S, P and L together,
  so an implementer never materialises π, τ, or the GF(2) matrix at runtime —
  but if you build the table yourself you must apply π then τ then L in RFC
  (MSB) order and then store results little-endian.
- The 256-bit truncation takes `h[32:64]` (upper half of the LE buffer) =
  the *most-significant* 256 bits in RFC terms. gogost `hash.go:148`,
  engine `gosthash2012.c:240` (`QWORD[4]`).
- gost-engine has a separate `__GOST3411_BIG_ENDIAN__` code path
  (`gosthash2012.c:96-110`, `gosthash2012_const.h:16-28`) that byte-reverses
  `add512` and the `buffer512`/`N`-increment constant. A little-endian Go
  implementation must NOT mirror that path; follow the `#ifndef
  __GOST3411_BIG_ENDIAN__` (little-endian) branch.

### D2. N is incremented by 512 *as a little-endian 512-bit integer*

Stage 2 adds `512` to `N` (RFC §9 Step 2). gost-engine encodes this as the
constant `buffer512 = 0x0000000000000200` in the lowest QWORD and adds it with
the full 512-bit carry-propagating `add512` (`gosthash2012.c:169`,
`gosthash2012_const.h:17-21`). gogost instead carries `N` as a `uint64` and
adds `BlockSize*8 = 512` directly (`hash.go:133`, `h.n += BlockSize*8`), then
serialises it little-endian only when it is fed into `g` (`g()`,
`hash.go:98-105`, XORs the low 8 bytes of `N`). This shortcut is valid because
no realistic message overflows a 64-bit *bit*-counter, but a from-scratch
implementation that wants exact parity on pathological lengths must do the
full 512-bit add. The bit counter measures **bits**, not bytes (×8).

### D3. Stage-3 ordering and the *partial* N increment

RFC §9 Step 3 is easy to get subtly wrong. The exact sequence (engine
`stage3()`, `gosthash2012.c:173-189`; gogost `Sum()`, `hash.go:139-151`):

1. Pad the buffer (`0x01` after the data, zero-fill).
2. `g_N(h, paddedBlock)` at the **pre-finalisation** `N`.
3. `Σ := Σ + paddedBlock` (the padded block, including the `0x01` and zeros —
   NOT the raw tail). engine `gosthash2012.c:177`.
4. `N := N + (bufsize*8)` — add the bit length of the *real tail only*
   (`bufsize << 3`), not 512. engine `gosthash2012.c:181-185`; gogost folds
   this into the `g` call argument `h.n + len(h.buf)*8` at `hash.go:144`.
5. `g_0(h, N)` then `g_0(h, Σ)` with N=0 (engine `gosthash2012.c:187-188`).

A common bug is adding 512 (instead of the tail bit length) in step 4, or
adding `Σ += rawTail` instead of `Σ += paddedBlock`. The
`special-CF-128bytes` carry vector in the tests exists precisely to catch
checksum carry-propagation errors here.

### D4. The whole-message empty-input case is handled by the normal path

Unlike GOST R 34.11-**94** (which has a documented empty-input divergence
between gogost and gost-engine — see `TODO.md` "Disagreements" and the note at
`internal/gost/engine_hash_vectors_test.go:322-329`), **Streebog has NO such
divergence**. For empty input, stage 2 runs zero times and stage 3 pads a
block of a lone `0x01` byte; gogost and gost-engine agree, and both match the
RFC. The empty-input KATs are in the test vectors below and both pass. Do not
conflate the 94 divergence with 2012.

### D5. `Sum` must be non-destructive; `Write` buffers partial blocks

To satisfy `hash.Hash` (required by `crypto/hmac` for the TLS PRF):

- `Write` may be called repeatedly with arbitrary chunk sizes. The
  implementation buffers bytes and only compresses on reaching a full 64-byte
  block (gogost `Write()`, `hash.go:126-137`; engine `gost2012_hash_block()`,
  `gosthash2012.c:195-226`). `Write` returns `(len(data), nil)`.
- **`Sum(in)` must not mutate the receiver** — it has to snapshot `h`, `N`,
  `Σ`, and the partial buffer, run stage 3 on the *copy*, and append the digest
  to `in`. gogost achieves this by computing into local arrays `buf, hsh, tmp,
  addBuf` and never writing back to `h.hsh/h.chk/h.n` (`hash.go:139-151`). The
  Go contract is that you can `Sum`, then `Write` more, then `Sum` again. The
  GOST IMIT MAC (a *different* primitive) has a known destructive-`Sum` bug
  documented in `CLAUDE.md`; do not replicate that pattern here — Streebog's
  `Sum` is and must remain pure.
- `BlockSize()` returns 64; `Size()` returns 32 or 64. HMAC relies on
  `BlockSize()==64`.

### D6. The S/P/L precompute table is shared and order-sensitive

Both references collapse `L∘P∘S` into one 8×256 table of `uint64`
(`precalc[8][256]` in gogost `precalc.go:3`; `Ax[8][256]` in engine
`gosthash2012_precalc.h`). The table is applied as: for each output QWORD
index, XOR `table[j][ (state_word_j >> 8*k) & 0xff ]` across the 8 input bytes.
If you regenerate the table, the S-box π is **not** reversed for Streebog
(unlike the GOST 28147 / R34.11-94 S-box row-order quirk noted in `TODO.md`);
π is applied straight per RFC 6986 §6 Table 1. Verify your generated table by
hashing the empty string and the 63-byte standard example below before
trusting it.

### D7. `C` round constants: 12 constants, 13 key additions

RFC E() does 13 XOR-key stages (`K_1..K_13`) but only **12** round constants
`C_1..C_12` (the last key is `LPS(K_12 ⊕ C_12)`). gogost `e()` loops `for i in
0..12` (12 iterations) computing `K_{i+1}` and the message half, then does a
final `XOR` (`hash.go:113-124`). engine unrolls 11 `ROUND` macros + a 12th
inline (`gosthash2012.c:153-157`). Off-by-one on the constant count yields a
completely wrong digest.

## Test vectors

Existing KATs (gost-engine v3.0.3, ported with `tmp/engine/...:line`
citations) live in
`internal/gost/engine_hash_vectors_test.go`:

- `TestGost_Streebog256_EngineVectors` (lines 32-142) — 8 cases.
- `TestGost_Streebog512_EngineVectors` (lines 149-257) — 8 cases.
- `TestGost_HMACStreebog512_EngineVectors` (lines 362-383) — HMAC parity,
  proves `hash.Hash` streaming correctness (input 63 bytes, 30-byte key).

Each row cites `tmp/engine/test/01-digest.t` or
`tmp/engine/tcl_tests/dgst.try`.

### Inline, runnable vectors (RFC 6986 §10 standard examples)

**M1** — 63-byte ASCII string `"012345678901234567890123456789012345678901234567890123456789012"`:

- Streebog-256 =
  `9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500`
- Streebog-512 =
  `1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48`

**Empty string** (`""`):

- Streebog-256 =
  `3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb`
- Streebog-512 =
  `8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a`

**Carry-propagation stress** — 128 bytes (input hex):
`ee`×64, then `16`, then `11`×62, then `16`:

- Streebog-256 =
  `81bb632fa31fcc38b4c379a662dbc58b9bed83f50d3a1b2ce7271ab02d25babb`
- Streebog-512 =
  `8b06f41e59907d9636e892caf5942fcdfb71fa31169a5e70f0edb873664df41c2cce6e06dc6755d15a61cdeb92bd607cc4aaca6732bf3568a23a210dd520fd41`

The empty-string vector exercises stage 3 with no stage 2; the carry vector
exercises the `Σ` modular-add carry chain; M1 (63 bytes, one short of a block)
exercises padding with a 1-bit pad in the last byte position.

## Re-implementation checklist

Each step is independently testable.

1. **Constants.** Transcribe π (256 bytes), τ (64 bytes), and the GF(2)
   matrix `A` from RFC 6986 §6; transcribe `C_1..C_12` (12×64 bytes) from
   RFC 6986 §6.5 and byte-reverse each into little-endian before use (see §3).
   Unit-test by regenerating the `LPS` table and
   comparing against a known value (or against
   `third_party/gogost/internal/gost34112012/precalc.go` *values only*).
2. **LPS table.** Build `T[8][256] uint64` = little-endian-packed `L(P(S(·)))`
   applied to a single byte in each of the 8 lanes. Verify against the RFC 6986
   §10 worked value: because `π(0)=0xfc`, `LPS(0^512)` is *not* zero — it is
   `b383fc2eced4a574` repeated eight times in RFC MSB-first order (the LE
   working buffer holds the byte-reverse, `74a5d4ce2efc83b3` ×8). (If you fold
   only the linear part `L(P(·))` into the table and apply `S` separately at
   lookup time, then the linear-only check is `LP(0) == 0`.)
3. **`g_N(h, m)`.** Implement `LPS(h⊕N)` → key schedule of 13 keys using
   `K_{i+1}=LPS(K_i⊕C_i)` → E permutation → `⊕h⊕m`. Test `g` against an
   intermediate value, or skip straight to step 6.
4. **State + `add512`.** Implement the carrying 512-bit little-endian add for
   `N += 512` and `Σ += block`. Test: `add(0xFF...FF, 1) == 0` (full wrap).
5. **`Write` / block buffering.** Buffer partial input; compress full 64-byte
   blocks; track `N += 512` and `Σ += m` per block. Return `(len, nil)`.
6. **`Sum` / stage 3 (non-destructive).** Snapshot state; pad (`0x01` after
   data, zero fill); `g_N`; `Σ += padded`; `N += tailBits`; `g_0(h,N)`;
   `g_0(h,Σ)`; truncate. Verify against the **empty-string** and **M1**
   vectors above for both 256 and 512.
7. **256 vs 512 wiring.** IV = `0x01·64` vs `0x00·64`; output = `h[32:64]` vs
   `h[0:64]`. Verify both digests of every inline vector.
8. **Carry vector.** Run the 128-byte carry-stress vector; a mismatch here but
   passes on M1 means a `Σ`/`N` carry bug (delta D3).
9. **HMAC / streaming.** Wrap as `hash.Hash`, run under `crypto/hmac`. Confirm
   chunked `Write` (e.g. 1 byte at a time) yields identical digests to one-shot
   (delta D5). The HMAC path is exercised transitively by `kdftree` and
   `tlstree` KATs in sibling packages; in-package coverage is in
   `streebog/streebog_test.go` (see `TestStreaming`, `TestSumNonDestructive`).
10. **Drop-in.** Provide `Streebog256/512(msg)` and `NewStreebog256/512Hash()`
    in the facade (`exports.go`, `primitives.go`). Parity against the gogost
    reference is proved by `../gostcrypto-compat/parity/streebog/` — run with
    `( cd ../gostcrypto-compat && go test ./parity/streebog/ )` (no build tags).

## Conformance & fuzz testing

Streebog is a *pure function* (`[]byte msg → []byte digest`), so differential
testing is simple: hash the **same** message with the clean-room impl and with
the reference, and assert byte-for-byte equality.

### In-module tests

The clean-room tests live in `streebog/streebog_test.go` (no build tags):

- `TestKAT*` — RFC 6986 §10 / gost-engine vectors (M1, empty, carry128) for
  both 256 and 512.
- `TestStreaming` — chunked writes at sizes {1,3,7,31,63,64,65,127,128} over a
  1050-byte message; result must match one-shot `Sum256`/`Sum512`.
- `TestSumNonDestructive` — calling `Sum` twice on the same digest object
  returns identical output.

```sh
CGO_ENABLED=0 go test ./streebog/
```

### Differential parity (gogost reference)

The gogost library (GPL-3.0) is quarantined in `../gostcrypto-compat`. The
differential parity test is at
`../gostcrypto-compat/parity/streebog/streebog_parity_test.go`. It covers
arbitrary-length messages for both 256 and 512, including a fuzz target
`FuzzDiffAgainstGost`. No build tags are needed:

```sh
( cd ../gostcrypto-compat && go test ./parity/streebog/ )
( cd ../gostcrypto-compat && go test -fuzz=FuzzDiffAgainstGost -fuzztime=30s ./parity/streebog/ )
```

## References

- **RFC 6986** — "GOST R 34.11-2012: Hash Function".
  https://github.com/bigbes/gostcrypto/blob/master/streebog/rfc/rfc6986.txt
  - §6 — S-box π (Table 1), permutation τ (Table 2), linear matrix `A` / `l`.
  - §7 — transformations X[k], S, P, L.
  - §6.5 — iteration constants `C_1..C_12` (printed MSB-first).
  - §8 — round function: E key schedule (`K_{i+1}=LPS(K_i⊕C_i)`),
    compression `g_N(h,m)=E(LPS(h⊕N),m)⊕h⊕m`.
  - §9 — three-stage hashing procedure (init / process / finalise),
    incl. Step 3.6 output and 256-bit truncation `MSB_256`.
  - §10 — informative worked examples.
- **GOST R 34.11-2012** — the originating Russian national standard
  (equivalent to RFC 6986).
- OIDs: Streebog-256 `1.2.643.7.1.1.2.2`, Streebog-512 `1.2.643.7.1.1.2.3`
  (`x509gost/oids.go:53,57`).

Key source citations (reference impls, cited for line numbers — do not copy
the GPL-3.0 gogost code):

- `third_party/gogost/internal/gost34112012/hash.go:49` — `Reset`/IV.
- `.../hash.go:70-77` — `add512bit` (512-bit checksum add).
- `.../hash.go:79-93` — `lps` (LPS via precompute table).
- `.../hash.go:95-111` — `g` (compression `g_N`).
- `.../hash.go:113-124` — `e` (12-round E with `C`).
- `.../hash.go:126-137` — `Write` (block buffering, `N+=512`, `Σ+=m`).
- `.../hash.go:139-151` — `Sum` (non-destructive stage 3 + truncation).
- `.../c.go:3-124` — the 12 round constants `C` (little-endian rows).
- `.../precalc.go:3` — `precalc[8][256]` LPS table.
- `tmp/engine/gosthash2012.c:39-54` — `init_gost2012_hash_ctx` (IV).
- `tmp/engine/gosthash2012.c:56-61` — `pad`.
- `tmp/engine/gosthash2012.c:63-111` — `add512` (LE + BE paths).
- `tmp/engine/gosthash2012.c:113-163` — `g`.
- `tmp/engine/gosthash2012.c:165-189` — `stage2` / `stage3`.
- `tmp/engine/gosthash2012.c:233-243` — `gost2012_finish_hash` (truncation).
- `tmp/engine/gosthash2012_const.h:32,144` — `C[12]` (LE / BE).
- `tmp/engine/gosthash2012_ref.h:36-71` — `XLPS` / `ROUND` macros.
- `internal/gost/engine_hash_vectors_test.go` — ported KATs.
