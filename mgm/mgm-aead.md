# MGM — Multilinear Galois Mode AEAD (RFC 9058)

## What it is

MGM (Multilinear Galois Mode) is a nonce-based AEAD block-cipher mode of operation
standardized in **RFC 9058** and in the Russian recommendation
**R 1323565.1.026-2019** ("Information technology. Cryptographic data security.
Authenticated encryption block cipher operation modes"). It is the GOST analogue
of AES-GCM: a single pass produces a CTR-style ciphertext plus a polynomial
(Galois-field) authentication tag computed over the additional data and the
ciphertext.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

MGM is defined for both GOST block sizes:

- `n = 128` bits (16 bytes) — Kuznyechik / "Grasshopper" (GOST R 34.12-2015,
  block cipher `gost3412128`).
- `n = 64` bits (8 bytes) — Magma (GOST R 34.12-2015 64-bit, block cipher
  `gost341264`).

### Where this repo uses it

MGM is **not wired into any TLS suite, OID, or handshake path today**.
The clean-room implementation lives in `mgm/mgm.go`; tests are in
`mgm/mgm_test.go` and `mgm/mgm_internal_test.go`. Differential parity
tests live in `../gostcrypto-compat/parity/mgm/` (GPL-quarantined).

The TLS GOST AEAD path in production is MGM's cousin Kuznyechik/Magma-CTR-ACPKM
+ OMAC (RFC 9189 suites `0xC100`/`0xC101`), not MGM. This document exists so
MGM can be used if a future suite needs it.

**statusKind: clean-room** — `mgm/mgm.go` is the in-repo implementation,
BSD-2-Clause, zero third-party dependencies.

---

## Specification

All section references are to RFC 9058 unless noted. MGM is parameterized by a
block cipher `E_K` with block size `n` bits (`n ∈ {64, 128}`), a key `K`, and a
tag length `S` bits.

### Sizes and parameters

| Parameter            | Kuznyechik (n=128) | Magma (n=64) |
|----------------------|--------------------|--------------|
| Block size           | 16 bytes           | 8 bytes      |
| Key size             | 32 bytes           | 32 bytes     |
| Nonce / ICN size     | 16 bytes           | 8 bytes      |
| Tag size `S` (bytes) | 4 … 16             | 4 … 8        |
| Max data per **field** | `2^(n/2-3) − 1` bytes | same    |
| Combined bound (RFC §4.1) | `\|A\| + \|P\| < 2^(n/2)` bits | same |

Tag-size bound (RFC 9058 §4: `32 ≤ S ≤ n` bits): enforced as bytes in `NewMGM`
— `tagSize < 4 || tagSize > blockSize` is an error (`mgm/mgm.go:NewMGM`).

Per-field length cap: `mgm/mgm.go:maxFieldLen()` returns `2^(n/2-3) − 1` bytes.
For Magma (n=64): `2^29 − 1` bytes (~512 MiB). Exceeding this would silently
truncate the length block and forge a wrong tag.

RFC combined bound: `|A| + |P| < 2^(n/2)` bits (rfc/rfc9058.txt:281-282).
This is enforced by `mgm/mgm.go:validateLens()` in addition to the per-field cap.
For Magma this rules out two ~512 MiB fields together (sum ≥ 2^32 bits). For
Kuznyechik the per-field cap (effectively `maxInt`) already implies compliance.

> **32-bit portability note (MGM-51).** On 32-bit platforms (`GOARCH=386/arm`)
> the Kuznyechik shift `n/2-3 = 61` does not fit a signed `int`. The old code
> hardcoded `maxFieldShiftBits = 63` (64-bit only), causing `maxFieldLen()` to
> return `-1` on 32-bit, breaking all Seal/Open calls. The fix compares the
> shift against `bits.UintSize-1` (`math/bits`) and returns `maxInt` when it
> would overflow — effectively unbounded for any in-memory buffer.
> See `mgm/mgm.go:maxFieldLen`.

### Nonce / ICN constraint (RFC 9058 §3, §4.1)

The nonce is the **Initial Counter Nonce (ICN)**, exactly `n` bits. Its most
significant bit MUST be 0 — that bit is reserved as the domain-separation prefix
(`0` for the encryption counter, `1` for the MAC counter). The mode then forms two
counters by prepending one bit to ICN:

- Encryption counter seed: `Y_1 = E_K(0¹ || ICN)` (§4.1)
- MAC counter seed:        `Z_1 = E_K(1¹ || ICN)` (§4.1)

In a byte-oriented implementation the "prepend a bit" is realised by forcing the
top bit of byte 0: clear it (`&0x7F`) for the encryption pass, set it (`|0x80`)
for the MAC pass. See `mode.go:116` (`mgm.icn[0] |= 0x80`) and `mode.go:172`
(`mgm.icn[0] &= 0x7F`); engine `gost_gost2015.c:234,256,321,324`.

### Counter increments (RFC 9058 §3)

The block is split into two halves `A = L || R`, each `n/2` bits.

- `incr_r(A) = L || Vec_{n/2}( Int_{n/2}(R) [+] 1 )` — increment the **right**
  (low) half. Used for the encryption counter `Y`.
- `incr_l(A) = Vec_{n/2}( Int_{n/2}(L) [+] 1 ) || R` — increment the **left**
  (high) half. Used for the MAC counter `Z`.

Both increments are **big-endian** over their half: the integer is taken
MSB-first across the half, incremented modulo `2^(n/2)`, with carry propagating
toward the more-significant bytes within that half only (it never crosses into
the other half). gogost's `incr` (`mode.go:82-89`) adds from the last byte
backward, stopping on no-carry, applied to `bufP[:BlockSize/2]` for `Z`
(`mode.go:125`) and `bufP[BlockSize/2:]` for `Y` (`mode.go:180`). Engine
`inc_counter` (`tmp/engine/gost_grasshopper_cipher.c:581-595`) is identical,
called as `inc_counter(Zi, bl/2)` and `inc_counter(Yi + bl/2, bl/2)`
(`gost_gost2015.c:282,358`).

### Encryption pass (RFC 9058 §4.1)

Plaintext `P = P_1 || … || P_q` (last block may be partial, length `p` bytes).

```
Y_1 = E_K(0¹ || ICN)
for i = 1 … q:
    C_i = P_i XOR E_K(Y_i)          # last block: XOR with MSB_p(E_K(Y_q))
    Y_{i+1} = incr_r(Y_i)
```

A new keystream block `E_K(Y_i)` is produced for every plaintext block; `Y` is
advanced by `incr_r` after each. The partial final block XORs only the leading
`p` bytes (`mode.go:184-189`; engine processes byte-by-byte,
`gost_gost2015.c:355-369`).

> **Two levels of encryption — do not conflate them.** `Y_1` is *itself* the
> cipher output of the (masked) nonce: `Y_1 = E_K(0¹ || ICN)`. The per-block
> keystream is then a *second* application, `E_K(Y_i)`. So the first plaintext
> block is masked with `E_K(E_K(0¹ || ICN))` — the nonce is encrypted twice for
> block 1. A common first-attempt bug is to set `Y_1 = (0¹ || ICN)` directly (no
> encryption) and then XOR `E_K(Y_i)`; that drops one encryption and produces a
> wrong ciphertext. The checklist step 5 below (`Y_1 = E_K(icn & 0x7f…)`) is the
> correct reading: the seed is the *encryption* of the masked ICN, not the masked
> ICN itself.

### Authentication pass (RFC 9058 §4.1)

Inputs to the MAC are the **additional data** `A = A_1 … A_h` and the
**ciphertext** `C = C_1 … C_q` (note: MAC is over ciphertext, not plaintext —
encrypt-then-MAC). `sum` starts at 0.

```
Z_1 = E_K(1¹ || ICN)
# additional data
for i = 1 … h:
    H_i = E_K(Z_i)
    sum = sum XOR ( H_i  ⊗  A_i )       # A_h padded with zeros on the right
    Z_{i+1} = incr_l(Z_i)
# ciphertext
for j = 1 … q:
    H_{h+j} = E_K(Z_{h+j})
    sum = sum XOR ( H_{h+j}  ⊗  C_j )   # C_q padded with zeros on the right
    Z_{h+j+1} = incr_l(Z_{h+j})
# length block
H_{h+q+1} = E_K(Z_{h+q+1})
sum = sum XOR ( H_{h+q+1}  ⊗  ( len(A) || len(C) ) )
T   = MSB_S( E_K(sum) )
```

`⊗` is multiplication in `GF(2^n)`. `len(A)` and `len(C)` are the **bit** lengths
of the additional data and ciphertext, each encoded as an `n/2`-bit big-endian
integer, concatenated into one `n`-bit block (`mode.go:157-164`; engine
`gost_gost2015.c:443-444,464-474`).

Key contract details:

- Every full or partial block consumes one fresh `H_i = E_K(Z_i)`, then advances
  `Z` by `incr_l`. AD blocks and ciphertext blocks share the **same** `Z`
  sequence (no reset between AD and ciphertext) — `Z` keeps climbing across the
  whole MAC.
- Partial AD / ciphertext blocks are zero-padded to a full block on the **right**
  (least-significant end) before multiplication.
- The length block consumes the next `H` after the last data block.
- The final tag is `E_K(sum)` truncated to the `S` most-significant bytes
  (`MSB_S`), i.e. the **first** `S` bytes of the cipher output
  (`mode.go:167-168`; engine `gost_gost2015.c:480-483`).

### GF(2^n) multiplication and reduction polynomials (RFC 9058 §3)

The field is `GF(2^n)` with:

- `n = 64`:  `f(w) = w^64 + w^4 + w^3 + w + 1`  → reduction constant **`0x1b`**.
- `n = 128`: `f(w) = w^128 + w^7 + w^2 + w + 1` → reduction constant **`0x87`**.

Multiplication is the schoolbook shift-and-add (XOR) algorithm over the field.
The byte string is interpreted **big-endian**: the first byte holds the most
significant coefficients. On each step the accumulator `Z` is XORed with the
running shifted `X` when the corresponding bit of `Y` is set; `X` is shifted left
by one (toward more-significant) and reduced by XOR-ing the constant into the low
byte whenever the top bit overflowed.

For `n = 128` the engine and gogost split `Y` into two 64-bit halves and run
64 + 63 iterations plus a trailing conditional XOR (so the very last
shift-without-XOR is skipped — a micro-optimisation, the high bit of the product
can never be set after the final add). See `mul128.go:43-57` (`mul128.Mul`),
`gost_grasshopper_cipher.c:391-465` (`gf128_mul_uint64`). For `n = 64` it is a
single 63-iteration loop plus the trailing conditional XOR
(`gost_crypt.c:572-613`, `gf64_mul`). gogost's `mul64` instead uses `math/big`
with the same R64 = `0x1b` reduction (`third_party/gogost/mgm/mul64.go:22-63`).

---

## RFC ↔ implementation deltas

This is the core section. Every place where a reimplementer can silently diverge.

### 1. Endianness of the GF operands is BIG-endian (the surprising part)

GOST is little-endian in many places, but **MGM's field elements are big-endian
byte strings**. The first byte of a block is the most-significant field
coefficient. gogost `mul128` reads `x1 = BigEndian(x[0:8])`, `x0 = BigEndian(x[8:16])`
(`mul128.go:44-47`) and writes back with `BigEndian.PutUint64` (`mul128.go:54-55`).
The engine does `BSWAP64` only under `#ifdef L_ENDIAN` to normalize the
little-endian machine word back to the big-endian field convention
(`gost_grasshopper_cipher.c:397-410`). A reimplementer working purely with
`[]byte` and `encoding/binary.BigEndian` needs **no** byte-swap — the bytes are
already in field order. Do not little-endian these.

### 2. Two distinct counters with two distinct increments

The single most common bug: using one counter, or incrementing the wrong half.
`Y` (encryption) advances with `incr_r` (low half); `Z` (MAC) advances with
`incr_l` (high half). They are seeded from the SAME ICN but with different
domain bits (`0` vs `1` in the MSB). RFC 9058 §4.1; gogost `mode.go:125,180`;
engine `gost_gost2015.c:282,358`.

### 3. MSB-must-be-0 nonce rule is enforced by masking, not rejection

RFC 9058 reserves the top bit. gogost **panics** if the caller supplies a nonce
with the top bit set (`validateNonce`, `mode.go:95-97`). The engine silently
**masks** it: `nonce.c[0] &= 0x7f` in `setiv` (`gost_gost2015.c:234`), then
re-derives `0x80` / `0x7f` variants internally. A BSD reimplementation should
reject (panic/error) on `nonce[0]&0x80 != 0` to match gogost and to surface
caller bugs; if matching engine behavior exactly, mask instead. Both produce the
same ciphertext/tag for a conforming (top-bit-clear) nonce.

### 4. Length block is BIT length, big-endian, split n/2 + n/2

`len(A)` and `len(C)` are bit lengths (`bytes * 8`), each an `n/2`-bit big-endian
field, concatenated MSB-first. For `n=128` that is two `BigEndian.PutUint64`
(`mode.go:162-163`). For `n=64` it is two `BigEndian.PutUint32` (32-bit each,
`mode.go:159-160`). A reimplementer must multiply by 8 BEFORE encoding, and must
NOT byte-length it. Engine: `alen = ctx->len.u[0] << 3` (`gost_gost2015.c:443`).

### 5. MAC is over CIPHERTEXT (encrypt-then-MAC ordering)

`Seal` first runs `crypt` (produce ciphertext), then `auth` over the ciphertext
(`mode.go:200-205`). `Open` runs `auth` over the received ciphertext FIRST,
constant-time-compares the tag, and only then decrypts (`mode.go:223-227`). A
reimplementation must MAC the ciphertext bytes, not plaintext, and must verify
before releasing plaintext.

### 6. Partial-block zero padding is on the right (low/least-significant end)

Both AD and data partial blocks are right-zero-padded to a full block before the
GF multiply (`mode.go:128-133` for AD, `mode.go:146-153` for text). The padded
bytes occupy the trailing (least-significant) positions of the big-endian field
element. The keystream XOR for a partial final encryption block touches only the
real `p` bytes (`mode.go:184-189`).

### 7. `gf128` skips the final shift (off-by-one that is intentional)

gogost runs `gf128half(64, …)` then `gf128half(63, …)` and a trailing
conditional XOR (`mul128.go:49-53`); the engine mirrors this with `for i<64`,
`for i<63`, plus a tail `if (t&1)` (`gost_grasshopper_cipher.c:412-460`). A
naive 128-iteration loop that always shifts after the last bit will diverge by
one shift on inputs whose product's MSB would overflow. Match the 64+63+tail
structure (or equivalently: do not shift `X` after processing the final `Y` bit).

This off-by-one is a hazard *only* in the shift-the-multiplicand formulation that
gogost/engine happen to use (XOR `X` into the accumulator, then shift `X`). It is
**not intrinsic to the field math.** An equivalent Horner-form multiply — scan `Y`
MSB-first, and at the start of every iteration *after the first* shift the
**accumulator** left by one (toward more-significant) and reduce, then conditionally
XOR `X` — is naturally correct for both block sizes with no special-casing, no
64+63 split, and no tail. The clean-room impl (`mgm/mgm.go:gfMul`) takes
this route and matches gogost/engine bit-for-bit. If you reach for Horner-form you
can ignore this delta entirely; it only matters if you mirror gogost's
shift-multiplicand structure.

### 8. Streaming / state-reuse gotcha (gogost MGM is single-shot per call)

gogost's `MGM` struct holds mutable scratch (`bufP`, `bufC`, `sum`, `icn`,
`padded`). `Seal`/`Open` overwrite `icn` from the nonce each call (`mode.go:199,222`)
and `auth` clears `sum` at entry (`mode.go:113`), so the same `*MGM` is reusable
across calls — but it is **NOT goroutine-safe** (shared scratch). A reimplementer
exposing the streaming `gost_mgm128_aad/encrypt/finish` shape (as the engine does,
`gost_gost2015.c:238-493`) must additionally track `ares`/`mres` (partial AD/text
byte counts) and finalize the trailing partial block at the AD→text and
text→length transitions (engine `gost_gost2015.c:341-351,450-458`). The one-shot
`Seal`/`Open` API hides all of that.

### 9. No S-box / key-meshing divergences apply to MGM

The three known gogost↔engine divergences in `TODO.md` (S-box row order,
R 34.11-94 empty-input finalization, CryptoPro key meshing) do **not** touch MGM:

- MGM never hashes (no R 34.11-94), so the empty-input finalization delta is
  irrelevant.
- MGM does **no** CryptoPro key meshing — the per-block `H_i = E_K(Z_i)` re-keys
  nothing; the meshing in `TODO.md` is specific to GOST28147 IMIT
  (`gost_crypt.c:1510-1524`), not MGM. The two R 1323565.1.026-2019 KATs pass
  bit-for-bit between gogost and engine.
- The S-box row-order note concerns GOST R 34.11-94's internal `step`, not the
  GOST R 34.12-2015 ciphers (Kuznyechik/Magma) that MGM drives. MGM's correctness
  depends only on those block ciphers' published S-boxes, which already agree.

So MGM can be reimplemented against the RFC + the inlined vectors with no hidden
parity caveat, provided the underlying Kuznyechik/Magma block ciphers are correct.

---

## Test vectors

### Existing in-repo KATs

`internal/gost/mgm_test.go` (`TestMGM_EngineVectors`) holds both vectors,
ported from `tmp/engine/test_mgm.c`:

- Kuznyechik: key/nonce/aad/plain at `mgm_test.go:38-51`,
  expected ciphertext+tag at `mgm_test.go:52-58`. Engine source
  `tmp/engine/test_mgm.c:41-73` (`gh_key`, `gh_nonce`, `gh_adata`, `gh_pdata`,
  `gh_e_cdata`, `gh_e_tag`).
- Magma: `mgm_test.go:62-82`. Engine source `tmp/engine/test_mgm.c:76-108`
  (`mg_key`, `mg_nonce`, `mg_adata`, `mg_pdata`, `mg_e_cdata`, `mg_e_tag`).

These are the canonical R 1323565.1.026-2019 §A worked examples.

### Inline runnable vector — Kuznyechik (n=128), tag = 16 bytes

```
K     = 8899aabbccddeeff0011223344556677 fedcba98765432100123456789abcdef   (32 bytes)
ICN   = 1122334455667700ffeeddccbbaa9988                                    (16 bytes, MSB of byte0 = 0x11, top bit clear OK)
A     = 02020202020202020101010101010101
        04040404040404040303030303030303
        ea0505050505050505                                                  (41 bytes)
P     = 1122334455667700ffeeddccbbaa9988
        00112233445566778899aabbcceeff0a
        112233445566778899aabbcceeff0a00
        2233445566778899aabbcceeff0a0011
        aabbcc                                                              (67 bytes)

C     = a9757b8147956e9055b8a33de89f42fc
        8075d2212bf9fd5bd3f7069aadc16b39
        497ab15915a6ba85936b5d0ea9f6851c
        c60c14d4d3f883d0ab94420695c76deb
        2c7552                                                              (67 bytes)
T     = cf5d656f40c34f5c46e8bb0e29fcdb4c                                    (16 bytes)
```

`Seal(nil, ICN, P, A)` must return `C || T`. `Open` of `C || T` returns `P`.
Note `len(A) = 41*8 = 328 bits`, `len(C) = 67*8 = 536 bits`; the length block is
`BigEndian64(328) || BigEndian64(536)` = `00000000000001480000000000000218`.

### Inline runnable vector — Magma (n=64), tag = 8 bytes

```
K     = ffeeddccbbaa99887766554433221100 f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
ICN   = 12def06b3c130a59
A     = 0101010101010101020202020202020203030303030303030404040404040404
        0505050505050505ea                                                 (41 bytes)
P     = ffeeddccbbaa99881122334455667700
        8899aabbcceeff0a0011223344556677
        99aabbcceeff0a001122334455667788
        aabbcceeff0a00112233445566778899
        aabbcc                                                             (67 bytes)
C     = c795066c5f9ea03b85113342459185ae
        1f2e00d6bf2b785d940470b8bb9c8e7d
        9a5dd3731f7ddc70ec27cb0ace6fa576
        70f65c646abb75d547aa37c3bcb5c34e
        03bb9c
T     = a7928069aa10fd10
```

### Regenerating against gost-engine (ground truth)

The engine self-test binary `tmp/engine/test_mgm.c` embeds exactly these vectors;
it is the parity oracle. There is no CLI MGM oracle wired up in this repo's
debugging toolkit (the OMAC/CTR `openssl enc -engine gost` recipes in CLAUDE.md
cover CTR+OMAC, not MGM).

---

## Re-implementation checklist

Each step is independently testable against the vectors above.

1. **Block ciphers first.** Have correct Kuznyechik (`E_K` over 16 bytes) and
   Magma (`E_K` over 8 bytes) single-block encrypt. Verify with the GOST R
   34.12-2015 single-block KATs before touching MGM. Everything below assumes
   `E_K` is correct.

2. **GF(2^n) multiply, n=64.** Implement big-endian shift-and-XOR with reduction
   `0x1b`. Unit-test against `third_party/gogost/mgm/mul64_test.go` vectors (or
   any standalone GF(2^64) test). Treat operands as big-endian `[]byte`.

3. **GF(2^n) multiply, n=128.** Same, reduction `0x87`, two-half structure
   (64 + 63 iterations + tail). Test against `mul128_test.go`. Confirm the
   final-shift-skip behavior (delta §7).

4. **incr_l / incr_r.** Big-endian increment of the left half (`Z`) and right
   half (`Y`) independently, carry confined to the half. Unit-test: increment a
   known half across a byte-carry boundary (e.g. `…00ff → …0100` within the half,
   no spill to the other half).

5. **Counter seeds.** From a top-bit-clear ICN, compute `Y_1 = E_K(icn & 0x7f…)`
   and `Z_1 = E_K(icn | 0x80…)`. Verify `Y_1`/`Z_1` for the inline Kuznyechik
   vector by instrumenting (or trust step 8's end-to-end check).

6. **Encryption pass (`crypt`).** CTR over `Y` with `incr_r`, partial last block
   XOR of leading bytes only. Verify ciphertext `C` matches the inline vector
   (tag not yet needed — split the check).

7. **Authentication pass (`auth`).** Over `A` then `C` (ciphertext!), shared `Z`
   sequence with `incr_l`, right-zero-padded partials, then the
   `BigEndian(len(A)*8) || BigEndian(len(C)*8)` block, then `sum`, then
   `T = MSB_S(E_K(sum))`. Verify `T` matches.

8. **End-to-end Seal/Open.** `Seal` = crypt then auth; assert `C || T`. `Open` =
   auth then constant-time tag compare then crypt; assert round-trip and that a
   single flipped tag/ciphertext byte yields an error. Run both inline vectors
   (Kuznyechik n=128, Magma n=64).

9. **Edge rules.** Enforce `4 ≤ S ≤ n/8` bytes, nonce length `== n/8`,
   `nonce[0]&0x80 == 0` (reject), and `len(text)+len(ad) ≤ 2^(n/2)−1` bytes.
   At least one of text / AD must be non-empty.

---

## Conformance & fuzz testing

Once the clean-room MGM is built (placeholder import alias `mynew`, exposing the
same `cipher.AEAD`-shaped `Seal`/`Open` as `mgm.NewMGM` in
`third_party/gogost/mgm/mode.go:47-72`), prove parity by **differential testing**
against two reference targets: (1) raw gogost `mgm` driving gogost's own
`gost3412128`/`gost341264` block ciphers (the same code path
`internal/gost/mgm_test.go:96-103` exercises), and (2) the in-repo usage shape —
your own clean-room block cipher feeding both implementations the identical key.
There is no CLI MGM oracle (the `openssl enc -engine gost` recipes in CLAUDE.md
cover CTR+OMAC, not MGM), so the gogost API is the ground truth. Fuzz random
`key` + `nonce` (top bit of `nonce[0]` cleared — see delta §3) + arbitrary `aad`
+ `plaintext`, for **both** the 64-bit (Magma, tag 8) and 128-bit (Kuznyechik,
tag 16) instances; assert `Open(Seal()) == plaintext` and that `Seal`'s
`ciphertext || tag` is byte-identical to the reference.

### KAT conformance test

Seeded with the exact pinned vectors from this doc (Test vectors §). It runs the
clean-room `mynew` and the gogost reference and asserts both equal the pinned
`C || T`.

```go
//go:build gost

package mynew_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
	"go.stargrave.org/gogost/v7/mgm"

	mynew "yourpkg/mgm" // clean-room impl: NewMGM(cipher.Block, tagSize) (cipher.AEAD, error)
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestMGMConformance(t *testing.T) {
	cases := []struct {
		name             string
		newRef, newMine  func(key []byte) (cipher.Block, error)
		key, nonce       string
		aad, plain       string
		wantCT, wantTag  string
	}{
		{
			name:   "Kuznyechik",
			newRef: func(k []byte) (cipher.Block, error) { return gost3412128.NewCipher(k), nil },
			key:    "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			nonce:  "1122334455667700ffeeddccbbaa9988",
			aad:    "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505",
			plain: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a" +
				"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
			wantCT: "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39" +
				"497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552",
			wantTag: "cf5d656f40c34f5c46e8bb0e29fcdb4c",
		},
		{
			name:   "Magma",
			newRef: func(k []byte) (cipher.Block, error) { return gost341264.NewCipher(k), nil },
			key:    "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			nonce:  "12def06b3c130a59",
			aad:    "0101010101010101020202020202020203030303030303030404040404040404" +
				"0505050505050505ea",
			plain: "ffeeddccbbaa998811223344556677008899aabbcceeff0a0011223344556677" +
				"99aabbcceeff0a001122334455667788aabbcceeff0a00112233445566778899aabbcc",
			wantCT: "c795066c5f9ea03b85113342459185ae1f2e00d6bf2b785d940470b8bb9c8e7d" +
				"9a5dd3731f7ddc70ec27cb0ace6fa57670f65c646abb75d547aa37c3bcb5c34e03bb9c",
			wantTag: "a7928069aa10fd10",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := unhex(t, tc.key)
			nonce := unhex(t, tc.nonce)
			aad := unhex(t, tc.aad)
			plain := unhex(t, tc.plain)
			want := append(append([]byte{}, unhex(t, tc.wantCT)...), unhex(t, tc.wantTag)...)
			tagSize := len(unhex(t, tc.wantTag))

			refBlk, err := tc.newRef(key)
			if err != nil {
				t.Fatalf("ref cipher: %v", err)
			}
			ref, err := mgm.NewMGM(refBlk, tagSize)
			if err != nil {
				t.Fatalf("ref NewMGM: %v", err)
			}
			// Clean-room impl drives its OWN block cipher; here we reuse the same
			// gogost block so the diff isolates the MGM mode itself. Swap to your
			// own Kuznyechik/Magma to also cover the block-cipher layer.
			mine, err := mynew.NewMGM(refBlk, tagSize)
			if err != nil {
				t.Fatalf("mynew NewMGM: %v", err)
			}

			gotRef := ref.Seal(nil, nonce, plain, aad)
			gotMine := mine.Seal(nil, nonce, plain, aad)
			if !bytes.Equal(gotRef, want) {
				t.Fatalf("gogost ref != pinned:\n got  %x\n want %x", gotRef, want)
			}
			if !bytes.Equal(gotMine, want) {
				t.Fatalf("mynew != pinned:\n got  %x\n want %x", gotMine, want)
			}

			back, err := mine.Open(nil, nonce, gotMine, aad)
			if err != nil {
				t.Fatalf("mynew Open: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatalf("round-trip: got %x want %x", back, plain)
			}
		})
	}
}
```

### Fuzz harness

Seeds the corpus from the KAT inputs, normalizes the random `[]byte` into MGM's
fixed-size arguments (32-byte key, `blockSize`-byte nonce with top bit cleared,
remainder split into AAD and plaintext), runs both implementations, and
`t.Fatalf`s on any divergence. Both block sizes are covered by deriving the
selector from the seed.

```go
//go:build gost

package mynew_test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"
	"go.stargrave.org/gogost/v7/mgm"

	mynew "yourpkg/mgm"
)

func FuzzMGMConformance(f *testing.F) {
	// Seed from the two pinned KATs: blockSize selector, key, nonce, aad, plain.
	f.Add(byte(16),
		unhexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		unhexF("1122334455667700ffeeddccbbaa9988"),
		unhexF("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505"),
		unhexF("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0aaabbcc"))
	f.Add(byte(8),
		unhexF("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		unhexF("12def06b3c130a59"),
		unhexF("0101010101010101020202020202020203030303030303030404040404040404"),
		unhexF("ffeeddccbbaa998811223344556677008899aabbcceeff0aaabbcc"))

	f.Fuzz(func(t *testing.T, sel byte, rndKey, rndNonce, aad, plain []byte) {
		blockSize := 16
		newBlk := func(k []byte) cipher.Block { return gost3412128.NewCipher(k) }
		if sel&1 == 0 {
			blockSize, newBlk = 8, func(k []byte) cipher.Block { return gost341264.NewCipher(k) }
		}
		tagSize := blockSize // full-width tag

		// Normalize into fixed-size args.
		key := fixLen(rndKey, 32)
		nonce := fixLen(rndNonce, blockSize)
		nonce[0] &= 0x7F // MSB-must-be-0 (delta §3); avoids the gogost panic
		// MGM rejects empty text+aad; guarantee at least one byte of plaintext.
		if len(plain) == 0 && len(aad) == 0 {
			plain = []byte{0}
		}

		blk := newBlk(key)
		ref, err := mgm.NewMGM(blk, tagSize)
		if err != nil {
			t.Skipf("ref NewMGM: %v", err)
		}
		mine, err := mynew.NewMGM(blk, tagSize)
		if err != nil {
			t.Skipf("mynew NewMGM: %v", err)
		}

		gotRef := ref.Seal(nil, nonce, plain, aad)
		gotMine := mine.Seal(nil, nonce, plain, aad)
		if !bytes.Equal(gotRef, gotMine) {
			t.Fatalf("Seal mismatch (bs=%d):\n ref  %x\n mine %x", blockSize, gotRef, gotMine)
		}

		back, err := mine.Open(nil, nonce, gotMine, aad)
		if err != nil {
			t.Fatalf("mynew Open rejected own Seal: %v", err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("round-trip mismatch:\n got  %x\n want %x", back, plain)
		}
	})
}
```

`unhexF` is a panic-on-error `hex.DecodeString` (seed corpus only); `fixLen`
truncates or zero-right-pads a slice to `n` bytes — both are two-line local
helpers. Note: feeding the SAME block-cipher key to both AEADs isolates the MGM
mode; to also fuzz the block-cipher layer, build `mine` from your clean-room
Kuznyechik/Magma over `key` instead of from `blk`.

### Run

```sh
go test -tags gost -run TestMGMConformance ./yourpkg/
go test -tags gost -fuzz=FuzzMGMConformance -fuzztime=30s ./yourpkg/
```

---

## References

- **RFC 9058** — "Multilinear Galois Mode (MGM)".
  https://github.com/bigbes/gostcrypto/blob/master/mgm/rfc/rfc9058.txt
  - §3 Basic terms: `MSB_i`, `incr_l`, `incr_r`, the GF(2^64)/GF(2^128) field
    polynomials (`w^64+w^4+w^3+w+1` → `0x1b`; `w^128+w^7+w^2+w+1` → `0x87`).
  - §4 / §4.1 MGM encryption and tag generation: `Y_1=E_K(0¹||ICN)`,
    `Z_1=E_K(1¹||ICN)`, `H_i=E_K(Z_i)`, the `sum`/`T=MSB_S(E_K(sum))` recurrence,
    the `len(A)||len(C)` block, tag-size bound `32 ≤ S ≤ n` bits.
- **R 1323565.1.026-2019** — Russian recommendation defining MGM and the two
  worked KATs reproduced above (Kuznyechik §A, Magma §A).
- **GOST R 34.12-2015** — Kuznyechik (128-bit) and Magma (64-bit) block ciphers
  that MGM drives.

Key source citations (de-facto spec this repo matches):

- `third_party/gogost/mgm/mode.go:47-72` — `NewMGM`, size/tag validation,
  `MaxSize = 2^(n/2)−1`.
- `third_party/gogost/mgm/mode.go:82-98` — `incr`, `validateNonce` (top-bit panic).
- `third_party/gogost/mgm/mode.go:112-169` — `auth` (Z counter, H_i, sum, length
  block, tag truncation).
- `third_party/gogost/mgm/mode.go:171-190` — `crypt` (Y counter CTR).
- `third_party/gogost/mgm/mode.go:192-229` — `Seal` / `Open` (encrypt-then-MAC,
  constant-time verify).
- `third_party/gogost/mgm/mul128.go:26-57` — GF(2^128) multiply, big-endian,
  `0x87`, 64+63+tail.
- `third_party/gogost/mgm/mul64.go:22-63` — GF(2^64) multiply, R64 = `0x1b`.
- `internal/gost/mgm_test.go:26-130` — both KATs and the Seal/Open round-trip.

gost-engine ground truth (Tarantool upstream, v3.0.3):

- `tmp/engine/gost_gost2015.c:207-493` — `gost_mgm128_{init,setiv,aad,encrypt,decrypt,finish,tag}`.
- `tmp/engine/gost_grasshopper_cipher.c:391-465` — `gf128_mul_uint64` (`0x87`).
- `tmp/engine/gost_grasshopper_cipher.c:581-595` — `inc_counter`.
- `tmp/engine/gost_crypt.c:572-613` — `gf64_mul` (`0x1b`).
- `tmp/engine/test_mgm.c:41-108` — the two KATs (vectors are byte-identical to
  `mgm_test.go`).
