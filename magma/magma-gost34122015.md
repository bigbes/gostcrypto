# Magma — GOST R 34.12-2015 64-bit block cipher

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

## What this is

Magma is the 64-bit-block / 256-bit-key block cipher standardised in **GOST R
34.12-2015** and republished as **RFC 8891**. Cryptographically it is the
**GOST 28147-89 core with two things pinned down**:

1. a single **fixed S-box** — the tc26 param-Z set (`id-tc26-gost-28147-param-Z`,
   OID `1.2.643.7.1.2.5.1.1`); GOST 28147-89 left the S-box as a parameter,
   Magma fixes it, and
2. a **byte/word-order flip** relative to legacy 28147-89: RFC 8891 numbers
   bits big-endian / MSB-first, whereas RFC 5830 (legacy 28147) is
   little-endian. This endianness flip is the **#1 reimplementation trap** and
   is the whole reason Magma needs its own wrapper instead of being an alias
   for 28147-89.

Everything else — the Feistel structure, the round function (mod-2³² key
addition → S-box substitution → 11-bit cyclic left rotate), the 32-round
schedule (K1..K8 three times forward, then K8..K1 reverse), the key size, and
the block size — is identical to the legacy 28147-89 core documented in the
sibling guide.

> **Read the sibling guide first:**
> [`gost28147-cipher.md`](../gost28147/gost28147-cipher.md). This document does **not**
> re-derive the 28147-89 core. It documents only the delta layer that turns
> that core into Magma. Section/delta references like "D1" / "§2" below point
> into the sibling guide.

There is **no GF(2) polynomial reduction** anywhere in Magma. (The
linear-mixing GF(2⁸) multiply-and-reduce step belongs to *Kuznyechik*,
GOST R 34.12-2015's **128-bit** cipher — a structurally different algorithm.
Do not import any GF reduction here.)

**Repo status: clean-room implementation.** `magma/magma.go` IS the
implementation — zero GPL code in this module's dependency graph. The
`go.mod` carries no gogost dependency; `internal/` and `third_party/`
do not exist here. This document serves as the authoritative implementation
guide; there is nothing to "enable" — the implementation already lives here.

**Where this module uses it (call sites)**

- `exports.go:35` — `MagmaBlockSize = magma.BlockSize` (= 8).
- `exports.go:104` — `NewMagmaCipher(key) cipher.Block`, the opaque
  `cipher.Block` handle used by all composing modes.
- `primitives.go` — `MagmaEncrypt` / `MagmaDecrypt` (single 8-byte block,
  fixed tc26-Z S-box, no caller-selectable S-box).
- `magma/magma_test.go` and `magma/guard_test.go` — in-package KATs (RFC
  8891 A.3–A.4, GOST R 34.13-2015 §A.2.1 multi-block ECB), in-place
  Encrypt/Decrypt coverage, and panic-contract tests.
- Differential parity tests vs the gogost reference live in
  `../gostcrypto-compat/parity/magma/` (GPL-quarantined, not in this module's
  CI) and pass — that is the strongest external correctness signal.
- TLS suite **0xC101** `GOST2012-MAGMA-MAGMAOMAC` (RFC 9189 §4.4) uses Magma
  in CTR mode + OMAC; the dialer's end-to-end EE tests exercise the full
  block→CTR→OMAC→ACPKM stack against a live Tarantool EE server.

**Dimensions (constants)**

| Quantity            | Value              | Source |
|---------------------|--------------------|--------|
| Block size          | 8 bytes (64 bit)   | `magma/magma.go` `BlockSize = 8` |
| Key size            | 32 bytes (256 bit) | `magma/magma.go` `KeySize = 32` |
| Subkeys             | 8 × 32-bit         | same as 28147-89 core |
| Rounds (enc/dec)    | 32                 | `seqEncrypt`/`seqDecrypt` (sibling §4/§5) |
| S-box               | tc26 param-Z, fixed | `magma/magma.go` `sboxTC26Z` |


## Specification

RFC 8891 defines Magma over bit strings indexed **MSB-first** (big-endian).
The standard never mentions GOST 28147-89; it is a self-contained restatement
whose internals happen to coincide with the 28147-89 core under a
byte-reversal. The clean way to implement it is: **reverse to big-endian at the
boundary, run the 28147-89 core, reverse back.** That is exactly what gogost
and gost-engine do (deltas §RFC↔impl below).

### 1. Sizes (RFC 8891 §1)

> "block length of n=64 bits and key length of k=256 bits"

Block = 8 octets, key = 32 octets. Same as 28147-89.

### 2. The fixed S-box π (RFC 8891 §4.1)

RFC 8891 §4.1 gives the substitution as eight 16-entry nibble permutations
`Pi'_0 … Pi'_7`, where (in the RFC's big-endian convention) `Pi'_7` substitutes
the **most-significant** nibble and `Pi'_0` the least. Verbatim from the RFC:

```
Pi'_0 = (12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7,  0,  3, 15,  1)
Pi'_1 = ( 6, 8, 2, 3,  9,10,  5,12,  1,14,  4, 7, 11, 13,  0, 15)
Pi'_2 = (11, 3, 5, 8,  2,15, 10,13, 14, 1,  7, 4, 12,  9,  6,  0)
Pi'_3 = (12, 8, 2, 1, 13, 4, 15, 6,  7, 0, 10, 5,  3, 14,  9, 11)
Pi'_4 = ( 7,15, 5,10,  8, 1,  6,13,  0, 9,  3,14, 11,  4,  2, 12)
Pi'_5 = ( 5,13,15, 6,  9, 2, 12,10, 11, 7,  8, 1,  4,  3, 14,  0)
Pi'_6 = ( 8,14, 2, 5,  6, 9,  1,12, 15, 4, 11, 0, 13, 10,  3,  7)
Pi'_7 = ( 1, 7,14,13,  0, 5,  8, 3,  4,15, 10, 6,  9, 12, 11,  2)
```

This is **byte-for-byte the tc26 param-Z S-box** — the same data the legacy
28147-89 code stores as `Gost28147_TC26ParamSetZ`. In the engine / gogost
**internal (LE) row convention**, where `s[0]` substitutes the *low* nibble,
the table is (engine `tmp/engine/gost89.c:214-238`, gogost
`third_party/gogost/gost28147/sbox.go:72-81`):

```
s[0] = {12,4, 6, 2,10, 5,11, 9,14, 8,13, 7, 0, 3,15, 1}   // == RFC Pi'_0
s[1] = {6, 8, 2, 3, 9,10, 5,12, 1,14, 4, 7,11,13, 0,15}   // == RFC Pi'_1
s[2] = {11,3, 5, 8, 2,15,10,13,14, 1, 7, 4,12, 9, 6, 0}   // == RFC Pi'_2
s[3] = {12,8, 2, 1,13, 4,15, 6, 7, 0,10, 5, 3,14, 9,11}   // == RFC Pi'_3
s[4] = {7,15, 5,10, 8, 1, 6,13, 0, 9, 3,14,11, 4, 2,12}   // == RFC Pi'_4
s[5] = {5,13,15, 6, 9, 2,12,10,11, 7, 8, 1, 4, 3,14, 0}   // == RFC Pi'_5
s[6] = {8,14, 2, 5, 6, 9, 1,12,15, 4,11, 0,13,10, 3, 7}   // == RFC Pi'_6
s[7] = {1, 7,14,13, 0, 5, 8, 3, 4,15,10, 6, 9,12,11, 2}   // == RFC Pi'_7
```

**Row-order note (read this).** In gogost's internal convention `s[i]` is
applied to the i-th nibble counting from the *low* end, and the rows line up
one-to-one with the RFC: **gogost `s[i] == RFC Pi'_i`** (gogost `s[0]` low
nibble `== Pi'_0`, …, `s[7]` high nibble `== Pi'_7`). The RFC's MSB-first text
and gogost's LE core read the *same* nibble-row pairing because the Magma
wrapper reverses the whole 8-byte block (delta **M2**) — the reversal lands
each `Pi'_i` back on the nibble gogost numbers `i`. So the rows above are the
literal gogost array, **not** to be reversed when transcribing. (If you build a
from-scratch big-endian implementation that reads bits MSB-first exactly as
RFC 8891 §4.1 states, you also index `Pi'_0` on the low nibble of the
big-endian word — same pairing, no transposition.) Verify against the
§Test-vectors KAT before trusting it.

The §8 table in the sibling guide (`gost28147-cipher.md:237`) lists this same
tc26-Z set in the identical gogost (`s[0]`=low-nibble) row order
(`s[0]={12,4,6,...}` … `s[7]={1,7,14,...}`); cross-check against it
byte-for-byte.

### 3. The round function g (RFC 8891 §4.2)

RFC 8891 §4.2 defines, for round key `k`:

> `g[k](a) = (t(Vec32(Int32(a) [+] Int32(k)))) <<<_11`

read as three steps on a 32-bit half `a`:

1. **Key addition mod 2³²:** `a' = (a + k) mod 2^32`.
2. **Substitution `t`:** split `a'` into eight nibbles and substitute each
   through its π row — `t(a') = Pi'_7(n7) || … || Pi'_0(n0)`.
3. **11-bit cyclic left rotate:** `<<<_11` rotates the 32-bit result left by
   11 bit positions.

This is identical to the 28147-89 round function (sibling §2): same mod-2³²
add, same nibble substitution, same `rotl32(·, 11)`. Magma changes *which*
S-box is used and the *byte order in which `a` is assembled*, nothing in the
round function itself.

### 4. Feistel structure & round schedule (RFC 8891 §4.3)

256-bit key split into eight 32-bit words (RFC §4.3, big-endian):

```
K1 = k_255..k_224   (most-significant 32 bits)
K2 = k_223..k_192
...
K8 = k_31 ..k_0     (least-significant 32 bits)
```

32 rounds, round-key order:

```
Rounds  1– 8:  K1 K2 K3 K4 K5 K6 K7 K8     (forward)
Rounds  9–16:  K1 K2 K3 K4 K5 K6 K7 K8     (forward)
Rounds 17–24:  K1 K2 K3 K4 K5 K6 K7 K8     (forward)
Rounds 25–32:  K8 K7 K6 K5 K4 K3 K2 K1     (reverse)
```

i.e. **K1..K8 forward 24 rounds, then K8..K1 reverse 8 rounds** — identical to
28147-89's `SeqEncrypt = [0..7, 0..7, 0..7, 7..0]`. Each round is the standard
Feistel step `(L, R) ← (R, L ⊕ g[k](R))`; gogost/engine implement it by
swapping the *names* `n1`/`n2` each round rather than the data (engine
`tmp/engine/gost89.c:337-373` `magmacrypt`; sibling §3). Decryption uses the
reverse schedule `K1..K8 forward 8, then K8..K1 reverse 24` (the 28147-89
`SeqDecrypt`).

### 5. Mapping a Magma block onto the 28147-89 core (the implementation recipe)

This is how gogost actually realises §1–§4 (`third_party/gogost/gost341264/cipher.go`):

**Key (constructor, `cipher.go:37-45`):** reverse each 4-byte key word, then
hand the 32-byte result to the 28147-89 core with the tc26-Z S-box:

```
for each 32-bit word i in 0..7:
    keyCompatible[4i+0] = key[4i+3]
    keyCompatible[4i+1] = key[4i+2]
    keyCompatible[4i+2] = key[4i+1]
    keyCompatible[4i+3] = key[4i+0]
core = NewGOST28147(keyCompatible, sbox=tc26-Z)
```

This reverse-per-word makes the 28147-89 core's **little-endian** word read of
`keyCompatible` reproduce Magma's **big-endian** `K1 = k_255..k_224` split.

**Block (`Encrypt`/`Decrypt`, `cipher.go:54-92`):** reverse all 8 input bytes,
run the core, reverse all 8 output bytes:

```
tmp[j] = src[7-j]   for j in 0..7
core.Encrypt(tmp, tmp)   // or core.Decrypt for decryption
dst[j] = tmp[7-j]   for j in 0..7
```

The full-block reversal makes the core's little-endian block read reproduce
Magma's big-endian numbering. **Encrypt and Decrypt differ only in which core
routine they call** — the byte-reversal wrapper is identical (`cipher.go:54-72`
vs `:74-92`).


## RFC ↔ implementation deltas

The core deltas of the underlying 28147-89 primitive (little-endian packing,
output half-swap, 16-round MAC schedule, S-box row order vs textbook) are
documented as **D1–D8** in the sibling guide and are **inherited unchanged**.
This section lists only what is *new in Magma*.

### M1. Per-word key byte reversal (big-endian key split)

RFC 8891 §4.3 splits the key big-endian (`K1` = most-significant 32 bits). The
28147-89 core reads key words little-endian (sibling D1). gogost bridges this
by reversing the four bytes **within each 32-bit word** before constructing the
core (`third_party/gogost/gost341264/cipher.go:37-43`). Engine does the same
reversal inline in `magma_key` (`tmp/engine/gost89.c:587-591`):
`c->key[i] = k[j+3] | (k[j+2]<<8) | (k[j+1]<<16) | (k[j]<<24)` — big-endian word
read, versus the legacy `gost_key` little-endian read. **Skipping this gives a
cipher that passes no Magma vector but may look "GOST-ish".**

> The engine additionally subtracts a random `mask[i]` here and adds it back in
> the round (`gost89.c:339-346`) purely as a side-channel countermeasure; the
> mask cancels and has no effect on output. A clean reimplementation ignores it.

### M2. Whole-block byte reversal (big-endian block numbering)

RFC 8891 numbers block bits MSB-first. The core packs octets little-endian
(sibling D1). gogost reverses all 8 octets on input and on output
(`cipher.go:55-62` and `:64-71`). Engine `magmacrypt` does the identical thing
with `in[7-0], in[7-1], …` on read and `out[7-0], …` on write
(`tmp/engine/gost89.c:335-336, 375-382`). **Combined with M1, these two
reversals are the entire difference between Magma and a tc26-Z-keyed
28147-89.** They are also why the §2 row pairing holds with no transposition
(gogost `s[i] == RFC Pi'_i`): the whole-block reversal lands each RFC `Pi'_i`
back on the nibble gogost numbers `i`, so the array rows match the RFC rows
in order.

### M3. Fixed tc26-Z S-box, no parameter choice

28147-89 takes the S-box as a parameter (CryptoPro-A, tc26-Z, …). Magma fixes
it to tc26 param-Z (RFC 8891 §4.1). gogost hardcodes
`&gost28147.SboxIdtc26gost28147paramZ` in the constructor
(`cipher.go:45`); the repo wrapper exposes **no** S-box argument
(`internal/gost/primitives_gost.go:103`, `exports_gost.go:76`). A
reimplementation must *not* accept an S-box parameter on the Magma API.

### M4. tc26-Z produces identical substitution across gogost and gost-engine — but the two store the rows in OPPOSITE array order

As with the 28147-89 cipher (sibling D5), gogost
`SboxIdtc26gost28147paramZ` (`sbox.go:72-81`) and engine
`Gost28147_TC26ParamSetZ` (`tmp/engine/gost89.c:214-238`) compute the **same
substitution**, but they do **not** hold the same bytes in the same array rows.
gogost `array[0]` is the **low-nibble** row; engine `array[0]` is the
**high-nibble** row (the engine struct is laid out `{k8,…,k1}`, so `array[0]=k8`
and `kboxinit` uses `k1`, the *last* struct entry, for the low nibble). Concretely:

- gogost `s[0]` (low nibble) `= {12,4,6,2,10,5,11,9,…}` (`sbox.go:73`) equals
  engine **k1 = the last struct entry = array row 7** =
  `{0xc,0x4,0x6,0x2,0xa,0x5,0xb,0x9,…}` (`gost89.c:236-237`).
- engine **array row 0 = k8** = `{0x1,0x7,0xe,0xd,…}` (`gost89.c:215-216`)
  equals gogost `s[7]` (high nibble, `sbox.go:80`).

So gogost `array[i] == engine array[7-i]`: the two impls store the rows in
**reverse array order** and compensate at the indexing step, yielding identical
output. Do **not** copy engine `array[0]` into gogost `s[0]` — you would feed
the high-nibble row to the low-nibble slot and break the cipher. (The sibling
guide states the same fact correctly at `gost28147-cipher.md:303-306`.) The
"rotated 90° / reverse-row-order" divergence noted in `TODO.md:9` is a separate
issue — it concerns the **GOST R 34.11-94 hash's** internal use of 28147, not
Magma or the plain ECB cipher.

### M5. No GF reduction (Magma ≠ Kuznyechik)

Magma's only non-linear step is the 4-bit S-box; its only diffusion is the
11-bit rotate. There is **no GF(2⁸) multiply or polynomial reduction**. The
LFSR-style linear transform with the field reduction polynomial
`x⁸+x⁷+x⁶+x+1` belongs to **Kuznyechik** (`gost3412128`,
`internal/gost/exports_gost.go` `KuznyechikEncrypt`), the 128-bit cipher in the
same standard. Keep the two implementations entirely separate.


## Test vectors

### V1. RFC 8891 Appendix A single-block KAT (inline, authoritative)

Verbatim from RFC 8891 Appendix A.3–A.4. Pinned by `TestRFC8891KAT` and
`TestEncryptDecryptInPlace` in `magma/magma_test.go` and `magma/guard_test.go`.

```
key (32B):        ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
plaintext (8B):   fedcba9876543210
ciphertext (8B):  4ee901e5c2d8ca3d
```

A correct implementation that applies M1 + M2 + the tc26-Z S-box + the §3 round
function + the §4 schedule MUST produce `4ee901e5c2d8ca3d` and
`Decrypt(key, 4ee901e5c2d8ca3d)` MUST return `fedcba9876543210`.

### V2. Multi-block ECB (GOST R 34.13-2015 §A.2.1)

Pinned by `TestECB_A21` in `magma/magma_test.go`. Exercises cipher-instance
reuse across four 8-byte blocks in ECB mode, both encrypt and decrypt.

```
key:    ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
pt:     92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
ct:     2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb
```

(Expected ciphertext derived against gost-engine 3.0.3:
`openssl enc -magma-ecb -K <key> -nopad`.)

### V3. Magma ACPKM key meshing (engine etalon)

Meshing = encrypt the 32-byte `ACPKM_D_const`
(`0x80,0x81,…,0x9f`, engine `tmp/engine/gost89.c:247-252`) block-by-block under
the current key to derive the next key. Pinned in `ctracpkm/ctracpkm_test.go`.

```
initialKey: 8899aabbccddeeff0011223344556677 fedcba98765432100123456789abcdef
wantK2:     863ea017842c3d372b18a85a28e2317d 74befc107720de0c9e8ab974abd00ca0
```

### V4. End-to-end interop

Suite 0xC101 `GOST2012-MAGMA-MAGMAOMAC` is exercised by
`TestTarantoolEE_Ping_GOST_Pure/GOST2012-MAGMA-MAGMAOMAC` against a live
Tarantool-EE server in the dialer module — the strongest signal that the
block core, CTR, OMAC, and ACPKM all match gost-engine.

### V5. gost-engine ground truth

- `tmp/engine/test_gost89.c` — Magma ECB/CTR/ACPKM reference values.
- The gost-engine dylib
  (`/opt/homebrew/opt/gost-engine@3.0.3/libexec/engines-3/gost.dylib`) exports
  `Gost28147_TC26ParamSetZ`; per `CLAUDE.md`, read the S-box symbol out of the
  dylib rather than hand-coding it when building a KAT.
- CLI oracle (`CLAUDE.md`): `openssl enc -engine gost -magma-ctr -K <hex> -iv
  <hex>` and `openssl dgst -engine gost -mac magma-mac` for CTR/OMAC
  cross-checks.


## Re-implementation checklist

Each step is independently testable. Steps marked "(core)" are the unchanged
28147-89 core — see the sibling guide's checklist for their sub-tests.

1. **Constants.** `BlockSize = 8`, `KeySize = 32`. (core)
2. **tc26-Z S-box.** Transcribe the eight π rows from §2 verbatim (gogost
   `s[0]`=low-nibble convention, `s[i] == RFC Pi'_i` — do **not** transpose or
   reverse the row order). If you cross-check against engine
   `Gost28147_TC26ParamSetZ`, note its array rows are stored in the *reverse*
   order (`array[0]=k8`=high nibble); gogost `s[i] == engine array[7-i]` —
   see delta **M4**. Test: each row is a permutation of `0..15`. (core, fixed)
3. **Round function `g`.** `(a+k) mod 2³²` → nibble substitution `t` →
   `rotl32(·, 11)`. Test: hand-compute one nibble + assert `rotl32` vs a
   reference. (core)
4. **32-round Feistel schedule.** `K1..K8` ×3 forward then `K8..K1` reverse for
   encrypt; inverse for decrypt. (core, `SeqEncrypt`/`SeqDecrypt`)
5. **M1 — per-word key reversal.** Reverse the 4 bytes within each of the eight
   32-bit key words before the core key schedule. Test: assert the constructed
   core subkey `X[0]` LSB equals `key[3]` (not `key[0]`).
6. **M2 — whole-block reversal.** Reverse all 8 input bytes before the core,
   reverse all 8 output bytes after. Same wrapper for Encrypt and Decrypt.
7. **Encrypt.** Wire M1+M2 around the core encrypt. Test: **V1** — assert
   `Encrypt(key, fedcba9876543210) == 4ee901e5c2d8ca3d`.
8. **Decrypt.** Same wrapper around the core decrypt. Test:
   `Decrypt(key, 4ee901e5c2d8ca3d) == fedcba9876543210` and
   `Decrypt(Encrypt(p)) == p` for random `p`.
9. **No S-box parameter.** Confirm the public Magma API takes only `(key)` —
   no S-box argument (M3).
10. **No GF reduction.** Confirm no GF(2⁸) multiply/reduction is present (M5);
    if you copied any from a Kuznyechik impl, delete it.
11. **Mode parity (separate primitives).** Once the block passes V1, validate
    CTR / OMAC / ACPKM (V2–V3) against engine CLI oracles per `CLAUDE.md`.


## Conformance & fuzz testing

The implementation is already complete in `magma/magma.go`. Correctness is
established by three complementary test layers:

1. **In-package KATs and guards** (`magma/magma_test.go`, `magma/guard_test.go`):
   - RFC 8891 Appendix A.3–A.4 single-block vector (V1).
   - GOST R 34.13-2015 §A.2.1 multi-block ECB round-trip (V2).
   - In-place `Encrypt(buf, buf)` / `Decrypt(buf, buf)` against V1.
   - Panic-contract tests: wrong key length, short src/dst.
   - 10 000-iteration random round-trip.
   - S-box permutation check.

2. **Differential parity against the gogost reference** (`../gostcrypto-compat/parity/magma/`):
   `FuzzMagmaDifferential` generates random keys + blocks and compares this
   implementation byte-for-byte against `go.stargrave.org/gogost/v7/gost341264`.
   This lives in the GPL-quarantined compat module (license boundary — it may not
   move here), but runs as part of the parity gate and **passes**.

3. **End-to-end suite interop** (TLS dialer module): the `GOST2012-MAGMA-MAGMAOMAC`
   (0xC101) end-to-end tests against a live Tarantool EE server exercise the full
   block→CTR→OMAC→ACPKM stack (strongest external signal).

**Mode parity (CTR / OMAC / ACPKM).** The block cipher itself is covered by the
Go-API parity oracle above. The CTR/OMAC/ACPKM modes built on top are anchored to
gost-engine via CLI cross-checks (`OPENSSL_CONF=... openssl enc -magma-ctr ...`)
documented in `CLAUDE.md` and exercised in `ctracpkm/` and `omac/` test suites.

### Run

```sh
CGO_ENABLED=0 go test ./magma/
( cd ../gostcrypto-compat && go test ./parity/magma/ )
```


## References

**RFCs**

- **RFC 8891** — *GOST R 34.12-2015: Block Cipher "Magma".* §1 sizes, §4.1 π
  S-box, §4.2 round function `g`/`t`/`<<<_11`, §4.3 key schedule & 32-round
  order, Appendix A test vectors.
  https://github.com/bigbes/gostcrypto/blob/master/magma/rfc/rfc8891.txt
- **RFC 5830** — *GOST 28147-89.* The legacy core Magma is built on
  (little-endian); see the sibling guide. https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc5830.txt
- **RFC 4357** — S-box parameter sets & OIDs (tc26-Z =
  `1.2.643.7.1.2.5.1.1`). https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc4357.txt
- **RFC 9189** — *GOST Cipher Suites for TLS 1.2*; §4.4 the Magma-CTR-OMAC
  suite. https://github.com/bigbes/gostcrypto/blob/master/gost28147cnt/rfc/rfc9189.txt
- **RFC 9367** — *GOST Cipher Suites for TLS 1.2 (additional).* Suite 0xC101
  `GOST2012-MAGMA-MAGMAOMAC`, GOST18 key transport, ACPKM.
  https://github.com/bigbes/gostcrypto/blob/master/kuznyechik/rfc/rfc9367.txt

**Standards**

- **GOST R 34.12-2015** — Russian Federal Standard, block ciphers Magma (64-bit)
  and Kuznyechik (128-bit). Magma is the normative source republished as
  RFC 8891.
- **GOST R 34.13-2015** — modes of operation (ECB/CTR/CBC/OMAC/MGM) over Magma.

**Source citations**

- `magma/magma.go` — the clean-room implementation (constants, `sboxTC26Z`,
  per-word key reversal M1, whole-block reversal M2, fixed tc26-Z S-box M3,
  Encrypt/Decrypt, round function `g`/`t`).
- `magma/magma_test.go` — RFC 8891 A.3–A.4 KAT (V1), GOST R 34.13-2015
  §A.2.1 multi-block ECB (V2), random round-trip, S-box permutation check.
- `magma/guard_test.go` — in-place Encrypt/Decrypt and panic-contract tests.
- `../gostcrypto-compat/parity/magma/` — differential fuzz vs the gogost
  reference (GPL-quarantined; not in this module's CI).
- `tmp/engine/gost89.c:214-238` — engine tc26-Z S-box (M4 cross-check).
- `tmp/engine/gost89.c:332-383` — engine `magmacrypt`/`magmadecrypt`
  (block reversal M2, 32-round structure).
- `tmp/engine/gost89.c:583-592` — engine `magma_key` (per-word key reversal M1).
- `tmp/engine/gost89.c:247-252` — `ACPKM_D_const`.
- `../gost28147/gost28147-cipher.md` — the 28147-89 core (deltas D1–D8).
- `TODO.md:9` — S-box row-order divergence note (hash context, not Magma).
```

