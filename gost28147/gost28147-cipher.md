# GOST 28147-89 block cipher (ECB, key schedule, S-boxes)

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

## What this is

GOST 28147-89 is the Soviet/Russian 64-bit-block, 256-bit-key Feistel block
cipher. This document specifies the **core block primitive only**: the key
schedule, the round function (the `t`-substitution + 11-bit cyclic shift),
the 32-round encrypt / decrypt schedule, the 16-round MAC (IMIT) schedule,
the little-endian block↔word packing, and the named S-box parameter sets.
Modes built on top of it (CNT counter stream, IMIT MAC with key meshing,
CFB used by the CryptoPro key wrap) are *consumers* of this primitive and
are documented only insofar as they need the 16-round schedule or a raw
ECB block — they are not re-specified here.

**Standards identity**

- Algorithm: GOST 28147-89 (Государственный стандарт). The cipher
  algorithms (ECB / "simple substitution", gamma/CTR, gamma-feedback/CFB,
  and IMIT/MAC) are republished as **RFC 5830**. The cipher itself is
  sometimes called "Magma" in its 2015 re-standardization (GOST R
  34.12-2015, 64-bit), but the 2015 Magma uses a *fixed* S-box and a
  *big-endian* block convention — it is a **different** primitive and is
  NOT what this document covers (it lives in `gostcrypto/magma/`).
- S-box parameter sets and their OIDs: **RFC 4357 §2** ("Additional
  Cryptographic Algorithms for Use with GOST 28147-89…").

**Repo status: clean-room implementation.** This package (`gost28147/`) is a
BSD-2-Clause, zero-dependency, pure-Go clean-room reimplementation of the
GOST 28147-89 block core. It has no gogost import and no build tags. The
differential parity tests that compare this implementation against the gogost
reference live in `../gostcrypto-compat/parity/gost28147/` (GPL-licensed,
never imported here). Tests for this package are in `gost28147/gost28147_test.go`
and `gost28147/guard_test.go`.

**Where the module uses it (call sites in `github.com/bigbes/gostcrypto`)**

- `gost28147cnt/cnt.go` — `NewCNT(c *gost28147.Cipher, iv []byte)` builds
  the GOST 28147-89 CNT counter stream; key meshing calls `gost28147.NewCipher`
  with the original S-box (read via `c.SBox()`).
- `gost28147imit/imit.go` — `IMIT()` / `SeqMACBlock()` build the 16-round IMIT
  MAC; `NewCipher` is called per MAC instance.
- `keywrap/keywrap.go` — `KeyWrapCryptoPro` and `Diversify` use the
  GOST 28147-89 ECB block step and a CFB-mode IMIT for key wrapping.
- Root facade (`exports.go`, `modes.go`, `primitives.go`) — `GOST28147Cipher`
  opaque handle (`.Encrypt`, `.Decrypt`, `.SeqMACBlock`), `GOST2814789Encrypt` /
  `GOST2814789Decrypt` single-block helpers, and the CNT/IMIT stream factories.
  The facade selects **CryptoPro-A** for GOST 2001 suites and **tc26-Z** for
  GOST 2012 suites.

**Dimensions (constants)**

| Quantity         | Value              | Source                          |
|------------------|--------------------|---------------------------------|
| Block size       | 8 bytes (64 bit)   | `gost28147.go`: `BlockSize = 8` |
| Key size         | 32 bytes (256 bit) | `gost28147.go`: `KeySize = 32`  |
| Subkeys          | 8 × 32-bit, little-endian from key | `gost28147.go:88-90`  |
| Rounds (enc/dec) | 32                 | `gost28147.go:156-159`          |
| Rounds (IMIT)    | 16                 | `gost28147imit/imit.go` (separate schedule) |
| S-box            | 8 × 16 nibbles     | `gost28147.go:36`               |
| MAC tag (IMIT)   | 1–8 bytes (TLS truncates to 4) | `gost28147imit/imit.go` |


## Specification

### 1. Block ↔ word packing (little-endian — this is the surprising part)

The 64-bit block is split into two 32-bit halves `N1` (low) and `N2`
(high). The bytes are read **little-endian**: byte 0 is the least
significant byte of `N1`.

```
N1 = b[0] | b[1]<<8 | b[2]<<16 | b[3]<<24      // first 4 bytes, LE
N2 = b[4] | b[5]<<8 | b[6]<<16 | b[7]<<24      // last 4 bytes, LE
```

Source: `gost28147/gost28147.go:103-104` (read via `binary.LittleEndian.Uint32`).
Engine equivalent: `tmp/engine/gost89.c:281-282`
(`n1 = in[0] | (in[1]<<8) | (in[2]<<16) | ((word32)in[3]<<24)`).

The subkeys are derived from the 256-bit key the same way — eight 32-bit
little-endian words `X[0..7]` (`gost28147/gost28147.go:88-90`).

> Note RFC 5830 §4 (General Statements) phrases the cipher over a 64-bit
> value and 32-bit subkeys `X(i)` without nailing down a byte order, because the original
> GOST defined the cipher over machine words, not octet strings. The
> octet→word convention is **little-endian** in every interoperable
> implementation (CryptoPro, gost-engine, gogost). Get this wrong and
> every test vector fails.

### 2. Round function `t` (the S-box substitution + shift)

Within a round, the 32-bit input `x` (already `= half + subkey mod 2^32`)
is substituted nibble-by-nibble through the eight S-boxes, then cyclically
left-rotated by 11 bits.

RFC 5830 §4 (General Statements) describes the substitution box `K` as eight nodes
`K(1)…K(8)`, each a permutation of `{0..15}`, applied to the eight 4-bit
groups of the 32-bit word; the result is rotated left by 11.

In this package (`gost28147/gost28147.go`, function `t`):
the S-box is indexed nibble `i` (bits `4i..4i+3`) through table row `s[i]`,
and the substituted nibble is written back to bit position `4i`:

```
t(x) = Σ over i=0..7 of  s[i][(x >> 4i) & 0xF]  << 4i
```

So **row `s[0]` substitutes the lowest nibble (bits 0–3); row `s[7]`
substitutes the highest nibble (bits 28–31).** Then:

```
f(x) = rotl32(t(x), 11)
```

Source: `gost28147.go:136-151` (functions `t` and `f`).
Engine equivalent: `tmp/engine/gost89.c:269-275` (`f()` — precomputes
`k87/k65/k43/k21` byte-pair tables, ORs them, then `x<<11 | x>>(32-11)`).

### 3. One Feistel round

```
(N1, N2) ← ( f(N1 + X[i]) XOR N2,  N1 )
```

i.e. the new `N1` is `f(N1 + X[i]) ⊕ N2`, and the new `N2` is the old `N1`.
Source: `gost28147.go:158` —
`n1, n2 = c.f(n1+c.x[seq[i]])^n2, n1`. (The engine does the
same trick with named `n1`/`n2`, `gost89.c:283`.)

The per-round subkey index sequence `seq` determines which `X[i]` is used:

### 4. Encrypt schedule (32 rounds)

```
SeqEncrypt = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7,  7,6,5,4,3,2,1,0]
```

Three forward passes `X[0..7]` then one reverse pass `X[7..0]`.
Source: `gost28147.go:64-67` (`seqEncrypt`). Matches RFC 5830 §5 (the Electronic Codebook
Mode, basic encryption step `A`): subkeys used in order K0…K7 three times, then K7…K0 once.
Engine: `gost89.c:285-319` (unrolled, same order).

### 5. Decrypt schedule (32 rounds)

```
SeqDecrypt = [0,1,2,3,4,5,6,7,  7,6,5,4,3,2,1,0,  7,6,5,4,3,2,1,0,  7,6,5,4,3,2,1,0]
```

One forward pass then three reverse passes — the exact inverse of encrypt.
Source: `gost28147.go:68-71` (`seqDecrypt`). Engine: `gost89.c:339-373`.

### 6. Output packing (note the half-swap)

After the final round the two halves are written back, but with the halves
**swapped** relative to input order — `N2` goes to bytes 0–3, `N1` to bytes
4–7:

```
out[0..3] = LE(N2)
out[4..7] = LE(N1)
```

Source: `gost28147.go:107-108` (writes `n2` to `dst[0:4]`, `n1` to `dst[4:8]`).
Engine: `gost89.c:321-328` (writes `n2` to `out[0..3]`).
This swap is what makes the 32-round Feistel network its own structural
inverse with the reversed key schedule.

### 7. The 16-round MAC (IMIT) schedule

IMIT (имитовставка / message authentication) uses a **truncated 16-round**
encryption — only the first two forward subkey passes, no reverse pass:

```
SeqMAC = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7]
```

Source: RFC 5830 §8 (the MAC generation mode / imitovstavka) specifies exactly
16 rounds of the encryption step, not 32 — this is **the** defining difference
between the MAC core and the cipher core. The 16-round transform is implemented
in `gost28147imit/imit.go` (using a local `macBlock` function with its own
`[16]int` schedule) and exposed to callers through the root facade as
`GOST28147Cipher.SeqMACBlock` (`exports.go:138`).

The IMIT chaining (per RFC 5830 §8): CBC-MAC-style — XOR the next plaintext
block into the running state, run the 16-round transform, repeat; the tag
is the leading `s` bytes of the final state (`s ≤ 8`; TLS uses `s = 4`,
RFC 9189 §4.2). **Note the output-half ordering for the MAC differs from
the cipher** — see the deltas section (D3).

### 8. S-box parameter sets (RFC 4357 §2)

An S-box is `[8][16]uint8` — eight rows of sixteen nibbles. Row `s[i]`
substitutes nibble `i` (row 0 = lowest nibble). Two are load-bearing in
this repo:

**CryptoPro-A** (`id-Gost28147-89-CryptoPro-A-ParamSet`,
OID `1.2.643.2.2.31.1`) — used for TLS suite 0x0081 record protection and
the CryptoPro key wrap when the cert is GOST R 34.10-2001.
Source: `gost28147.go:39-48` (`SboxCryptoProA`); RFC 4357 §2.3.

```
s[0] = {9,6,3,2,8,11,1,7,10,4,14,15,12,0,13,5}
s[1] = {3,7,14,9,8,10,15,0,5,2,6,12,11,4,13,1}
s[2] = {14,4,6,2,11,3,13,8,12,15,5,10,0,7,1,9}
s[3] = {14,7,10,12,13,1,3,9,0,2,11,4,15,8,5,6}
s[4] = {11,5,1,9,8,13,15,0,14,4,2,3,12,7,10,6}
s[5] = {3,10,13,12,1,2,0,11,7,5,9,4,8,15,14,6}
s[6] = {1,13,2,9,7,10,6,0,8,12,4,5,15,3,11,14}
s[7] = {11,10,15,5,0,12,14,8,6,2,3,9,1,7,13,4}
```

**tc26-Z** (`id-tc26-gost-28147-param-Z`, OID `1.2.643.7.1.2.5.1.1`) — used
for the 2012 TLS suites (0xFF85, 0xC102) record protection and the
CryptoPro key wrap when the cert is GOST R 34.10-2012.
Source: `gost28147.go:51-60` (`SboxTC26Z`).

```
s[0] = {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1}
s[1] = {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15}
s[2] = {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0}
s[3] = {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11}
s[4] = {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12}
s[5] = {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0}
s[6] = {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7}
s[7] = {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2}
```

This module exports only `SboxCryptoProA` and `SboxTC26Z`. The root facade
(`exports.go`) selects the appropriate S-box per suite.

**The "R34.11-94-CryptoPro" S-box** is a *third* named set used internally by
the GOST R 34.11-94 hash. It is not exported from this package and is not used
for TLS record protection or key wrap.


## RFC ↔ implementation deltas

This is the section a reimplementer must internalize. Every entry cites
both the RFC and the source line.

### D1. Little-endian octet packing (RFC under-specifies; LE is mandatory)

RFC 5830 defines the cipher over 64-bit values and 32-bit subkeys without
fixing an octet order. All interoperable implementations pack octets
**little-endian** (byte 0 → LSB of `N1`; key bytes 0–3 → `X[0]` LSB-first).
Source: `gost28147.go:88-90` (key→subkeys) and `gost28147.go:103-104`
(block→halves); engine `gost89.c:281-282`. A big-endian reading fails every
vector below.

### D2. Output half-swap (cipher)

Encrypt/decrypt write the two final halves **swapped**: `N2` to the first 4
octets, `N1` to the last 4 (`gost28147.go:107-108`, `gost89.c:321-328`). Omitting
the swap yields a transform that is *not* invertible by `SeqDecrypt`.

### D3. MAC vs cipher output ordering differ (destructive-looking, but intentional)

The IMIT MAC's internal block transform writes the halves in the **opposite
order** to the cipher: the MAC keeps `(N1,N2)` in "natural" (non-swapped) order
across blocks while the cipher writes N2 first. A reimplementer who reuses the
cipher's pack/unpack verbatim inside the MAC will produce wrong tags. Both
conventions are self-consistent; see `gost28147imit/imit.go` for the MAC's
block step.

### D4. 16-round MAC schedule is not the cipher schedule

RFC 5830 §8: IMIT is 16 rounds (`SeqMAC`), the cipher is 32 (`SeqEncrypt`).
Using the 32-round schedule for the MAC is a classic and silent bug — it
produces a plausible-looking 8-byte value that is wrong. The module surfaces
the 16-round step through the root facade as `GOST28147Cipher.SeqMACBlock`
(`exports.go:138`) precisely because it is otherwise unreachable via the
cipher's public API.

### D5. S-box row order: gogost vs the RFC 4357 *textbook* layout

This is the divergence flagged in `TODO.md`. Two distinct facts:

1. **gogost and gost-engine agree byte-for-byte** for the 28147 *cipher*.
   gogost row `s[0]` (low nibble) holds the same nibbles as engine's
   `k1`/`k21` (low byte), and `s[7]` ↔ `k8`. Verify on CryptoPro-A:
   gogost `s[0] = {9,6,3,2,…}` (`sbox.go:33`) equals engine
   `Gost28147_CryptoProParamSetA` row 1 `{0x9,0x6,0x3,0x2,…}`
   (`tmp/engine/gost89.c:128-129`); gogost `s[7] = {11,10,15,5,…}`
   (`sbox.go:40`) equals engine row 8 `{0xB,0xA,0xF,0x5,…}`
   (`gost89.c:107-108`). Same data, same nibble-to-row mapping. **No
   transposition exists between gogost and engine for this primitive.**

2. **Both differ from the RFC/textbook presentation** by a "90° rotation."
   The engine itself documents this: *"our implementation of gost 28147-89
   algorithm uses S-box matrix rotated 90 degrees counterclockwise, relative
   to examples given in RFC"* — `tmp/engine/gost89.c:14-19`. The RFC/GOST
   prints each S-box node as a column; code stores it as a row. So when you
   transcribe a table out of RFC 4357 or a textbook, you may need to
   transpose it before it matches the byte tables above. **If you copy the
   byte tables from §8 of this document verbatim, you are already in the
   gogost/engine row convention and need no transposition.**

3. The S-box *row-reversal* in `TODO.md:9` ("gogost stores S-box rows in
   reverse order and applies a compensating `blockReverse`") refers to the
   **GOST R 34.11-94 hash's** use of 28147, not the plain ECB cipher. For
   the ECB/CNT/IMIT paths this repo uses, the cipher output matches engine
   bit-for-bit and no compensating reversal is involved. Do not let the
   hash divergence make you "fix" the cipher S-boxes.

### D6. CNT (counter) mode increment constants (consumer, for context)

Not part of the block core, but a reimplementer of the CNT mode must know:
the two 32-bit counter halves are incremented by **C2 = 0x01010101** (low
half) and **C1 = 0x01010104** (high half) per gamma block.
Source: engine `tmp/engine/gost_crypt.c:686,693`. Also note `CLAUDE.md`:
gogost's `gost28147.CTR.XORKeyStream` over-increments on block-aligned inputs
and is not stream-safe — this module reimplements CNT clean-room in
`gost28147cnt/cnt.go`.

### D7. CryptoPro key meshing threshold (consumer, IMIT over long records)

Also not block-core, but the closest gotcha: for IMIT over inputs >1024
bytes, the CryptoPro key-meshing step (RFC 4357 §2.3.2) re-keys every 1024
processed bytes by ECB-decrypting the current key against a fixed 32-byte
constant. The constant (engine `tmp/engine/gost89.c:240-251`):

```
69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
```

Meshing is implemented in `gost28147imit/imit.go` (the `meshKey` function).
See `TODO.md` for details on the meshing semantics.

### D8. MAC `Sum` is destructive on a pending partial block

From `CLAUDE.md` ("GOST IMIT MAC — EVP streaming semantics"): the gogost
`gost28147.MAC.Sum` mutates internal state via slice aliasing when a partial
block is pending — it violates the `hash.Hash` contract. Never call `Sum` on a
MAC you intend to `Write` to again. The clean-room `gost28147imit` implementation
snapshots state in `Finalize()` (finalize on a copy), matching EVP semantics
described in `CLAUDE.md`.


## Test vectors

### V1. ECB single block, CryptoPro-A S-box (inline, runnable now)

Computed with `gost28147.NewCipher(key, SboxCryptoProA).Encrypt` and verified
to round-trip via `Decrypt`; also cross-checked against gost-engine 3.0.3:

```
S-box:       CryptoPro-A (1.2.643.2.2.31.1)
key  (32B):  00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1
plaintext (8B): 1020304050607080
ciphertext(8B): 2685b30ddb497d05
```

`NewCipher(key, SboxCryptoProA).Decrypt(dst, ciphertext)` returns `1020304050607080`.
A correct from-scratch implementation that packs little-endian (D1),
applies the round function with the CryptoPro-A byte tables from §8, runs
`SeqEncrypt`, and packs the output with the N2/N1 swap (D2) MUST reproduce
`2685b30ddb497d05` exactly.

### V1b. ECB single block, tc26-Z S-box (inline, runnable now)

Same key and plaintext as V1, under the tc26 param-Z S-box (§8) instead of
CryptoPro-A — so an implementer can validate the tc26-Z table against a fixed
ciphertext, not only by round-trip. Computed with `gost28147.NewCipher(key,
SboxTC26Z).Encrypt` and verified to round-trip:

```
S-box:       tc26-Z (1.2.643.7.1.2.5.1.1)
key  (32B):  00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1
plaintext (8B): 1020304050607080
ciphertext(8B): 9810491f00ca7be0
```

The only difference from V1 is the substitution table; an implementation
that reproduces both `2685b30ddb497d05` (CryptoPro-A) and `9810491f00ca7be0`
(tc26-Z) has both §8 S-box transcriptions correct.

### V2. Module unit tests

- `gost28147/gost28147_test.go` — ECB KATs (CryptoPro-A and TC26-Z, 6
  engine-derived vectors), round-trip over 256 inputs per S-box, S-box
  permutation check, and SBox() accessor test.
- `gost28147/guard_test.go` — compile-time `cipher.Block` assertion, panic
  guards (bad key length, short src/dst), and in-place Encrypt/Decrypt test.
- Differential parity tests against gogost live in
  `../gostcrypto-compat/parity/gost28147/` (GPL module, never imported here).

### V3. gost-engine reference KATs

- `tmp/engine/test_gost2814789.c:60+` — table-driven ECB/CFB/CNT/IMIT
  vectors. The structure is
  `{ullLen, bIn(plaintext), szParamSet(S-box), szDerive, bRawKey(key),
  gMode, bIV, bOut(expected)}` (`test_gost2814789.c:41-58`). The
  CryptoPro-A ECB block at `test_gost2814789.c:131+` is a good cross-check
  once you extract the derived key. **Caveat:** the first few rows
  (`test_gost2814789.c:64-126`, `szParamSet =
  id-GostR3410-94-TestParamSet`) are GOST R 34.11-94 *hash* internal
  vectors, not direct ECB-with-this-key KATs — do not feed `bRawKey` as a
  plain ECB key there.
- Ground truth at runtime: the gost-engine dylib
  (`/opt/homebrew/opt/gost-engine@3.0.3/libexec/engines-3/gost.dylib`)
  exports the raw S-box symbols (`Gost28147_TC26ParamSetZ` et al.). Per
  `CLAUDE.md`, read the S-box out of the dylib rather than hand-coding it
  when building a KAT.


## Re-implementation checklist

Each step is independently testable against a vector.

1. **Constants.** Define `BlockSize = 8`, `KeySize = 32`. Test: trivial.
2. **Little-endian pack/unpack.** Implement `block2nvs` (read 8 octets →
   `N1`(low 4 LE), `N2`(high 4 LE)) and `nvs2block` that writes
   `(first, second)` halves LE. Test: round-trip random 8-byte blocks
   through pack→unpack. (Watch the arg order so you can reuse it for both
   the cipher's swapped and the MAC's natural ordering.)
3. **Key schedule.** Split the 32-byte key into eight LE 32-bit subkeys
   `X[0..7]`. Test: `X[0]` LSB == `key[0]`.
4. **S-box tables.** Transcribe CryptoPro-A and tc26-Z from §8 verbatim
   (already in gogost/engine row convention — do NOT transpose). Test:
   each row is a permutation of `0..15`.
5. **Round function `f`.** `t(x) = Σ s[i][(x>>4i)&0xF]<<4i`; then
   `f(x) = rotl32(t(x), 11)`. Test: pick a known `x`, hand-compute one
   nibble substitution, assert; assert `rotl32` against a reference.
6. **Feistel round + `xcrypt(seq)`.** `(N1,N2) ← (f(N1+X[seq])⊕N2, N1)`,
   looped over the schedule. Keep additions mod 2³².
7. **Encrypt.** `block2nvs` → `xcrypt(SeqEncrypt)` → `nvs2block` with the
   **N2,N1 swap** (D2). Test: **V1** — assert
   `Encrypt(key, 1020304050607080) == 2685b30ddb497d05`.
8. **Decrypt.** Same with `SeqDecrypt`. Test: `Decrypt(Encrypt(p)) == p`
   for random `p`; and `Decrypt(key, 2685b30ddb497d05) ==
   1020304050607080`.
9. **tc26-Z parity.** Repeat steps 7–8 with the tc26-Z S-box; cross-check
   against gost-engine (`openssl enc -engine gost` or the dylib symbol).
10. **16-round MAC step.** Implement `SeqMAC` (`[0..7,0..7]`) and the IMIT
    block step using the **natural** half ordering (D3): XOR plaintext into
    state, run `xcrypt(SeqMAC)`, pack with the MAC ordering. Test:
    determinism + key-sensitivity as in `gost28147imit/imit_test.go`.
11. **IMIT finalize-on-copy.** Make `Sum` snapshot state and not mutate the
    running MAC (D8). Test: `Sum` then `Write` more then `Sum` again gives a
    consistent extended tag.
12. **(Mode consumers, separate primitives.)** CNT with constants
    C2=0x01010101 / C1=0x01010104 (D6); CryptoPro key meshing every 1024
    bytes with the §D7 constant. Validate against engine CLI oracles per
    `CLAUDE.md`.


## Conformance & fuzz testing

The clean-room implementation is complete and lives in this package. The
differential parity tests against the gogost reference live in
`../gostcrypto-compat/parity/gost28147/` (GPL module, never imported here).

**Differential strategy:** for the plain ECB cipher the oracle is
`gostcrypto-compat/parity/gost28147/gost28147_parity_test.go`
(`FuzzDiffGost28147`), which diffs this package's `Encrypt`/`Decrypt` against
gogost's `SboxDefault` (CryptoPro-A) byte-for-byte. Run it with:

```sh
( cd ../gostcrypto-compat && go test -fuzz=FuzzDiffGost28147 -fuzztime=30s ./parity/gost28147/ )
```

For modes that have no gogost API (OMAC, CTR-ACPKM, KEG, KExp15, CryptoPro
KeyWrap), diff against the gost-engine CLI oracle as described in `CLAUDE.md`.

In-package tests (`gost28147/gost28147_test.go`, `guard_test.go`) are run with:

```sh
CGO_ENABLED=0 go test ./gost28147/
```

No `//go:build` tags are required; no gogost or monorepo imports are allowed
in this module.



## References

**RFCs**

- RFC 5830 — *GOST 28147-89: Encryption, Decryption, and Message
  Authentication Code (MAC) Algorithms.* §4 general statements /
  substitution box K, §5 ECB simple substitution (32-round schedule),
  §8 MAC generation (16-round IMIT).
  https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc5830.txt
- RFC 4357 — *Additional Cryptographic Algorithms for Use with GOST
  28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94
  Algorithms.* §2 S-box parameter sets and OIDs; §2.3.2 CryptoPro key
  meshing; §6.3/§6.5 CryptoPro key wrap.
  https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc4357.txt
- RFC 9189 — *GOST Cipher Suites for TLS 1.2.* §4.1 GOST_KEY_TRANSPORT,
  §4.2 IMIT-4 MAC truncation. https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc9189.txt
- RFC 5831 — *GOST R 34.11-94 Hash Function* (context for the
  R34.11-94-CryptoPro S-box).

**Standards**

- GOST 28147-89 — Russian Federal Standard, block cipher (the normative
  source republished as RFC 5830).
- GOST R 34.12-2015 / GOST R 34.13-2015 — the 2015 re-standardization
  ("Magma"); a **different** primitive (fixed S-box, big-endian) — not this
  document.

**Key source citations**

- `gost28147/gost28147.go` — this package: constants, key schedule,
  `SboxCryptoProA`, `SboxTC26Z`, round function (`t`, `f`), `xcrypt`,
  `Encrypt`/`Decrypt`, `BlockSize()`, `SBox()`.
- `gost28147imit/imit.go` — 16-round IMIT MAC (separate schedule, separate
  output-half convention).
- `gost28147cnt/cnt.go` — CNT counter stream (C1/C2 constants, key meshing).
- `keywrap/keywrap.go` — CryptoPro key wrap (CFB-mode IMIT, `Diversify`).
- `exports.go` — root facade: `GOST28147Cipher`, `SeqMACBlock`, `GOST2814789Encrypt/Decrypt`.
- `tmp/engine/gost89.c:14-19` — the "rotated 90° counterclockwise" S-box
  note (D5); `:106-130,214+` param-set byte tables; `:255-275` `kboxinit` +
  `f`; `:278-328` `gostcrypt` (32-round encrypt); `:334-373` decrypt.
- `tmp/engine/gost_crypt.c:686,693` — CNT increment constants.
- `tmp/engine/test_gost2814789.c:41-58,60+` — reference KAT table.
- `TODO.md` — S-box row-order / R34.11-94 / key-meshing divergence analysis.
