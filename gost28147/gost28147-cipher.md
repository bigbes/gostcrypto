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
  NOT what this document covers (it lives behind
  `internal/gost.MagmaEncrypt`, `gost341264`).
- S-box parameter sets and their OIDs: **RFC 4357 §2** ("Additional
  Cryptographic Algorithms for Use with GOST 28147-89…").

**Repo status: gogost-backed.** The repo currently sources every byte of
this primitive from `go.stargrave.org/gogost/v7/gost28147` (vendored at
`third_party/gogost/gost28147/`, GPL-3.0). There is no in-repo
reimplementation of the block cipher itself — `internal/gost` only wraps
gogost. (Higher modes CNT and IMIT *are* partly reimplemented in
`tls/internal/record/protection_gost.go`, but they still call gogost's
block cipher through the `GOST28147Cipher` / `SeqMACBlock` handles.) The
purpose of this document is to enable a GPL-free clean-room reimplementation
of the block core. Per `TODO.md` (the "BSD reimplementation" section), this
~200-LOC block core is the smallest and highest-priority piece to own.

**Where the repo uses it (call sites)**

- `internal/gost/exports_gost.go:84` — `GOST28147Cipher` opaque handle:
  `NewGOST28147Cipher(key, sbox)`, `.Encrypt`, `.Decrypt`, and
  `.SeqMACBlock` (the 16-round single-block step used by the record-layer
  IMIT MAC).
- `internal/gost/primitives_gost.go:124` — `GOST2814789Encrypt` /
  `GOST2814789Decrypt` (single 8-byte block, CryptoPro-A S-box). Used by
  unit tests and as the ECB step inside `KeyWrapCryptoPro`
  (`primitives_gost.go:289-292`).
- `tls/internal/record/protection_gost.go:75,191,283,332,335` — the
  record-layer GOST 28147 CNT+IMIT protector builds `GOST28147Cipher`
  instances per record key (TLS suites **0x0081**
  `GOST2001-GOST89-GOST89` and **0xFF85**
  `GOST2012-GOST8912-GOST8912`).
- `tls/internal/ke/vkogost.go:166,252` — `KeyWrapCryptoPro` wraps the
  premaster secret (ClientKeyExchange `GOST_KEY_TRANSPORT`); uses the ECB
  block step plus the IMIT MAC.
- `tls/internal/handshake/protector_gost.go:17-19` — selects the S-box:
  **CryptoPro-A** for the 2001 suite, **tc26-Z** for the 2012 suites.

**Dimensions (constants)**

| Quantity      | Value            | Source |
|---------------|------------------|--------|
| Block size    | 8 bytes (64 bit) | `third_party/gogost/gost28147/cipher.go:21` (`BlockSize = 8`) |
| Key size      | 32 bytes (256 bit) | `third_party/gogost/gost28147/cipher.go:22` (`KeySize = 32`) |
| Subkeys       | 8 × 32-bit, little-endian from key | `cipher.go:66-75` |
| Rounds (enc/dec) | 32 | `cipher.go:40-51` |
| Rounds (IMIT) | 16 | `third_party/gogost/gost28147/mac.go:22-25` |
| S-box         | 8 × 16 nibbles   | `third_party/gogost/gost28147/sbox.go:19` |
| MAC tag (IMIT) | 1–8 bytes (TLS truncates to 4) | `mac.go:42` |


## Specification

### 1. Block ↔ word packing (little-endian — this is the surprising part)

The 64-bit block is split into two 32-bit halves `N1` (low) and `N2`
(high). The bytes are read **little-endian**: byte 0 is the least
significant byte of `N1`.

```
N1 = b[0] | b[1]<<8 | b[2]<<16 | b[3]<<24      // first 4 bytes, LE
N2 = b[4] | b[5]<<8 | b[6]<<16 | b[7]<<24      // last 4 bytes, LE
```

Source: `third_party/gogost/gost28147/cipher.go:84-88` (`block2nvs`).
Engine equivalent: `tmp/engine/gost89.c:281-282`
(`n1 = in[0] | (in[1]<<8) | (in[2]<<16) | ((word32)in[3]<<24)`).

The subkeys are derived from the 256-bit key the same way — eight 32-bit
little-endian words `X[0..7]` (`cipher.go:66-75`).

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

In code (`third_party/gogost/gost28147/sbox.go:117-126`, function `k`):
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

Source: `cipher.go:104` (`c.sbox.k(n1+c.x[i]).shift11()`) and
`cipher.go:30-32` (`shift11` = cyclic 11-bit left rotate).
Engine equivalent: `tmp/engine/gost89.c:269-275` (`f()` — precomputes
`k87/k65/k43/k21` byte-pair tables, ORs them, then `x<<11 | x>>(32-11)`).

### 3. One Feistel round

```
(N1, N2) ← ( f(N1 + X[i]) XOR N2,  N1 )
```

i.e. the new `N1` is `f(N1 + X[i]) ⊕ N2`, and the new `N2` is the old `N1`.
Source: `cipher.go:104` —
`n1, n2 = c.sbox.k(n1+c.x[i]).shift11()^n2, n1`. (gogost swaps the
*variables* each round rather than swapping halves; the engine does the
same trick with named `n1`/`n2`, `gost89.c:283`.)

The per-round subkey index sequence `seq` determines which `X[i]` is used:

### 4. Encrypt schedule (32 rounds)

```
SeqEncrypt = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7,  7,6,5,4,3,2,1,0]
```

Three forward passes `X[0..7]` then one reverse pass `X[7..0]`.
Source: `cipher.go:40-45`. Matches RFC 5830 §5 (the Electronic Codebook
Mode, basic encryption step `A`): subkeys used in order K0…K7 three times, then K7…K0 once.
Engine: `gost89.c:285-319` (unrolled, same order).

### 5. Decrypt schedule (32 rounds)

```
SeqDecrypt = [0,1,2,3,4,5,6,7,  7,6,5,4,3,2,1,0,  7,6,5,4,3,2,1,0,  7,6,5,4,3,2,1,0]
```

One forward pass then three reverse passes — the exact inverse of encrypt.
Source: `cipher.go:46-51`. Engine: `gost89.c:339-373`.

### 6. Output packing (note the half-swap)

After the final round the two halves are written back, but with the halves
**swapped** relative to input order — `N2` goes to bytes 0–3, `N1` to bytes
4–7:

```
out[0..3] = LE(N2)
out[4..7] = LE(N1)
```

Source: `cipher.go:91-99` (`nvs2block` takes args `(n1, n2)` and writes
`n2` first). Engine: `gost89.c:321-328` (writes `n2` to `out[0..3]`).
This swap is what makes the 32-round Feistel network its own structural
inverse with the reversed key schedule.

### 7. The 16-round MAC (IMIT) schedule

IMIT (имитовставка / message authentication) uses a **truncated 16-round**
encryption — only the first two forward subkey passes, no reverse pass:

```
SeqMAC = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7]
```

Source: `third_party/gogost/gost28147/mac.go:22-25`. RFC 5830 §8 (the
MAC generation mode / imitovstavka) specifies exactly 16 rounds of the encryption
step, not 32 — this is **the** defining difference between the MAC core
and the cipher core. The 16-round transform is otherwise unreachable
through the public cipher API, which is why the repo exposes it as
`GOST28147Cipher.SeqMACBlock` (`internal/gost/exports_gost.go:98-107`).

The IMIT chaining (per RFC 5830 §8): CBC-MAC-style — XOR the next plaintext
block into the running state, run the 16-round transform, repeat; the tag
is the leading `s` bytes of the final state (`s ≤ 8`; TLS uses `s = 4`,
RFC 9189 §4.2). gogost's `MAC` (`mac.go:70-99`) implements this. **Note the
output-half ordering for the MAC differs from the cipher**: `mac.go:78`
writes `nvs2block(m.n2, m.n1, ...)` — see the deltas section.

### 8. S-box parameter sets (RFC 4357 §2)

An S-box is `[8][16]uint8` — eight rows of sixteen nibbles. Row `s[i]`
substitutes nibble `i` (row 0 = lowest nibble). Two are load-bearing in
this repo:

**CryptoPro-A** (`id-Gost28147-89-CryptoPro-A-ParamSet`,
OID `1.2.643.2.2.31.1`) — used for TLS suite 0x0081 record protection and
the CryptoPro key wrap when the cert is GOST R 34.10-2001.
Source: `third_party/gogost/gost28147/sbox.go:32-41`,
var `SboxIdGost2814789CryptoProAParamSet`; wrapper `SboxCryptoProA`
(`internal/gost/primitives_gost.go:42`).

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
Source: `third_party/gogost/gost28147/sbox.go:72-81`,
var `SboxIdtc26gost28147paramZ`; wrapper `SboxTC26Z`
(`internal/gost/primitives_gost.go:47`).

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

`SboxDefault = &SboxIdGost2814789CryptoProAParamSet`
(`sbox.go:113`); `GOST2814789Encrypt`/`Decrypt` use it.

**The "R34.11-94-CryptoPro" S-box** (`SboxIdGostR341194CryptoProParamSet`,
`sbox.go:93-102`) is a *third* named set. It is the substitution table the
GOST R 34.11-94 *hash* uses internally for its 28147 core (call site:
`primitives_gost.go:161`). It is a valid 28147 S-box and indexed
identically; it is mentioned here only because the task asks how the
"R34.11-94-CryptoPro" name maps to a byte table — it maps to `sbox.go:93`.
It is **not** used for TLS record protection or key wrap.


## RFC ↔ implementation deltas

This is the section a reimplementer must internalize. Every entry cites
both the RFC and the source line.

### D1. Little-endian octet packing (RFC under-specifies; LE is mandatory)

RFC 5830 defines the cipher over 64-bit values and 32-bit subkeys without
fixing an octet order. All interoperable implementations pack octets
**little-endian** (byte 0 → LSB of `N1`; key bytes 0–3 → `X[0]` LSB-first).
Source: `cipher.go:66-75` (key→subkeys) and `cipher.go:84-88` (block→halves);
engine `gost89.c:281-282`. A big-endian reading fails every vector below.

### D2. Output half-swap (cipher)

Encrypt/decrypt write the two final halves **swapped**: `N2` to the first 4
octets, `N1` to the last 4 (`cipher.go:91-99`, `gost89.c:321-328`). Omitting
the swap yields a transform that is *not* invertible by `SeqDecrypt`.

### D3. MAC vs cipher output ordering differ (destructive-looking, but intentional)

The IMIT MAC's internal block transform writes the halves in the **opposite
order** to the cipher: `mac.go:78` calls `nvs2block(m.n2, m.n1, m.prev)`
(N1 first), whereas the cipher calls `nvs2block(n1, n2, ...)` with N2 first.
Likewise `mac.go:49-51` reads the IV with the halves swapped
(`n2, n1 := block2nvs(iv)`). A reimplementer who reuses the cipher's
pack/unpack verbatim inside the MAC will produce wrong tags. The net effect
is that the MAC keeps `(N1,N2)` in "natural" order across blocks while the
cipher keeps them swapped — both are self-consistent, but they are not the
same convention.

### D4. 16-round MAC schedule is not the cipher schedule

RFC 5830 §8: IMIT is 16 rounds (`SeqMAC`, `mac.go:22-25`), the cipher is 32
(`SeqEncrypt`). Using the 32-round schedule for the MAC is a classic and
silent bug — it produces a plausible-looking 8-byte value that is wrong.
The repo deliberately surfaces the 16-round step as a distinct method
(`SeqMACBlock`, `exports_gost.go:98-107`) precisely because it is otherwise
unreachable.

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
Source: `third_party/gogost/gost28147/ctr.go:41-42` and engine
`tmp/engine/gost_crypt.c:686,693`. Also note `CLAUDE.md`: gogost's
`gost28147.CTR.XORKeyStream` over-increments on block-aligned inputs and
is not stream-safe — the repo reimplements CNT in
`tls/internal/record/protection_gost.go` (`gostCNT`).

### D7. CryptoPro key meshing threshold (consumer, IMIT over long records)

Also not block-core, but the closest gotcha: for IMIT over inputs >1024
bytes, the CryptoPro key-meshing step (RFC 4357 §2.3.2) re-keys every 1024
processed bytes by ECB-decrypting the current key against a fixed 32-byte
constant. The constant
(`primitives_gost.go:398-403`, engine `tmp/engine/gost89.c:240-251`):

```
69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
```

gogost's raw `gost28147.MAC` omits meshing; the repo adds it in
`GOST28147_IMIT` (`primitives_gost.go:424-489`). See `TODO.md:11`.

### D8. MAC `Sum` is destructive on a pending partial block

From `CLAUDE.md` ("gogost/v7 library gotchas"): `gost28147.MAC.Sum` mutates
internal `n1`/`n2` via slice aliasing when a partial block is pending —
it violates the `hash.Hash` contract. Never call `Sum` on a MAC you intend
to `Write` to again. A clean reimplementation should snapshot state in
`Sum` (finalize on a copy), matching the EVP "finalize-on-copy" semantics
described in `CLAUDE.md`.


## Test vectors

### V1. ECB single block, CryptoPro-A S-box (inline, runnable now)

Computed with this repo's `GOST2814789Encrypt` (gogost CryptoPro-A,
`SboxDefault`) and verified to round-trip via `GOST2814789Decrypt`:

```
S-box:       CryptoPro-A (1.2.643.2.2.31.1)
key  (32B):  00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1
plaintext (8B): 1020304050607080
ciphertext(8B): 2685b30ddb497d05
```

`GOST2814789Decrypt(key, 2685b30ddb497d05)` returns `1020304050607080`.
A correct from-scratch implementation that packs little-endian (D1),
applies the round function with the CryptoPro-A byte tables from §8, runs
`SeqEncrypt`, and packs the output with the N2/N1 swap (D2) MUST reproduce
`2685b30ddb497d05` exactly.

### V1b. ECB single block, tc26-Z S-box (inline, runnable now)

Same key and plaintext as V1, under the tc26 param-Z S-box (§8) instead of
CryptoPro-A — so a clean-room implementer can validate the tc26-Z table
against a fixed ciphertext, not only by round-trip. Computed with this
repo's `NewGOST28147Cipher(key, SboxTC26Z)` and verified to round-trip:

```
S-box:       tc26-Z (1.2.643.7.1.2.5.1.1)
key  (32B):  00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1
plaintext (8B): 1020304050607080
ciphertext(8B): 9810491f00ca7be0
```

The only difference from V1 is the substitution table; an implementation
that reproduces both `2685b30ddb497d05` (CryptoPro-A) and `9810491f00ca7be0`
(tc26-Z) has both §8 S-box transcriptions correct.

### V2. Repo unit tests

- `internal/gost/primitives_test.go:106-164` — CNT round-trip and IMIT
  determinism/key-sensitivity (consume the block core).
- `internal/gost/primitives_gost.go` exercised end-to-end by
  `TestTarantoolEE_Ping_GOST_Pure` (0x0081, 0xFF85) against a live
  Tarantool-EE 3.5.0 server — the strongest interop signal that the block
  core, CNT, IMIT, and key wrap all match gost-engine.

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
    determinism + key-sensitivity like
    `internal/gost/primitives_test.go:137-164`.
11. **IMIT finalize-on-copy.** Make `Sum` snapshot state and not mutate the
    running MAC (D8). Test: `Sum` then `Write` more then `Sum` again gives a
    consistent extended tag.
12. **(Mode consumers, separate primitives.)** CNT with constants
    C2=0x01010101 / C1=0x01010104 (D6); CryptoPro key meshing every 1024
    bytes with the §D7 constant. Validate against engine CLI oracles per
    `CLAUDE.md`.


## Conformance & fuzz testing

This scaffolding is for the clean-room implementer who is replacing the
gogost-backed block core. **Differential strategy:** for the plain ECB
cipher there are two byte-for-byte oracles to diff against — the raw
gogost `gost28147.NewCipher(key, gost28147.SboxDefault).Encrypt`
(`third_party/gogost/gost28147/cipher.go:60`) and this repo's thin wrapper
`internal/gost.GOST2814789Encrypt` (`internal/gost/primitives_gost.go:124`).
Both source the same gogost core, so they MUST agree with each other and
with your new impl on every input. Fuzz a random 32-byte key + 8-byte block
and require all three outputs equal; round-trip
`Decrypt(Encrypt(p)) == p` catches asymmetric bugs in the inverse schedule.
The 16-round IMIT step (`GOST28147Cipher.SeqMACBlock`,
`internal/gost/exports_gost.go:102`) and the keyed modes that have no
gogost API surface (OMAC, CTR-ACPKM, KEG, KExp15, CryptoPro KeyWrap) have
**no importable reference** — for those, diff against the gost-engine CLI
oracle (see the `oracleKuznyechikCTR`-style helper at the end of this
section, and the CLI invocations in `CLAUDE.md`).

Wire the clean-room package in under the alias `mynew` and keep the
reference imports beside it.

### KAT — pinned vectors (V1)

Seeded with the exact bytes pinned in §V1 (CryptoPro-A / `SboxDefault`):
key `00112233…dcedf0e1`, plaintext `1020304050607080`, ciphertext
`2685b30ddb497d05`.

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"encoding/hex"
	"testing"

	gostref "go.stargrave.org/gogost/v7/gost28147" // raw gogost oracle
	"go.bigb.es/tlsdialer/internal/gost"                      // local wrapper oracle
	mynew "example.com/gost28147"         // clean-room impl under test
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestGOST28147Conformance(t *testing.T) {
	cases := []struct {
		name             string
		key, in, wantOut string
	}{
		{
			name: "V1/CryptoProA",
			key:  "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1",
			in:   "1020304050607080",
			wantOut: "2685b30ddb497d05",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, in, want := mustHex(t, tc.key), mustHex(t, tc.in), mustHex(t, tc.wantOut)

			// reference A: raw gogost (CryptoPro-A == SboxDefault).
			refOut := make([]byte, gostref.BlockSize)
			gostref.NewCipher(key, gostref.SboxDefault).Encrypt(refOut, in)
			if !bytes.Equal(refOut, want) {
				t.Fatalf("gogost ref: got %x want %x", refOut, want)
			}

			// reference B: in-repo wrapper.
			if got := gost.GOST2814789Encrypt(key, in); !bytes.Equal(got, want) {
				t.Fatalf("internal/gost ref: got %x want %x", got, want)
			}

			// subject under test: clean-room impl.
			gotOut := make([]byte, mynew.BlockSize)
			mynew.NewCipher(key, mynew.SboxCryptoProA).Encrypt(gotOut, in)
			if !bytes.Equal(gotOut, want) {
				t.Fatalf("clean-room: got %x want %x", gotOut, want)
			}

			// round-trip the inverse schedule.
			back := make([]byte, mynew.BlockSize)
			mynew.NewCipher(key, mynew.SboxCryptoProA).Decrypt(back, gotOut)
			if !bytes.Equal(back, in) {
				t.Fatalf("clean-room round-trip: got %x want %x", back, in)
			}
		})
	}
}
```

### Fuzz — differential against both oracles

The corpus is seeded from the KAT inputs; the random `[]byte` is normalized
into the fixed 32-byte key + 8-byte block this primitive takes. All three
encrypt outputs must match, and the clean-room impl must round-trip.

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"testing"

	gostref "go.stargrave.org/gogost/v7/gost28147"
	"go.bigb.es/tlsdialer/internal/gost"
	mynew "example.com/gost28147"
)

func FuzzGOST28147Conformance(f *testing.F) {
	// seed from the pinned V1 vector (key||plaintext = 40 bytes).
	f.Add([]byte("\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff" +
		"\x10\x21\x32\x43\x54\x65\x76\x87\x98\xa9\xba\xcb\xdc\xed\xf0\xe1" +
		"\x10\x20\x30\x40\x50\x60\x70\x80"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// normalize into fixed-size arguments: 32-byte key, 8-byte block.
		var key [gostref.KeySize]byte
		var in [gostref.BlockSize]byte
		for i := range raw {
			if i < len(key) {
				key[i] ^= raw[i]
			} else if i < len(key)+len(in) {
				in[i-len(key)] ^= raw[i]
			}
		}

		refOut := make([]byte, gostref.BlockSize)
		gostref.NewCipher(key[:], gostref.SboxDefault).Encrypt(refOut, in[:])

		wrapOut := gost.GOST2814789Encrypt(key[:], in[:])

		gotOut := make([]byte, mynew.BlockSize)
		mynew.NewCipher(key[:], mynew.SboxCryptoProA).Encrypt(gotOut, in[:])

		if !bytes.Equal(gotOut, refOut) {
			t.Fatalf("key=%x in=%x: clean-room %x != gogost %x", key, in, gotOut, refOut)
		}
		if !bytes.Equal(wrapOut, refOut) {
			t.Fatalf("key=%x in=%x: internal/gost %x != gogost %x", key, in, wrapOut, refOut)
		}

		back := make([]byte, mynew.BlockSize)
		mynew.NewCipher(key[:], mynew.SboxCryptoProA).Decrypt(back, gotOut)
		if !bytes.Equal(back, in[:]) {
			t.Fatalf("key=%x: round-trip %x != %x", key, back, in)
		}
	})
}
```

### Oracle helper (for the no-API modes: IMIT, OMAC, CTR-ACPKM, KEG, KExp15, KeyWrap)

These have no gogost type to import, so shell out to the gost-engine CLI
from `CLAUDE.md` and diff the bytes. Example for a Kuznyechik CTR
cross-check (substitute the Magma/IMIT invocation as needed); strip
`OPENSSL_CONF` only if the engine is statically linked per
`project_tarantool_ee_harness`:

```go
//go:build gost

package yourpkg

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// oracleKuznyechikCTR returns the gost-engine ciphertext for key/iv over the
// plaintext written to a temp file. key is 32-byte hex, iv is 8-byte hex.
func oracleKuznyechikCTR(t *testing.T, keyHex, ivHex string, plain []byte) []byte {
	t.Helper()
	in := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(in, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		"/opt/homebrew/opt/openssl@3/bin/openssl", "enc", "-engine", "gost",
		"-kuznyechik-ctr", "-K", keyHex, "-iv", ivHex, "-in", in,
	)
	cmd.Env = append(os.Environ(),
		"OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("gost-engine CLI unavailable: %v", err) // skip-and-log, not fail
	}
	return out
}
```

### Run commands

```sh
go test -tags gost -run TestGOST28147Conformance ./yourpkg/
go test -tags gost -fuzz=FuzzGOST28147Conformance -fuzztime=30s ./yourpkg/
```


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

- `third_party/gogost/gost28147/cipher.go:20-126` — constants, key
  schedule, pack/unpack, round function, `SeqEncrypt`/`SeqDecrypt`,
  `Encrypt`/`Decrypt`. (gogost, GPL-3.0 — describe, do not copy.)
- `third_party/gogost/gost28147/sbox.go:19-126` — S-box type, named
  parameter sets, `k` substitution.
- `third_party/gogost/gost28147/mac.go:22-99` — `SeqMAC` (16 rounds), IMIT
  chaining, MAC output ordering.
- `third_party/gogost/gost28147/ctr.go:41-42` — CNT increment constants.
- `internal/gost/primitives_gost.go:124-139` — `GOST2814789Encrypt/Decrypt`
  wrappers; `:42,47` S-box wrappers; `:398-489` key meshing + IMIT.
- `internal/gost/exports_gost.go:84-107` — `GOST28147Cipher`,
  `SeqMACBlock`.
- `tmp/engine/gost89.c:14-19` — the "rotated 90° counterclockwise" S-box
  note (D5); `:106-130,214+` param-set byte tables; `:255-275` `kboxinit` +
  `f`; `:278-328` `gostcrypt` (32-round encrypt); `:334-373` decrypt.
- `tmp/engine/gost_crypt.c:686,693` — CNT increment constants.
- `tmp/engine/test_gost2814789.c:41-58,60+` — reference KAT table.
- `TODO.md:7-11` — S-box row-order / R34.11-94 / key-meshing divergence
  analysis.
