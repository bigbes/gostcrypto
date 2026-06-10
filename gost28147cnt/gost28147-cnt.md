# GOST 28147-89 CNT (counter/gamma) stream mode

GOST 28147-89 CNT is the *gammirovaniye* (counter / gamma) stream mode of
the GOST 28147-89 64-bit block cipher. A keystream ("gamma") is produced by
ECB-encrypting a counter that is advanced by two fixed additive constants
between blocks; the gamma is XORed with the plaintext. Encryption and
decryption are the same operation.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

- **Standard identity:** GOST 28147-89, gamma (counter) mode of operation.
  Re-published as **RFC 5830 §6** ("Counter Mode" / *gammirovaniye*). The
  CryptoPro key-meshing extension used in TLS comes from **RFC 4357 §2.3.2**.
  The TLS suites are specified by **RFC 9189 §4** and
  draft-smyshlyaev-tls12-gost-suites.
- **Block size:** 8 bytes. **Key size:** 32 bytes. **IV (synchro/"S")
  size:** 8 bytes (one block). **Output:** same length as input (stream).
- **MAC pairing:** in TLS this cipher is always paired with GOST 28147-89
  IMIT (documented separately); the record-layer Seal is
  `CNT.encrypt(plaintext || IMIT)`.

## Where this module uses it

This package (`github.com/bigbes/gostcrypto/gost28147cnt`) is a standalone
clean-room module — it does **not** import gogost or any GPL code.

- **Facade entry point:** `modes.go` in the root `gostcrypto` package exposes
  `NewGOST28147_CNT(key, iv []byte) (cipher.Stream, error)` which constructs
  a CNT instance using `gost28147.SboxCryptoProA`.
- **TLS suites** (in the sibling `github.com/bigbes/gostls` module):
  - `0x0081` GOST2001-GOST89-GOST89 — CryptoPro-A S-box
  - `0xFF85` GOST2012-GOST8912-GOST8912 — tc26-Z S-box
  - `0xC102` IANA alias of `0xFF85`
- **Record-layer streaming:** `gostls` constructs one `*CNT` per TLS
  connection and calls `XORKeyStream` on successive records — the whole point
  of this package is that partial-block gamma is carried correctly across calls,
  which `gogost`'s `gost28147.CTR` cannot do (see deltas below).

`statusKind` for this primitive is **clean-room**: the counter/gamma logic is
implemented from scratch in `cnt.go` without consulting gogost source. The only
dependency is the sibling `gost28147` block-cipher package.

## Specification

### Block cipher (the ECB transform used as the gamma generator)

CNT never uses the cipher in any chained mode — it only needs single-block
ECB encryption of the counter. The 64-bit block is split into two 32-bit
halves, processed for 32 rounds with an 8x32-bit key schedule and eight
4-bit S-boxes, with an 11-bit cyclic left shift each round. Per RFC 5830 §5
and the de-facto reference at `third_party/gogost/gost28147/cipher.go`:

- Key → eight little-endian `uint32` subkeys `x[0..7]`
  (`cipher.go:66-75`).
- Round function `f(a) = shift11( S(a) )` where `S` substitutes each of the
  eight 4-bit nibbles through its S-box column and `shift11` is an 11-bit
  cyclic left shift (`cipher.go:30-32`, `sbox.go:117-126`).
- One round: `(n1, n2) = ( f(n1 + x[i]) XOR n2 , n1 )` (`cipher.go:102-107`).
- The 32 round-index sequence for **encryption** is
  `0..7, 0..7, 0..7, 7..0` (`SeqEncrypt`, `cipher.go:40-45`).
- Block↔halves conversion is **little-endian**, and the two halves are
  emitted **n2 first, then n1** (`block2nvs`/`nvs2block`,
  `cipher.go:84-100`). This byte-order detail matters for the counter
  arithmetic below.

This block transform (call it `E_K(block)->block`) is the only thing CNT
borrows from the cipher core. A reimplementer can treat it as a black box:
`E_K` maps an 8-byte input to an 8-byte output under a 32-byte key and a
chosen S-box.

### CNT keystream algorithm (RFC 5830 §6)

RFC 5830 §6.1 specifies the gamma generation. Quoting the normative steps
(consolidated from the WebFetch of RFC 5830 §6.1):

> "The initialisation vector S = (S1, S2, ..., S64)" is loaded into
> registers N1 and N2, then "encrypted in the electronic codebook mode in
> accordance with the requirements from section 5.1." The result
> A(S) = (Y0, Z0) is transferred to N3 and N4.
>
> "The filling of register N4 is added modulo (2^32-1) ... to the 32-bit
> constant C1"; "the filling of register N3 is added modulo 2^32 ... with
> the 32-bit constant C2."

Per RFC 5830 Appendix A, the constants are:

- **C1 = 0x01010104** (applied to the *upper* half, modulo 2^32 − 1).
- **C2 = 0x01010101** (applied to the *lower* half, modulo 2^32).

Concrete algorithm (matches `gost_cnt_next` and `gostCNT.nextGamma`):

1. **Init.** Take the 8-byte IV (synchro `S`). Compute
   `iv0 = E_K(IV)`. This encrypted value is the initial counter state.
   (RFC: "encrypted in ECB ... transferred to N3 and N4.")
2. **Per gamma block** (each block produces 8 keystream bytes):
   - If this is the very first block, the working counter `buf1` is `iv0`
     (the encrypted IV). For every subsequent block, `buf1` is the
     *current* counter state carried over from the previous step.
   - **Lower half** `g = LE_u32(buf1[0:4])`; `g = (g + C2) mod 2^32`;
     write back little-endian to `buf1[0:4]`.
   - **Upper half** `h = LE_u32(buf1[4:8])`; `h = (h + C1) mod (2^32 - 1)`;
     write back little-endian to `buf1[4:8]`. The mod-(2^32−1) reduction is
     done as a 32-bit add with end-around carry: `old=h; h+=C1; if old>h: h++`.
   - Store `buf1` back as the new counter state (`iv`).
   - **Gamma block** `G = E_K(buf1)`.
3. **XOR** each byte of `G` with the corresponding plaintext byte. Leftover
   gamma bytes (when input is not a multiple of 8) are retained for the next
   call (streaming).

Decryption is identical: the same `G` is XORed with ciphertext (RFC 5830 §6.2).

### CryptoPro key meshing (RFC 4357 §2.3.2) — TLS-mandatory

In the TLS GOST suites the CNT state additionally performs **CryptoPro key
meshing** every 1024 bytes of keystream, per RFC 4357 §2.3.2. Without it,
long records produce a wrong keystream after the first 1024 bytes.

A processed-byte counter `count` starts at 0 and increments by 8 per gamma
block (`count = count mod 1024 + 8`). When `count == 1024`, **before**
generating the next block:

1. Derive a new key: ECB-**decrypt** the 32-byte constant
   `CryptoProKeyMeshingKey` (below) under the *current* key, four 8-byte
   blocks, producing the new 32-byte key.
2. Re-key the cipher with that new key.
3. Re-encrypt the current IV under the new key:
   `iv = E_{newK}(iv)`, and use that as the counter for the next block
   (count is **not** reset to 0).

`CryptoProKeyMeshingKey` (32 bytes,
`tmp/engine/gost89.c:240-245`,
`protection_gost.go:142-147`):

```
69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
```

### S-box selection (param set)

The CNT mode itself is S-box-agnostic; the S-box is a parameter of `E_K`.
TLS picks it from the suite:

- `0x0081` (GOST2001): **CryptoPro-A** S-box (`Gost28147_CryptoProParamSetA`
  / gogost `SboxIdGost2814789CryptoProAParamSet`).
- `0xFF85` / `0xC102` (GOST2012): **tc26-Z** S-box
  (`Gost28147_TC26ParamSetZ` / gogost `SboxIdtc26gost28147paramZ`).

Both S-boxes are inlined below in **engine row order**: row 0 is the box
for the *lowest* nibble of the input (nibble `i` selects from `S[i]`). This
is the order a reimplementer must apply if reading the bytes out of the
gost-engine dylib or `gost89.c` (see the S-box row-order delta D5; gogost's
in-memory tables are the eight rows reversed).

**tc26-Z** (`Gost28147_TC26ParamSetZ`, used by `0xFF85` / `0xC102`), as
gost-engine stores it (`tmp/engine/gost89.c:214-238`):

```
S0: 1 7 e d 0 5 8 3 4 f a 6 9 c b 2
S1: 8 e 2 5 6 9 1 c f 4 b 0 d a 3 7
S2: 5 d f 6 9 2 c a b 7 8 1 4 3 e 0
S3: 7 f 5 a 8 1 6 d 0 9 3 e b 4 2 c
S4: c 8 2 1 d 4 f 6 7 0 a 5 3 e 9 b
S5: b 3 5 8 2 f a d e 1 7 4 c 9 6 0
S6: 6 8 2 3 9 a 5 c 1 e 4 7 b d 0 f
S7: c 4 6 2 a 5 b 9 e 8 d 7 0 3 f 1
```

**CryptoPro-A** (`Gost28147_CryptoProParamSetA`, used by `0x0081`; also the
gost-engine `SboxDefault` and so the S-box behind the bare `gost89-cnt` CLI
name), as gost-engine stores it (`tmp/engine/gost89.c:106-130`, same engine
row order):

```
S0: b a f 5 0 c e 8 6 2 3 9 1 7 d 4
S1: 1 d 2 9 7 a 6 0 8 c 4 5 f 3 b e
S2: 3 a d c 1 2 0 b 7 5 9 4 8 f e 6
S3: b 5 1 9 8 d f 0 e 4 2 3 c 7 a 6
S4: e 7 a c d 1 3 9 0 2 b 4 f 8 5 6
S5: e 4 6 2 b 3 d 8 c f 5 a 0 7 1 9
S6: 3 7 e 9 8 a f 0 5 2 6 c b 4 d 1
S7: 9 6 3 2 8 b 1 7 a 4 e f c 0 d 5
```

(Suite → S-box: `0x0081` → CryptoPro-A; `0xFF85` / `0xC102` → tc26-Z.
The bare gost-engine `gost89` / `gost89-cnt` default is CryptoPro-A
(`SboxDefault`); the tc26-Z variant is the `gost89-cnt-12` CLI name.)

## RFC ↔ implementation deltas

This is the section a reimplementer must get exactly right. Each item cites
both the RFC and the source line(s).

### D1. Little-endian everywhere, halves emitted high-half-first

GOST 28147 is little-endian in two surprising places:

- Key bytes and block bytes load as little-endian `uint32`
  (`cipher.go:67`, `block2nvs` `cipher.go:84-87`).
- When writing a block back, the **upper** half `n2` goes to bytes `[0:4]`
  and the **lower** half `n1` to bytes `[4:8]` (`nvs2block` `cipher.go:91-99`).

Consequence for the counter: the C2-incremented half lives in IV bytes
`[0:4]` and the C1-incremented half in bytes `[4:8]`. The engine and the
in-repo `gostCNT` add C2 to `LE_u32(buf1[0:4])` and C1 to
`LE_u32(buf1[4:8])` (`gost_crypt.c:685-699`, `protection_gost.go:95-110`).
RFC 5830 describes the halves as N3/N4 abstractly; the byte mapping is
implementation lore, not spelled out in the RFC. **Do not** byte-swap or
treat the counter as one 64-bit big-endian integer.

### D2. mod (2^32 − 1) is an end-around-carry add, and 0 is never normalised

RFC 5830 §6.1 says the upper half is added "modulo (2^32-1)". Both the
engine and `gostCNT` implement this as `h += C1; if (old > h) h++` — i.e. a
32-bit wraparound add plus one if it overflowed (`gost_crypt.c:692-695`,
`protection_gost.go:103-106`). The lower half uses plain mod 2^32
(`g += C2`, no carry fix-up) (`gost_crypt.c:686`, `protection_gost.go:96`).
Note this never special-cases the all-ones value, matching the engine
exactly. gogost's `CTR` does the same end-around carry but on the **whole**
counter, differently — see D4.

### D3. The first gamma block uses E_K(IV); later blocks do NOT re-encrypt the IV before incrementing

Per RFC 5830 §6.1, the IV is ECB-encrypted **once** to seed the counter; the
seeded value is then incremented and the incremented value re-encrypted to
form each gamma block. The trap is the "first block" branch:

- `count == 0`: `buf1 = E_K(iv)` (`gost_crypt.c:680-681`,
  `protection_gost.go:90-91`).
- `count != 0`: `buf1 = iv` (the carried counter) — **no** re-encryption of
  the IV before applying C1/C2 (`gost_crypt.c:682-684`,
  `protection_gost.go:92-94`).

Then in both branches: apply C1/C2, store back to `iv`, and set the gamma
block `G = E_K(buf1)` (`gost_crypt.c:701`, `protection_gost.go:112`).
Getting this branch wrong (e.g. re-encrypting on every block, or encrypting
the IV zero times) yields a keystream that is wrong from block 1.

### D4. gogost `gost28147.CTR.XORKeyStream` is UNUSABLE for streaming TLS

`third_party/gogost/gost28147/ctr.go` is a valid one-shot CTR but cannot be
called incrementally across TLS records. Two concrete bugs
(also flagged in `CLAUDE.md` "gogost/v7 library gotchas"):

1. **Over-increments the counter on block-aligned input.** The increment
   happens at the *top* of `MainLoop` (`ctr.go:41-45`) before the
   break check at `ctr.go:48-51`. When `len(src)` is an exact multiple of
   8, the loop advances the counter one extra time past the last consumed
   block, so the next call starts from the wrong counter value. (It also
   applies the carry to the whole `n2` half via `c.n2 >= 1<<32-1`
   (`ctr.go:43-44`), which is the lower-half-first arrangement specific to
   gogost's `block2nvs` and differs from the engine's per-half mapping in D1.)
2. **Discards partial-block gamma across calls.** `XORKeyStream` consumes a
   freshly generated `block` and never stores the unused tail
   (`ctr.go:46-53`). A second call regenerates from scratch, so a record
   whose length is not a multiple of 8 corrupts the next record's
   keystream.

Additionally gogost seeds in its constructor by pre-encrypting the IV
*inside* `NewCTR` (`ctr.go:28-30`) and then increments on the first loop
iteration, which is a different decomposition from the engine's
`count==0 → E_K(iv)` branch — equivalent for a single call, but not
composable for streaming. Therefore the TLS record layer **must** use the
in-repo `gostCNT`, which mirrors the engine's `gost_cnt_next` byte-for-byte
and keeps `num`/`count`/`iv` state across calls
(`protection_gost.go:47-130`). The constants are the same:
`C2 = 0x01010101`, `C1 = 0x01010104` (`protection_gost.go:96,103`;
`ctr.go:41-42`; `gost_crypt.c:686,693`).

### D5. S-box row order is reversed between gogost and gost-engine

gogost stores each S-box with **row 0 = the box for the high nibble** and
applies a compensating reversal inside its substitution. gost-engine stores
**row 0 = the box for the low nibble** (`tmp/engine/gost89.c:214` —
`Gost28147_TC26ParamSetZ` row 0 `{1,7,e,d,...}` equals gogost's
`SboxIdtc26gost28147paramZ` **row 7** at
`third_party/gogost/gost28147/sbox.go:80`). The net cipher output is
identical; only the in-memory layout differs. This is documented as a known,
benign divergence in `TODO.md` ("Why S-box theory was wrong"). A clean-room
reimplementer who reads the S-box bytes out of the gost-engine dylib (the
recommended approach per `CLAUDE.md`) must apply them in **engine** order:
nibble `i` of the input selects from `S[i]`, where `S[0]` is the
lowest-nibble box. If copying gogost's tables instead, reverse the eight
rows (or use gogost's own `k()` which already compensates).

### D6. Key meshing threshold counts keystream bytes, fires before the block, count is not reset

RFC 4357 §2.3.2 mandates re-keying every 1024 bytes. The exact mechanics
(easy to get wrong):

- Meshing fires when `count == 1024`, **before** generating that block
  (`gost_crypt.c:677-679`, `protection_gost.go:86-88`). The engine asserts
  `count % 8 == 0 && count <= 1024` (`gost_crypt.c:676`).
- After meshing, `count` is **not** reset to 0; the post-mesh re-encrypted
  IV is used as the counter for that block (`protection_gost.go:81-88`
  comment). `count` then advances normally:
  `count = count mod 1024 + 8` (`gost_crypt.c:702`,
  `protection_gost.go:113`).
- The new key is `ECB-decrypt(CryptoProKeyMeshingKey)` (decrypt, not
  encrypt) under the current key, and the IV is re-encrypted under the new
  key (`cryptopro_key_meshing`, `gost89.c:750-766`; `meshKey`
  `protection_gost.go:67-79`).

Because the threshold is 1024 bytes, this bug is **invisible during the
handshake** (small records) and first manifests on large application-data
records — exactly the trap called out for the IMIT MAC in `CLAUDE.md`.

### D7. State is persistent across TLS records

The CNT counter (and the paired IMIT MAC) are **not** reset per record —
the same `gostCNT`/`gostIMIT` instance carries `iv`, `count`, and the
partial-block index `num` across every record in the connection
(`protection_gost.go:9-22` header note; `XORKeyStream` `:116-130`). This
matches OpenSSL's `EVP_CIPHER_CTX` reuse. A per-record reset would desync
after the first record.

### D8. No padding

CNT is a stream mode: output length equals input length, no block padding
(`XORKeyStream`, `protection_gost.go:116-130`). The record-layer Seal feeds
`plaintext || 4-byte-IMIT` through the same stream
(`protection_gost.go:356-362`).

## Test vectors

### Existing tests in this package

Tests live in `gost28147cnt/cnt_test.go`, `gost28147cnt/guard_test.go`,
`gost28147cnt/engine_vector_test.go`, and `gost28147cnt/fuzz_test.go`.

- **`TestKAT_FirstBlocks`** — pins the first 32-byte keystream for zero
  key/IV under both S-boxes (engine-CLI cross-checked).
- **`TestKAT_KeyMeshing`** — pins bytes [1016:1040] straddling the
  1024-byte CryptoPro meshing boundary for both S-boxes.
- **`TestKAT_EngineEncTry`** — pins the gost-engine `enc.try` etalon
  (CryptoPro-A, 21-byte plaintext, real key/IV).
- **`TestCNT_Engine4K_CarryAndMeshing`** — loads a 4096-byte keystream
  from `testdata/engine-cnt-cryptoproa-4096.hex` (CryptoPro-A, real key/IV,
  gost-engine 3.0.3). 512 blocks force ≥1 end-around carry and cross the
  meshing boundary 3 times. Both one-shot and split-write variants are checked.
- **`TestInvolution`** — encrypt-then-decrypt round-trip for 12 lengths and
  both S-boxes, including mesh-crossing lengths.
- **`TestStreamingEqualsOneShot`** — split-call streaming invariant for
  tc26-Z over 1100 bytes at six split schedules.
- **`TestNewCNT_PanicsOnBadIVLength`** / **`TestXORKeyStream_PanicsOnShortDst`**
  — guard tests for the promised panic contracts.
- **`FuzzSplitInvariance`** — oracle-free: chunked XORKeyStream output must
  equal one-shot output for arbitrary key/IV/split. Seed corpus reaches 2 KiB
  to exercise meshing.

Parity tests (differential against the gogost oracle and gost-engine CLI) live
in `../gostcrypto-compat/parity/gost28147cnt/` (GPL quarantine).

### Inline KAT a reimplementer can run immediately

This is a **first-gamma-block** vector for the CNT generator: it isolates
steps "encrypt IV → +C2/+C1 → encrypt → XOR" with no meshing (input < 1024
bytes), inlined for both S-boxes. Compute it from your own `E_K` and compare;
it is also reproducible from gost-engine via the CLI oracle below.

```
Key (hex):   0000000000000000000000000000000000000000000000000000000000000000  (32 zero bytes)
IV  (hex):   0000000000000000   (8-byte synchro, all zero)
Plaintext:   all-zero           (output IS the raw gamma keystream)

Procedure (must reproduce, byte-for-byte):
  iv0   = E_K(IV)                       # first-block encrypt of IV
  lo    = LE_u32(iv0[0:4]); lo  = (lo + 0x01010101) mod 2^32
  hi    = LE_u32(iv0[4:8]); old = hi; hi = hi + 0x01010104
                                        if old > hi: hi += 1   # mod 2^32-1
  buf1  = LE_bytes(lo) || LE_bytes(hi)
  G0    = E_K(buf1)                     # XOR with plaintext == G0 for zero input
```

The concrete gamma blocks are pinned below for **both** S-boxes. These were
produced two independent ways and cross-checked to the byte: (a) the
gost-engine CLI oracle (`gost89-cnt-12` → tc26-Z, `gost89-cnt` → CryptoPro-A,
commands below), and (b) the repo's validated `gostCNT`
(`tls/internal/record/protection_gost.go:47-130`), driven over an all-zero
buffer. Both agree exactly.

**tc26-Z (`Gost28147_TC26ParamSetZ`, suites `0xFF85` / `0xC102`):**

```
G0  keystream[0:8]   = 8671cdbf3c1aae3f
G1  keystream[8:16]  = 637fa5cfaa0cb42f
G2  keystream[16:24] = a5a47a133d73b9f2
G3  keystream[24:32] = c0b04f8ca25552f8
first 32 bytes       = 8671cdbf3c1aae3f637fa5cfaa0cb42fa5a47a133d73b9f2c0b04f8ca25552f8
```

**CryptoPro-A (`Gost28147_CryptoProParamSetA`, suite `0x0081`; also the
gost-engine `SboxDefault`):**

```
G0  keystream[0:8]   = 7f775ae1edb7082b
G1  keystream[8:16]  = 95a46f38e46d4026
G2  keystream[16:24] = d74593cd0a8874dc
G3  keystream[24:32] = 202d705df54f7899
first 32 bytes       = 7f775ae1edb7082b95a46f38e46d4026d74593cd0a8874dc202d705df54f7899
```

To reproduce from ground truth via the gost-engine CLI oracle (per
`CLAUDE.md` "CLI oracles"), encrypt zero bytes under the all-zero key + IV.
Use `-gost89-cnt-12` for tc26-Z and `-gost89-cnt` for the CryptoPro-A
default:

```sh
# tc26-Z first 32 keystream bytes (== 8671cdbf...):
OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
/opt/homebrew/opt/openssl@3/bin/openssl enc -engine gost -gost89-cnt-12 \
  -K 0000000000000000000000000000000000000000000000000000000000000000 \
  -iv 0000000000000000 -nopad \
  -in /dev/zero 2>/dev/null | head -c 32 | xxd -p -c 32

# CryptoPro-A first 32 keystream bytes (== 7f775ae1...): drop the "-12".
```

Given a correct `E_K`, the gamma block is fully determined by the procedure
above — so any mismatch localises to either `E_K` (block cipher / S-box
order, D5) or the counter arithmetic (D1–D3).

#### Key-meshing vector (>1024 bytes, exercises D6)

Encrypting **1040** zero bytes under the same all-zero key/IV crosses the
1024-byte CryptoPro key-meshing boundary. The engine re-keys at exactly byte
1024, so a non-meshing implementation matches bytes `[0:1024]` and then
diverges at offset 1024 and nowhere earlier. The keystream straddling the
boundary (same two routes, cross-checked):

```
tc26-Z      keystream[1016:1024] (pre-mesh)  = d0db6a6941467fc7
tc26-Z      keystream[1024:1032] (post-mesh) = 5184cd1d30f1544d
tc26-Z      keystream[1032:1040] (post-mesh) = 3d115a61239b6d9c

CryptoPro-A keystream[1016:1024] (pre-mesh)  = 7b9ef231641fa725
CryptoPro-A keystream[1024:1032] (post-mesh) = 56f45eab8381b608
CryptoPro-A keystream[1032:1040] (post-mesh) = 4399badbc168977d
```

Note: do **not** generate this vector with gogost's raw `gost28147.CTR` — it
over-increments the counter on block-aligned input (D4 / `CLAUDE.md`). Use
the engine or the in-repo `gostCNT`. To reproduce from the engine, feed 1040
zero bytes and slice past offset 1024:

```sh
head -c 1040 /dev/zero | \
OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
/opt/homebrew/opt/openssl@3/bin/openssl enc -engine gost -gost89-cnt-12 \
  -K 0000000000000000000000000000000000000000000000000000000000000000 \
  -iv 0000000000000000 -nopad 2>/dev/null | \
  dd bs=1 skip=1024 count=8 2>/dev/null | xxd -p   # == 5184cd1d30f1544d
```

## Re-implementation checklist

Each step is independently testable against a vector before moving on.

1. **Block cipher `E_K`.** Implement the 32-round 28147 ECB encrypt with
   little-endian key/block loading, the 11-bit cyclic shift, the
   `SeqEncrypt` round-index order (`0..7,0..7,0..7,7..0`), and engine-order
   S-boxes. *Verify:* a single-block ECB KAT from gost-engine (read the
   S-box out of the dylib; do not hand-copy — `CLAUDE.md`). This is the only
   piece CNT depends on.
2. **Counter step (no meshing).** Implement `nextGamma`: first-block
   `E_K(IV)` seeding (D3), `+C2` on `LE_u32(buf1[0:4])` mod 2^32, `+C1` on
   `LE_u32(buf1[4:8])` with end-around carry (D1, D2), store back to `iv`,
   then `G = E_K(buf1)`. *Verify:* the inline first-gamma-block KAT above;
   then a second block via `TestCTR_CounterIncrement`-style "IV+1 == second
   block" check adapted to the per-half constants.
3. **Streaming XOR with partial-block carry.** Implement `XORKeyStream`
   keeping `num` (offset into the current gamma block) and a 1-block buffer
   across calls (D4). *Verify:* split-call test — encrypting N bytes in two
   calls at every offset 1..N-1 equals the one-shot result (mirror
   `TestCTR_PartialBlock`, `ctr_test.go:188`).
4. **CryptoPro key meshing.** Add the `count` counter
   (`count = count mod 1024 + 8`), trigger `meshKey` at `count == 1024`
   before the block, decrypt `CryptoProKeyMeshingKey` under the current key
   for the new key, re-encrypt IV under the new key, do **not** reset count
   (D6). *Verify:* the >1024-byte engine vector; bytes [0:1024] match a
   non-meshing run, bytes past 1024 diverge from it and match the engine.
5. **Persistent connection state.** Ensure one instance is reused across all
   records (no per-record reset of `iv`/`count`/`num`) (D7). *Verify:* a
   two-record round-trip against the engine / live Tarantool-EE.
6. **Record-layer wiring.** Seal = `CNT.encrypt(plaintext || IMIT4)`; Open =
   `CNT.decrypt(fragment)` then split tail-4 MAC and constant-time compare.
   S-box chosen by suite (CryptoPro-A for `0x0081`, tc26-Z for `0xFF85`).
   *Verify:* the `gostls` module's `TestTarantoolEE_Ping_GOST_Pure` for both
   suites (lives in the sibling `github.com/bigbes/gostls` module).

## Conformance & fuzz testing

The clean-room implementation is tested at three levels:

1. **In-package KATs** (`cnt_test.go`, `engine_vector_test.go`): pinned
   keystream bytes from gost-engine 3.0.3 for both S-boxes, covering the
   first-block, mesh-boundary, and 4096-byte (carry+3 mesh) cases.

2. **In-package fuzz** (`fuzz_test.go`): `FuzzSplitInvariance` — oracle-free,
   runs in the BSD module. Any split of the input through a single `CNT`
   instance must produce the same bytes as a one-shot call. Input lengths up to
   4 KiB ensure the fuzzer crosses the meshing boundary.

3. **Cross-module parity tests** (`../gostcrypto-compat/parity/gost28147cnt/`):
   - `TestDiff_InternalGostOracle` — differential against gogost's `CTR`
     oracle, restricted to zero key/IV, n < 1024 (the oracle's valid regime).
   - `TestDiff_GostEngineCLI` — random key/IV differential against the
     gost-engine CLI, both S-boxes, including non-block-aligned splits.
   - `FuzzDiff_InternalGostOracle` — fuzzes the oracle-valid regime.
   - `TestDiff_OracleLacksMeshing` — locks in that the clean-room impl and
     the oracle agree pre-mesh and diverge post-mesh.

**Why the gogost oracle is not a general reference:** gogost's `CTR` diverges
from the gost-engine at the first counter-half wrap (empirically: as early as
offset 160 for a random key). The cause is the end-around-carry mismatch (D4):
gogost reduces the whole counter half on `n2 >= 2^32-1`; the engine applies
`if old > h: h++`. The clean-room impl matches the engine; the gogost oracle
is only valid for the pinned zero-key/zero-IV vector below 1024 bytes.

Run the in-package tests and fuzz:

```sh
CGO_ENABLED=0 go test ./gost28147cnt/
go test -fuzz=FuzzSplitInvariance -fuzztime=30s ./gost28147cnt/
```

Run the cross-module parity tests (requires `../gostcrypto-compat`):

```sh
( cd ../gostcrypto-compat && go test ./parity/gost28147cnt/ )
```

## References

- **RFC 5830** — GOST 28147-89 Cipher Modes. §5 (ECB block transform),
  **§6 (Counter / gamma mode)**, Appendix A (constants C1=0x01010104,
  C2=0x01010101). https://github.com/bigbes/gostcrypto/blob/master/gost28147cnt/rfc/rfc5830.txt
- **RFC 4357** — Additional Cryptographic Algorithms for GOST. **§2.3.2**
  (CryptoPro key meshing, 1024-byte threshold, meshing constant).
  https://github.com/bigbes/gostcrypto/blob/master/gost28147cnt/rfc/rfc4357.txt
- **RFC 9189** — GOST Cipher Suites for TLS 1.2. §4 (28147 CNT+IMIT suites,
  4-byte MAC). https://github.com/bigbes/gostcrypto/blob/master/gost28147cnt/rfc/rfc9189.txt
- **GOST 28147-89** — Soviet/Russian block cipher standard (gamma mode).
  Superseded for new work by GOST R 34.12/34.13-2015 but still mandated by
  the TLS GOST suites.

Key source citations:

- Clean-room implementation: `gost28147cnt/cnt.go` (this package).
- Block cipher dependency: `gost28147/gost28147.go` (`Encrypt`/`Decrypt`/`SBox()`).
- gost-engine ground truth: `tmp/engine/gost_crypt.c:671-703`
  (`gost_cnt_next` — the parity target), `tmp/engine/gost89.c:214-238`
  (tc26-Z, engine row order), `:240-245` (`CryptoProKeyMeshingKey`),
  `:750-766` (`cryptopro_key_meshing`).
- gogost reference (GPL-3, do not copy; informational only):
  `gost28147/ctr.go:33-56` (`CTR.XORKeyStream`, with the streaming bugs),
  `:24-31` (`NewCTR` seeding).
- Cross-module parity tests: `../gostcrypto-compat/parity/gost28147cnt/`.
- Divergence log: `gost28147cnt/TODO.md`; root `TODO.md`.
