# CryptoPro KeyWrap + key diversification (RFC 4357 §6)

## What it is

The CryptoPro key-wrap algorithm encrypts a 32-byte (256-bit) GOST 28147-89
session key (the **CEK** — content-encryption key) under a 32-byte GOST 28147-89
key-encryption key (the **KEK**), producing a 44-byte wrapped blob. It is the key
transport primitive used by the TLS 1.2 GOST cipher suites whose key exchange is
`GOST_KEY_TRANSPORT` (RFC 9189 §4.1): the TLS premaster secret is the CEK, and
the VKO-derived shared secret is the KEK.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

Two RFC 4357 sub-algorithms compose:

- **RFC 4357 §6.5 — CryptoPro KEK Diversification.** Given the 32-byte KEK and an
  8-byte UKM (user keying material), derives a per-UKM key `KEK(UKM)` via eight
  rounds of GOST 28147-89 CFB encryption. The bit pattern of each UKM byte selects
  how the eight current-key 32-bit words are summed into a fresh CFB IV.
- **RFC 4357 §6.3 — CryptoPro Key Wrap.** Diversifies the KEK, ECB-encrypts the CEK
  under `KEK(UKM)`, computes a 4-byte GOST 28147-89 IMIT (MAC) over the CEK with
  `IV = UKM`, and concatenates `UKM | CEK_ENC | CEK_MAC`.

(RFC 4357 §6.4 is the inverse Key Unwrap; the repo only *wraps* on the TLS client
side, so unwrap is not implemented here, but its layout assertions are documented
below for completeness.)

GOST / standard identity:

- Block cipher: GOST 28147-89 (a.k.a. "Magma legacy"), 64-bit block, 256-bit key.
- IMIT MAC: GOST 28147-89 imitovstavka (CBC-MAC-like); the `gost28147IMIT`
  function is defined in RFC 4357 §1.1 Terminology (here truncated to 4 bytes
  by the wrap).
- KEK source: VKO GOST R 34.10-2001 (RFC 4357 §5.2) or VKO GOST R 34.10-2012
  (RFC 7836), depending on the certificate's public-key algorithm.

### Where this repo uses it

`internal/gost.KeyWrapCryptoPro` is the entry point. Real call sites:

- `tls/internal/ke/vkogost.go:166` — `VKOGost2001Exchange.ClientKeyExchange`,
  suite `GOST2001-GOST89-GOST89` (TLS suite ID **0x0081**). Uses the
  **CryptoPro-A** S-box (`gost.SboxCryptoProA`) and cipher param OID
  `id-Gost28147-89-CryptoPro-A-ParamSet` = `1.2.643.2.2.31.1`
  (`tls/internal/ke/vkogost.go:48`).
- `tls/internal/ke/vkogost.go:252` — `VKOGost2012_256Exchange.ClientKeyExchange`,
  suites `GOST2012-GOST8912-GOST8912` (TLS suite IDs **0xFF85 / 0xC102**). Uses the
  **tc26-Z** S-box (`gost.SboxTC26Z`) and cipher param OID
  `id-tc26-gost-28147-param-Z` = `1.2.643.7.1.2.5.1.1`
  (`tls/internal/ke/vkogost.go:41`).

In both cases the 44-byte output is split: `wrapped[8:40]` becomes the
`GOST_KEY_INFO` encrypted key and `wrapped[40:44]` becomes the IMIT MAC, both fed
into `marshalGOSTKeyTransport` (`tls/internal/ke/gost_keytransport.go:79`).

### Status: in-repo reimplementation (not gogost's wrap)

The repo does **not** call gogost's `gost28147.WrapGost`
(`third_party/gogost/gost28147/wrap.go:24`) or `gost28147.DiversifyCryptoPro`
(`third_party/gogost/gost28147/wrap.go:60`). It reimplements
both steps in `internal/gost/primitives_gost.go:275` (`KeyWrapCryptoPro`) and
`:315` (`keyDiversifyCryptoPro`), using only gogost's `gost28147.Cipher`,
`NewCFBEncrypter`, `NewMAC`, and `Encrypt`. The reason: the wrap must select the
S-box by certificate type (tc26-Z vs CryptoPro-A), but gogost's `WrapGost`
hardcodes the CryptoPro-A S-box (and, unlike RFC 4357 §6.3, does not diversify
the KEK at all). A GPL-free reimplementation therefore needs only
a GOST 28147-89 block cipher with the two S-boxes, a CFB-encrypt helper, and an
IMIT MAC helper — all describable without reading gogost.

## Specification

All sizes are fixed:

| Quantity                | Size      |
|-------------------------|-----------|
| Block (GOST 28147-89)   | 8 bytes   |
| KEK                     | 32 bytes  |
| CEK (session key)       | 32 bytes  |
| UKM                     | 8 bytes   |
| Diversified key KEK(UKM)| 32 bytes  |
| CEK_ENC                 | 32 bytes  |
| CEK_MAC (IMIT, trunc.)  | 4 bytes   |
| Wrapped output          | 44 bytes  |

### RFC 4357 §6.5 — KEK Diversification (normative)

> "Given a random 64-bit UKM and a GOST 28147-89 key K, this algorithm creates a
> new GOST 28147-89 key K(UKM)." (RFC 4357 §6.5)

The algorithm (RFC 4357 §6.5):

1. `K[0] = K` (the input KEK).
2. UKM is processed bit-by-bit. For round `i = 0 .. 7`, treat the current key
   `K[i]` as eight little-endian 32-bit words `w[0..7]`. Form two 32-bit sums:
   for each word index `j = 0 .. 7`, if bit `j` of `ukm[i]` is set, add `w[j]`
   into `S1`, otherwise add `w[j]` into `S2` (sums taken mod 2^32).
3. Build the 8-byte CFB IV `S[i] = LE32(S1) || LE32(S2)`.
4. `K[i+1] = encryptCFB(S[i], K[i], K[i])` — CFB-encrypt the 32-byte current key
   under itself, with IV `S[i]`. The output replaces the key in place.
5. After 8 rounds, `K(UKM) = K[8]`.

Note the self-keying: each round encrypts `K[i]` using `K[i]` as the cipher key.

### RFC 4357 §6.3 — Key Wrap (normative)

> 1. "For a unique symmetric KEK or a KEK produced by VKO GOST R 34.10-94,
>    generate 8 octets at random. Call the result UKM."
> 2. "Diversify KEK, using the CryptoPro KEK Diversification Algorithm, described
>    in Section 6.5. Call the result KEK(UKM)."
> 3. "Compute a 4-byte checksum value, gost28147IMIT (UKM, KEK(UKM), CEK). Call
>    the result CEK_MAC."
> 4. "Encrypt CEK in ECB mode using KEK(UKM). Call the ciphertext CEK_ENC."
> 5. "The wrapped content-encryption key is (UKM | CEK_ENC | CEK_MAC)."
> (RFC 4357 §6.3)

Here `gost28147IMIT(UKM, KEK(UKM), CEK)` means: the GOST 28147-89 IMIT MAC of the
message `CEK` (32 bytes = 4 full blocks), keyed with `KEK(UKM)`, using the
**non-zero IV `UKM`** as the MAC's initial chaining state, truncated to its 4
least-significant (first) bytes. In TLS, the UKM is *not* freshly random — it is
derived from `client_random` (first 8 bytes), so step 1 is supplied by the caller.

### Wrap output layout

```
offset:  0        8                              40        44
        +--------+------------------------------+----------+
        |  UKM   |          CEK_ENC             | CEK_MAC  |
        | 8 B    |          32 B                |  4 B     |
        +--------+------------------------------+----------+
```

The 8 UKM bytes at `[0:8]` are a verbatim copy of the input UKM (RFC layout
requires UKM to travel with the wrapped key so the receiver can re-diversify).

### S-box selection rule

GOST 28147-89 is parameterized by an 8×16 S-box. The wrap and *all* its
sub-primitives (diversification CFB, ECB encrypt, IMIT MAC) use the **same**
S-box, selected by the server certificate's public-key algorithm:

- **GOST R 34.10-2012 certificate** → `id-tc26-gost-28147-param-Z` S-box
  (`SboxTC26Z`, gogost `SboxIdtc26gost28147paramZ`,
  `third_party/gogost/gost28147/sbox.go:72`). Cipher param OID `1.2.643.7.1.2.5.1.1`.
- **GOST R 34.10-2001 certificate** → CryptoPro-A S-box
  (`SboxCryptoProA`, gogost `SboxIdGost2814789CryptoProAParamSet`,
  `third_party/gogost/gost28147/sbox.go:32`). Cipher param OID `1.2.643.2.2.31.1`.

This selection is gost-engine behavior (RFC 9189 §4.1 GOST_KEY_TRANSPORT), not
RFC 4357 — RFC 4357 predates the 2012 suites and only ever used CryptoPro-A.
Source for the engine's `ctx` S-box init at the wrap call:
`tmp/engine/gost_ec_keyx.c` (`pkey_GOST_ECcp_encrypt`); the wrap itself is S-box
agnostic — it uses whatever S-box the passed-in `gost_ctx` was initialized with
(`tmp/engine/gost_keywrap.c:67-79`).

The tc26-Z S-box bytes (8 rows × 16 columns,
`third_party/gogost/gost28147/sbox.go:72`):

```
row0: c 4 6 2 a 5 b 9 e 8 d 7 0 3 f 1
row1: 6 8 2 3 9 a 5 c 1 e 4 7 b d 0 f
row2: b 3 5 8 2 f a d e 1 7 4 c 9 6 0
row3: c 8 2 1 d 4 f 6 7 0 a 5 3 e 9 b
row4: 7 f 5 a 8 1 6 d 0 9 3 e b 4 2 c
row5: 5 d f 6 9 2 c a b 7 8 1 4 3 e 0
row6: 8 e 2 5 6 9 1 c f 4 b 0 d a 3 7
row7: 1 7 e d 0 5 8 3 4 f a 6 9 c b 2
```

(CryptoPro-A bytes are at `third_party/gogost/gost28147/sbox.go:32`; not inlined
here. The tc26-Z rows above are a verbatim copy of gogost's
`SboxIdtc26gost28147paramZ` and are correct as-is for the GOST 28147-89 block
cipher — gogost stores these block-cipher S-box rows in canonical order and
applies row `i` to nibble `i` in its cipher step (`sbox.go:117` `Sbox.k`),
matching gost-engine byte-for-byte. (The "reverse row order" divergence noted in
TODO.md is scoped to the **GOST R 34.11-94 hash** primitive's S-box usage, NOT
this block cipher — see D8.) If you prefer to avoid copying gogost's table,
reading `Gost28147_tc26ParamSetZ` / `Gost28147_CryptoProParamSetA` straight out
of the gost-engine dylib (CLAUDE.md "read the S-box symbol out of the dylib")
yields the identical rows.)

## RFC ↔ implementation deltas

This is the core section. Each delta cites the RFC and the source line.

### D1 — Word/sum endianness in diversification is little-endian

RFC 4357 §6.5 describes the sum over "components" abstractly. Both gost-engine and
this repo read the 32-bit words **little-endian** and emit `S1`,`S2` **little-endian**:

- engine: `k = outputKey[4j] | (outputKey[4j+1]<<8) | (outputKey[4j+2]<<16) |
  (outputKey[4j+3]<<24)` then `S[0..3]=LE(s1)`, `S[4..7]=LE(s2)`
  (`tmp/engine/gost_keywrap.c:35-52`).
- repo: identical LE pack/unpack at `internal/gost/primitives_gost.go:322` and
  `:330-337`.

A reimplementer who packs big-endian here will produce a wrong `KEK(UKM)` and
every downstream byte will differ.

### D2 — Bit-selection order: LSB-first, `mask = 1 << j`

The UKM bit that routes word `j` is bit `j` (the `j`-th least significant bit) of
`ukm[i]`:

- engine: `for (j=0, mask=1; j<8; j++, mask<<=1) { if (mask & ukm[i]) s1 += k; }`
  (`tmp/engine/gost_keywrap.c:35-44`).
- repo: `if ukm[i]&(1<<j) != 0 { s1 += k } else { s2 += k }`
  (`internal/gost/primitives_gost.go:323`).

Bit `j` of `ukm[i]` → routes word `j`. Round index `i` selects `ukm[i]`; word
index `j` selects both the word AND the bit. Off-by-one or MSB-first here silently
corrupts the IV.

### D3 — Sum accumulator width (mod 2^32 wrap)

The two sums wrap mod 2^32. engine uses `u4` (uint32), so wrap is automatic
(`tmp/engine/gost_keywrap.c:29-30`). gogost's own `DiversifyCryptoPro` uses
`uint64` accumulators and explicitly takes `% (1<<32)`
(`third_party/gogost/gost28147/wrap.go:62,75-77`). The repo uses `uint32` and lets
Go's defined unsigned overflow wrap (`internal/gost/primitives_gost.go:320,326`).
All three agree; just don't use a signed accumulator or a wider type without the
mask.

### D4 — Self-keyed CFB each round

Each round re-keys the cipher with the *current* (already partially diversified)
key, then CFB-encrypts that same key buffer in place:

- engine: `gost_key(ctx, outputKey); gost_enc_cfb(ctx, S, outputKey, outputKey, 4)`
  — 4 CFB blocks = 32 bytes (`tmp/engine/gost_keywrap.c:53-54`).
- repo: `c := gost28147.NewCipher(out, sbox.inner);
  cfb := c.NewCFBEncrypter(S[:]); cfb.XORKeyStream(out, out)`
  (`internal/gost/primitives_gost.go:339-341`).

The CFB IV is the freshly computed 8-byte `S`; the plaintext and ciphertext buffers
are the same 32-byte `out`. CFB feedback uses the just-produced ciphertext as the
next block's IV (`gost_enc_cfb`, `tmp/engine/gost89.c:515-530`).

### D5 — IMIT MAC uses a NON-ZERO IV = UKM, and exactly 4 blocks (no `i==8` extra block)

The wrap's MAC is `gost_mac_iv(ctx, 32 bits, IV=ukm, data=CEK, data_len=32,
out=wrapped+40)` (`tmp/engine/gost_keywrap.c:77`). Two subtleties:

1. **IV = UKM**: the MAC starts from chaining state `UKM`, not zero. The repo does
   this via `c.NewMAC(4, ukm)` (`internal/gost/primitives_gost.go:296`).
2. **No final all-zero padding block**: `gost_mac_iv` processes `data_len=32` as
   four full 8-byte blocks. Because `data_len` is an exact multiple of 8 and
   nonzero, the `if (i < data_len)` partial-block branch never fires, and the
   `if (i == 8)` single-block special-case never fires (`i` ends at 32)
   (`tmp/engine/gost89.c:733-744`). So the MAC is exactly four `mac_block` calls
   over the four CEK blocks — no extra block, no zero-padding. The repo's plain
   `mac.Write(sessionKey)` + `mac.Sum(nil)` reproduces this because the input is a
   whole number of blocks (`internal/gost/primitives_gost.go:300-303`).

A reimplementer must NOT borrow the empty/partial-input finalization logic from the
general `GOST28147_IMIT` wrapper (`internal/gost/primitives_gost.go:424`) — that
path adds an all-zero block when `count==0 && remaining>0` and key-meshes; none of
that applies here.

### D6 — MAC truncation: first 4 bytes (least-significant), not last

`gost_mac_iv(..., mac_len=32 /*bits*/, ...)` → `get_mac` copies `nbits>>3 = 4`
bytes from the front of the 8-byte MAC state (`tmp/engine/gost89.c:686-696`,
`:745`). The repo takes `macOut := mac.Sum(nil)` (already 4 bytes via
`NewMAC(4, ...)`) and copies it to `out[40:44]`
(`internal/gost/primitives_gost.go:303,308`). The 8-byte IMIT state is
`LE32(n1) || LE32(n2)` (`tmp/engine/gost89.c:675-682`); the 4-byte truncation keeps
`LE32(n1)`.

### D7 — Key meshing does NOT fire in the wrap MAC

CLAUDE.md / TODO.md document CryptoPro key meshing every 1024 bytes of IMIT input
(`tmp/engine/gost_crypt.c:1510-1524 mac_block_mesh`, RFC 4357 §2.3.2). The wrap's
MAC input is only 32 bytes, far below the 1024-byte threshold, so **meshing never
triggers** in key wrap. This is the one of the three known gogost↔engine
divergences (TODO.md "RESOLVED 2026-04-20" entry) that is *irrelevant* to this
primitive — do not add meshing to the wrap MAC. (The other two divergences, S-box
row order — see D8 — and R 34.11-94 empty-input finalization, the latter does not
touch keywrap at all.)

### D8 — the "reversed S-box rows" caveat does NOT apply to the gost28147 block cipher

TODO.md records a gogost↔engine "reverse row order" divergence, but it is scoped
to the **GOST R 34.11-94 hash** primitive (`gost341194`), whose `step()` applies a
compensating `blockReverse`. It does **not** touch the GOST 28147-89 block-cipher
S-boxes that this wrap uses. Verified: gogost's `SboxIdtc26gost28147paramZ`
(`sbox.go:72`) and `SboxIdGost2814789CryptoProAParamSet` (`sbox.go:32`) store rows
in canonical order, and gogost's cipher step applies row `i` to nibble `i`
(`sbox.go:117` `Sbox.k`: `s[0][n&0xF] | s[1][(n>>4)&0xF] | ...`). Both tables are
byte-identical to the gost-engine dylib symbols and to the canonical RFC order.
Therefore a verbatim copy of gogost's tc26-Z / CryptoPro-A block-cipher rows (as
inlined above) is correct, and a clean-room cipher that applies row `i` to nibble
`i` reproduces engine output. Reading the rows out of the gost-engine dylib
(`Gost28147_tc26ParamSetZ` / `Gost28147_CryptoProParamSetA`) is an optional
cross-check, not a correction — it yields the same bytes.

### D9 — Diversified key is keyed before ECB encrypt (a no-op in our wrappers)

engine calls `gost_key(ctx, kek_ukm)` before `gost_enc(ctx, sessionKey, ...)`
(`tmp/engine/gost_keywrap.c:74-76`) to load `KEK(UKM)` into the cipher context.
The repo achieves the same by constructing a fresh cipher
`c := gost28147.NewCipher(kekUKM, sbox.inner)`
(`internal/gost/primitives_gost.go:289`) and reusing `c` for both the ECB encrypt
loop and the MAC. No behavioral delta — just note the ECB encrypt and the MAC both
use `KEK(UKM)`, never the raw KEK.

### D10 — ECB encrypt is 4 independent 8-byte blocks

`gost_enc(ctx, sessionKey, wrappedKey+8, 4)` = 4 ECB blocks
(`tmp/engine/gost_keywrap.c:76`, loop in `tmp/engine/gost89.c:493-501`). The repo
loops `i = 0,8,16,24` calling `c.Encrypt(encrypted[i:i+8], sessionKey[i:i+8])`
(`internal/gost/primitives_gost.go:291-293`). Plain ECB, no IV, no chaining.

## Test vectors

### In-repo KAT

`internal/gost/keywrap_vector_test.go:20` (`TestKeyWrapCryptoPro_KAT`) — captured
from gost-engine 3.0.3 `keyWrapCryptoPro` via dlopen on the **tc26-Z** S-box.

Inputs:

```
kek     = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20  (32 B)
ukm     = 0102030405060708                                                  (8 B)
session = 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f  (32 B)
sbox    = tc26-Z
```

Expected (all verified against gost-engine):

```
KEK(UKM)  = c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18   (32 B)
CEK_ENC   = 940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1   (32 B)  -> wrapped[8:40]
CEK_MAC   = e77d8bc3                                                           (4 B)   -> wrapped[40:44]
UKM       = 0102030405060708                                                   (8 B)   -> wrapped[0:8]
```

Full 44-byte wrapped output:

```
0102030405060708 940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1 e77d8bc3
```

A reimplementer can run this immediately: implement diversification → assert
`KEK(UKM)` matches `c8ffc6b8...`; then ECB-encrypt + IMIT → assert the full 44 bytes.

### gost-engine reference

- C implementation under test: `tmp/engine/gost_keywrap.c:67-79` (`keyWrapCryptoPro`),
  `:23-56` (`keyDiversifyCryptoPro`).
- The dylib exports `keyWrapCryptoPro`, `keyDiversifyCryptoPro`, `keyUnwrapCryptoPro`
  (CLAUDE.md "Ground-truth GOST primitives") — dlopen them to generate fresh
  vectors for the CryptoPro-A path (0x0081), which the in-repo KAT does not cover.

## Re-implementation checklist

Each step is independently testable against a vector.

1. **GOST 28147-89 block cipher** with both S-boxes (tc26-Z, CryptoPro-A) in
   *engine* row order (D8). Verify single-block ECB encrypt against a published
   GOST 28147-89 KAT before proceeding.
2. **CFB-encrypt helper** matching `gost_enc_cfb`: 8-byte IV, feedback = previous
   ciphertext block, XOR plaintext with `E(cur_iv)` (`tmp/engine/gost89.c:515-530`).
   Verify a multi-block CFB KAT.
3. **Diversification** (RFC 4357 §6.5): 8 rounds, LE 32-bit word read (D1),
   LSB-first bit selection `1<<j` (D2), `uint32` sums mod 2^32 (D3),
   `S = LE32(s1)||LE32(s2)`, self-keyed in-place CFB (D4). Assert `KEK(UKM)` ==
   `c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18` for the KAT
   inputs with tc26-Z.
4. **IMIT MAC with non-zero IV** (RFC 4357 §1.1 `gost28147IMIT` / §6.3 step 3): initialize chaining
   state to `UKM`, process exactly four 8-byte CEK blocks, take the first 4 bytes
   (`LE32(n1)`) of the 8-byte state (D5, D6). No padding block, no key meshing (D7).
   Assert `e77d8bc3` for the KAT.
5. **ECB encrypt CEK** under `KEK(UKM)` as four independent blocks (D10). Assert
   `940e6d83...`.
6. **Assemble** `UKM(8) | CEK_ENC(32) | CEK_MAC(4)` = 44 bytes (RFC 4357 §6.3
   step 5). Assert the full KAT output.
7. **S-box dispatch** by certificate type: tc26-Z for GOST R 34.10-2012 (0xFF85 /
   0xC102), CryptoPro-A for GOST R 34.10-2001 (0x0081). Generate a CryptoPro-A
   vector from the engine dylib and assert it.

## Conformance & fuzz testing

Differential testing for this primitive has **no gogost reference target**: the
repo deliberately does not call gogost's `WrapGost` (it hardcodes CryptoPro-A
and skips KEK diversification; see "Status" above), so the only oracles are (a) the in-repo
`internal/gost.KeyWrapCryptoPro` itself (`internal/gost/primitives_gost.go:275`) and
(b) the gost-engine 3.0.3 `keyWrapCryptoPro` dylib symbol, reached here through the
engine CLI per CLAUDE.md's oracle guidance, plus the pinned 44-byte KAT vectors from
`internal/gost/keywrap_vector_test.go:20`. Because the wrap is randomized only by its
inputs (a deterministic function of KEK, UKM, CEK), the fuzz harness drives a random
32-byte KEK + 8-byte UKM + 32-byte session key through *both* the clean-room impl and
the engine oracle for *each* S-box (tc26-Z and CryptoPro-A — the latter is the 0x0081
path the in-repo KAT does not cover) and asserts byte-for-byte equality of the full
44-byte blob. The KAT below seeds the corpus; the fuzzer expands coverage to the
CryptoPro-A S-box that has no pinned vector.

The engine oracle is a CLI helper, not a Go import — the gost-engine dylib's
`keyWrapCryptoPro` is reached via `dlopen` from an ad-hoc cgo tool (CLAUDE.md
"Ground-truth GOST primitives"; the dylib has a non-standard mach-o filetype and
won't link). Build a tiny `enginewrap` binary that dlsyms `keyWrapCryptoPro` and
prints the 44-byte hex; the helper below shells out to it. Substitute the alias
`mynew` for your clean-room package.

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"testing"

	gost "go.bigb.es/tlsdialer/internal/gost" // in-repo reference (KeyWrapCryptoPro)
	mynew "example.com/your/keywrap" // clean-room impl under test
)

// engineWrap shells out to an ad-hoc cgo tool that dlopens the gost-engine
// dylib and calls keyWrapCryptoPro (no gogost API exists for this wrap).
// The tool prints the 44-byte wrapped blob as hex. Path is overridable via
// ENGINE_WRAP_BIN; skip the engine leg if the binary isn't present.
func engineWrap(t *testing.T, sboxName string, kek, ukm, cek []byte) []byte {
	t.Helper()
	bin := os.Getenv("ENGINE_WRAP_BIN")
	if bin == "" {
		bin = "/tmp/claude/enginewrap/enginewrap"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("enginewrap oracle not built; set ENGINE_WRAP_BIN")
	}
	// enginewrap <sbox> <kek-hex> <ukm-hex> <cek-hex> -> 44B hex on stdout
	out, err := exec.Command(bin, sboxName,
		hex.EncodeToString(kek), hex.EncodeToString(ukm), hex.EncodeToString(cek)).Output()
	if err != nil {
		t.Fatalf("engineWrap %s: %v", sboxName, err)
	}
	b, err := hex.DecodeString(string(bytes.TrimSpace(out)))
	if err != nil {
		t.Fatalf("engineWrap decode: %v", err)
	}
	return b
}

// pick maps an S-box name to both the clean-room and in-repo selectors.
func pick(name string) (mynew.Sbox, *gost.Sbox) {
	switch name {
	case "tc26-z":
		return mynew.SboxTC26Z, gost.SboxTC26Z
	case "cryptopro-a":
		return mynew.SboxCryptoProA, gost.SboxCryptoProA
	}
	panic("unknown sbox " + name)
}

func TestKeyWrapCryptoProConformance(t *testing.T) {
	// The exact pinned tc26-Z vector from
	// internal/gost/keywrap_vector_test.go:20 (and "Test vectors" above).
	mustHex := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	cases := []struct {
		name, sbox             string
		kek, ukm, cek, wrapped []byte
	}{
		{
			name:    "tc26z-kat",
			sbox:    "tc26-z",
			kek:     mustHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
			ukm:     mustHex("0102030405060708"),
			cek:     mustHex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
			wrapped: mustHex("0102030405060708940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1e77d8bc3"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newSbox, repoSbox := pick(tc.sbox)

			// Clean-room impl must equal the pinned vector.
			gotNew, err := mynew.KeyWrapCryptoPro(newSbox, tc.kek, tc.ukm, tc.cek)
			if err != nil {
				t.Fatalf("mynew.KeyWrapCryptoPro: %v", err)
			}
			if !bytes.Equal(gotNew, tc.wrapped) {
				t.Fatalf("clean-room mismatch:\n got: %x\nwant: %x", gotNew, tc.wrapped)
			}

			// In-repo reference must also equal the pinned vector.
			gotRepo, err := gost.KeyWrapCryptoPro(repoSbox, tc.kek, tc.ukm, tc.cek)
			if err != nil {
				t.Fatalf("gost.KeyWrapCryptoPro: %v", err)
			}
			if !bytes.Equal(gotRepo, tc.wrapped) {
				t.Fatalf("in-repo mismatch:\n got: %x\nwant: %x", gotRepo, tc.wrapped)
			}
		})
	}
}

func FuzzKeyWrapCryptoProConformance(f *testing.F) {
	// Seed from the KAT inputs (kek||ukm||cek, 72 bytes) for each S-box.
	kek := mustHexF(f, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	ukm := mustHexF(f, "0102030405060708")
	cek := mustHexF(f, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
	for _, name := range []string{"tc26-z", "cryptopro-a"} {
		f.Add(name, append(append(append([]byte{}, kek...), ukm...), cek...))
	}

	f.Fuzz(func(t *testing.T, sbox string, raw []byte) {
		if sbox != "tc26-z" && sbox != "cryptopro-a" {
			return // only the two real S-boxes
		}
		// Normalize the random []byte into the fixed-size arguments:
		// 32-byte KEK | 8-byte UKM | 32-byte CEK (72 bytes total).
		buf := make([]byte, 72)
		copy(buf, raw) // short input -> zero-padded; long input -> truncated
		kek, ukm, cek := buf[0:32], buf[32:40], buf[40:72]

		newSbox, repoSbox := pick(sbox)

		gotNew, err := mynew.KeyWrapCryptoPro(newSbox, kek, ukm, cek)
		if err != nil {
			t.Fatalf("mynew.KeyWrapCryptoPro: %v", err)
		}
		gotRepo, err := gost.KeyWrapCryptoPro(repoSbox, kek, ukm, cek)
		if err != nil {
			t.Fatalf("gost.KeyWrapCryptoPro: %v", err)
		}
		if !bytes.Equal(gotNew, gotRepo) {
			t.Fatalf("clean-room vs in-repo mismatch (sbox=%s)\n kek=%x ukm=%x cek=%x\n new=%x\nrepo=%x",
				sbox, kek, ukm, cek, gotNew, gotRepo)
		}
		// Cross-check against the engine oracle when the binary is available.
		if want := engineWrap(t, sbox, kek, ukm, cek); !bytes.Equal(gotNew, want) {
			t.Fatalf("clean-room vs engine mismatch (sbox=%s)\n new=%x\n eng=%x", sbox, gotNew, want)
		}
	})
}

func mustHexF(f *testing.F, s string) []byte { f.Helper(); b, _ := hex.DecodeString(s); return b }
```

Run:

```sh
go test -tags gost -run TestKeyWrapCryptoProConformance ./yourpkg/
go test -tags gost -fuzz=FuzzKeyWrapCryptoProConformance -fuzztime=30s ./yourpkg/
```

## References

RFCs:

- RFC 4357 §6.3 — CryptoPro Key Wrap.
  https://github.com/bigbes/gostcrypto/blob/master/keywrap/rfc/rfc4357.txt
- RFC 4357 §6.4 — CryptoPro Key Unwrap (inverse; layout assertions).
  https://github.com/bigbes/gostcrypto/blob/master/keywrap/rfc/rfc4357.txt
- RFC 4357 §6.5 — CryptoPro KEK Diversification Algorithm.
  https://github.com/bigbes/gostcrypto/blob/master/keywrap/rfc/rfc4357.txt
- RFC 4357 §1.1 — `gost28147IMIT` (GOST 28147-89 IMIT MAC) definition, in Terminology.
  https://github.com/bigbes/gostcrypto/blob/master/keywrap/rfc/rfc4357.txt
- RFC 9189 §4.1 — GOST_KEY_TRANSPORT (TLS 1.2 use; S-box-by-cert selection).
  https://github.com/bigbes/gostcrypto/blob/master/keywrap/rfc/rfc9189.txt
- RFC 7836 — VKO GOST R 34.10-2012 (one of the two KEK sources).
- RFC 5830 — GOST 28147-89 block cipher / modes.

GOST standards:

- GOST 28147-89 — block cipher + IMIT (imitovstavka) MAC.
- GOST R 34.10-2001 / GOST R 34.10-2012 — public-key algorithms behind the KEK.

Key source citations:

- `internal/gost/primitives_gost.go:275` — `KeyWrapCryptoPro` (in-repo reimpl).
- `internal/gost/primitives_gost.go:315` — `keyDiversifyCryptoPro`.
- `internal/gost/keywrap_vector_test.go:20` — KAT.
- `tmp/engine/gost_keywrap.c:23-56` — engine `keyDiversifyCryptoPro`.
- `tmp/engine/gost_keywrap.c:67-79` — engine `keyWrapCryptoPro`.
- `tmp/engine/gost89.c:515-530` — `gost_enc_cfb`.
- `tmp/engine/gost89.c:493-501` — `gost_enc` (ECB).
- `tmp/engine/gost89.c:725-747` — `gost_mac_iv` (IMIT with IV).
- `tmp/engine/gost89.c:686-696` — `get_mac` (truncation).
- `tls/internal/ke/vkogost.go:166,252` — TLS call sites.
- `tls/internal/ke/vkogost.go:41,48` — cipher param OIDs.
- `third_party/gogost/gost28147/wrap.go:60` — gogost's (unused) `DiversifyCryptoPro`,
  for cross-reference only.
- `third_party/gogost/gost28147/sbox.go:32,72` — S-box tables (reversed row order, D8).
