# KExp15 / KImp15 key export wrapping (R 1323565.1.017-2018)

## What it is

KExp15 is the GOST **key-transport envelope**: it wraps a secret key `S`
(typically a 32-byte pre-master / session key) so that it can be carried over
the wire authenticated and encrypted under two independent export keys. KImp15
is the exact inverse (decrypt, then verify the MAC). This package implements
the export (wrap) direction only; the import/unwrap direction is intentionally
out of scope.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

The construction is **OMAC-then-CTR**:

```
CEK_MAC = OMAC(K_Exp_MAC, IV || S)            (truncated to mac_len)
SExp    = CTR-Encrypt(K_Exp_ENC, IV_full, S || CEK_MAC)
```

- Standard identity: **R 1323565.1.017-2018** (the Russian TC26 export-key
  recommendation). Referenced normatively by:
  - **RFC 9189 §8.2.1** ("KExp15 and KImp15 algorithms"), which defines the
    construction for the GOST 2012 TLS 1.2 cipher suites 0xC100 and 0xC101.
  - **RFC 9367** is the GOST TLS **1.3** specification (MGM AEAD key-share;
    it does **not** use KExp15 or key transport envelopes — its suites are
    0xC103–0xC106).
- Block-cipher variants (R 34.12-2015):
  - **Kuznyechik** — 128-bit block. `iv_len = 8`, `mac_len = 16`, `block = 16`.
    RFC 9189 suite 0xC100 (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`).
  - **Magma** — 64-bit block. `iv_len = 4`, `mac_len = 8`, `block = 8`.
    RFC 9189 suite 0xC101 (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`).

### Where this repo uses it

- `kexp15/kexp15.go` — `Kexp15(variant, sharedKey, cipherKey, macKey, iv)`
  and the `KexpVariant` enum (`KexpKuznyechik`, `KexpMagma`). This is the
  primitive being documented.
- The single direct consumer in the workspace is the GOST 2018 key exchange in
  the `gostls` sibling module:
  `gostls/internal/ke/gost2018.go` (approximate path)
  ```go
  wrapped, err := kexp15.Kexp15(kexpVariant(e.variant), preMaster, expkeys[32:], expkeys[:32], iv)
  ```
  Here `expkeys` is the 64-byte output of `KEG2012_256` (VKO + KDFTREE), split
  as `expkeys[:32] = mac_key (K_Exp_MAC)` and `expkeys[32:] = cipher_key
  (K_Exp_ENC)`. The `iv` is `ukm[24 : 24+iv_len]`. The wrapped output becomes
  the `psexp` field of the `PSKeyTransport_gost` ASN.1 structure sent in
  ClientKeyExchange.
- These suites are RFC 9189 0xC100 (Kuznyechik-CTR-OMAC) and 0xC101
  (Magma-CTR-OMAC).

### Status

**Clean-room.** `kexp15/kexp15.go` implements the envelope in Go: it does the
IV padding, the OMAC call, the concatenation, and the CTR call directly, using
the sibling packages `omac/` and `ctracpkm/` — both clean-room reimplementations
in this module. No gogost dependency exists anywhere in this package or its
imports; there are no build tags. The block ciphers are `kuznyechik.NewCipher`
and `magma.NewCipher` from the sibling packages.

The C ground truth is gost-engine's `gost_kexp15`
(`tmp/engine/gost_keyexpimp.c:34-109`), which is what the Go code mirrors
line-for-line. Differential parity testing lives in
`../gostcrypto-compat/parity/kexp15/kexp15_parity_test.go` (the mandated
home for all differential tests that touch GPL code; see workspace
`CLAUDE.md`).

## Specification

### Inputs and sizes

| name        | meaning                       | Kuznyechik | Magma |
|-------------|-------------------------------|------------|-------|
| `S`         | shared/secret key to wrap     | any len ≥ 1 (32 in TLS) | any len ≥ 1 (32 in TLS) |
| `K_Exp_ENC` | CTR encryption key            | 32 bytes   | 32 bytes |
| `K_Exp_MAC` | OMAC authentication key       | 32 bytes   | 32 bytes |
| `IV`        | half-block IV                 | 8 bytes    | 4 bytes |
| block size  | cipher block                  | 16 bytes   | 8 bytes |
| `mac_len`   | MAC truncation length         | 16 bytes   | 8 bytes |
| output      | `len(S) + mac_len`            | len(S)+16  | len(S)+8 |

The IV is **half a block** (`iv_len = block/2`). This is the key sizing quirk:
the wire IV is short, but the CTR mode needs a full-block counter.

### Algorithm (RFC 9189 §8.2.1, mirrored by gost-engine)

RFC 9189 §8.2.1 states the algorithm verbatim:

> KExp15:
> 1. `CEK_MAC = OMAC(K_Exp_MAC, IV | S)`
> 2. `SExp = CTR-Encrypt(K_Exp_ENC, IV, S | CEK_MAC)`

> KImp15:
> 1. `S | CEK_MAC = CTR-Decrypt(K_Exp_ENC, IV, SExp)`
> 2. `If CEK_MAC = OMAC(K_Exp_MAC, IV | S) then return S; else return FAIL`

> "The keys K_Exp_MAC and K_Exp_ENC MUST be independent. For every pair of
> keys, the IV values MUST be unique."

The RFC uses CTR with full block size (`s = n`, i.e. CTR-128 for Kuznyechik,
CTR-64 for Magma — no truncated gamma).

Step by step, as implemented (`kexp15/kexp15.go:98-152`, matching
`tmp/engine/gost_keyexpimp.c:62-98`):

1. **Build the full counter from the half-IV.**
   Allocate `iv_full = block` zero bytes, copy `IV` into the **front** (low
   indices), leave the back zero.
   `gost_keyexpimp.c:63-64`: `memset(iv_full, 0, 16); memcpy(iv_full, iv, ivlen);`
   `kexp15.go:122-125`. So Kuznyechik `iv_full = IV(8) || 00·8`,
   Magma `iv_full = IV(4) || 00·4`.

2. **Compute the MAC over `IV || S`** with `K_Exp_MAC`, using OMAC1/CMAC of the
   block cipher, then truncate to the leftmost `mac_len` bytes.
   `gost_keyexpimp.c:72-78`: `EVP_DigestUpdate(mac, iv, ivlen)` then
   `EVP_DigestUpdate(mac, shared_key, shared_len)`, finalized via
   `EVP_DigestFinalXOF(mac, mac_buf, mac_len)`.
   `kexp15.go:127-139`: `omac.New(macBlock, p.macLen)` → `Write(iv)` →
   `Write(sharedKey)` → `Sum(nil)`.
   - **Truncation is plain leftmost-bytes**: the engine computes the full
     `block`-byte CMAC tag and `memcpy`s the first `dgst_size` bytes
     (`tmp/engine/gost_omac.c:95`: `memcpy(md, mac, c->dgst_size)`). Our
     `omac.New` returns `state[:tagSize]` on `Sum`. No big/little-endian
     reordering on truncation — the leading bytes of the CBC chain value.

3. **CTR-encrypt `S || CEK_MAC`** with `K_Exp_ENC` and `iv_full`.
   `gost_keyexpimp.c:89-94`: two `EVP_CipherUpdate` calls — first the
   `shared_key`, then `mac_buf` — over a single CTR stream (one cipher init,
   one continuous keystream). `kexp15.go:141-151` concatenates
   `S || CEK_MAC` into one plaintext buffer and XORs it with one CTR stream.
   Output length is exactly `len(S) + mac_len`.

### OMAC / CMAC subkeys (R 34.13-2015 / RFC 4493)

OMAC here is RFC 4493 CMAC over the GOST block cipher. Subkeys:

- `L = E_K(0^block)`.
- `K1 = (L << 1) XOR (Rb if MSB(L)==1)`, `K2 = (K1 << 1) XOR (Rb if MSB(K1)==1)`.
- Reduction constant `Rb`:
  - Kuznyechik (128-bit): `0x87` (x^128 + x^7 + x^2 + x + 1) — RFC 4493 §2.3.
  - Magma (64-bit): `0x1b` (x^64 + x^4 + x^3 + x + 1) — RFC 8645 §4.1.1.
- Final block: if exactly one full block of unprocessed data remains, XOR with
  `K1`; otherwise pad with `0x80 00…` and XOR with `K2`, then run one more CBC
  step. The leftmost `mac_len` bytes of the resulting chain value are the tag.
  (`omac/omac.go`.)

For TLS the MAC input is `IV || S` = 36 bytes (Magma, IV=4 + S=32) or 40 bytes
(Kuznyechik, IV=8 + S=32), i.e. a non-block-multiple → always the `K2` /
0x80-pad path.

### CTR counter (R 34.13-2015)

- Counter is the full block, **big-endian increment**: the last byte increments
  first, carry propagates toward index 0 (`ctracpkm/ctracpkm.go`, matching
  gost-engine `ctr128_inc` / `ctr64_inc`).
- The keystream block `i` is `E_K(counter)`; counter is incremented **after**
  each block is generated.
- **No ACPKM** in kexp15: the wrapped payload (≤ 48 bytes) never crosses a
  rekey section. Use plain `ctracpkm.NewCTR`, not `NewCTRACPKM`.

## RFC ↔ implementation deltas

Each delta below is a place where a fresh implementer can go wrong; both the
RFC clause and the source line are cited.

1. **IV occupies the LOW bytes of the counter, remainder zero — not centered,
   not high.** RFC 9189 §8.2.1 says "IV" without specifying placement in the
   CTR counter block. gost-engine resolves it: `memset(iv_full,0,16);
   memcpy(iv_full, iv, ivlen)` (`tmp/engine/gost_keyexpimp.c:63-64`) — IV first,
   zeros after. `kexp15.go:122-125`. Getting this backwards (zeros first) is
   the most common reimplementation bug and produces a completely different
   keystream.

2. **MAC is over `IV || S`, encryption is over `S || CEK_MAC` — the IV is NOT
   encrypted and the order differs between the two layers.** RFC 9189 §8.2.1
   step 1 hashes `IV | S`; step 2 encrypts `S | CEK_MAC`. The IV appears only
   as MAC prefix; it is never part of the ciphertext (it travels separately, in
   TLS as part of the UKM). Engine: MAC update order is `iv` then `shared_key`
   (`gost_keyexpimp.c:75-76`); cipher update order is `shared_key` then
   `mac_buf` (`gost_keyexpimp.c:92-93`). `kexp15.go:127-151`.

3. **`K_Exp_MAC` keys the MAC, `K_Exp_ENC` keys the CTR — do not swap them.**
   Each is fed to a *separate* block-cipher instance: `macBlock` from `macKey`,
   `ctrBlock` from `cipherKey` (`kexp15.go:128,148`). In the TLS call site
   the 64-byte KEG output is split `expkeys[:32]=mac_key`,
   `expkeys[32:]=cipher_key`. Swapping them passes no test and fails the live
   handshake.

4. **MAC truncation is leftmost bytes of the full CMAC tag — no endianness
   flip.** The engine computes the full `block`-byte CMAC, then
   `memcpy(md, mac, dgst_size)` (`tmp/engine/gost_omac.c:95`). It does NOT
   reverse byte order on truncation (unlike some GOST contexts where values are
   little-endian). Magma keeps the leftmost 8 of the 8-byte tag (i.e. the whole
   tag); Kuznyechik keeps the leftmost 16 of 16 (whole tag) — so in *both* TLS
   variants `mac_len == block`, meaning no actual truncation happens at the TLS
   call. Truncation logic still matters if you reuse the primitive with a
   shorter `mac_len`.

5. **OMAC `EVP_DigestFinalXOF` is finalize-on-copy and non-destructive.** The
   engine MAC is an EVP XOF digest; finalization copies the context. Our
   `omac.Sum` snapshots state and does not mutate the receiver. This matters if
   you build the MAC incrementally and reuse the context — see CLAUDE.md "GOST
   IMIT MAC — EVP streaming semantics" (finalize-on-copy). For kexp15 it is a
   single `Write,Write,Sum` so the gotcha does not bite, but a naive
   reimplementation that mutates state in `Sum` would break if extended.

6. **No CryptoPro key meshing, no ACPKM in kexp15.** The third known
   gogost↔engine divergence (TODO.md: CryptoPro key meshing every 1024 bytes,
   `gost_crypt.c:1510-1524`) does **not** apply here: the MAC processes ≤ 40
   bytes and the CTR processes ≤ 48 bytes, both far below the 1024-byte mesh
   threshold and below any ACPKM section size (4096 Kuznyechik / 1024 Magma).
   A reimplementer should use the *raw* OMAC and *raw* CTR (no meshing), exactly
   as `kexp15.go` does. The other two TODO.md divergences (R 34.11-94
   empty-input finalization, S-box row order) are irrelevant: kexp15 uses no
   Streebog/R34.11 hashing, and the block cipher S-box order is internal to the
   block cipher (Kuznyechik/Magma) and cancels out — net cipher output matches
   the engine bit-for-bit (verified by the Magma etalon below).

7. **CTR is a single continuous stream across the `S` | `MAC` boundary.** The
   engine issues two `EVP_CipherUpdate` calls but on one initialized cipher
   context, so the keystream does not reset at the boundary
   (`gost_keyexpimp.c:91-93`). Our code XORs one contiguous `S || CEK_MAC`
   buffer with one CTR stream (`kexp15.go:141-151`). Do **not** re-init the
   counter for the MAC bytes.

8. **Counter increment is big-endian (last byte first).** RFC 9189 leaves
   "CTR-Encrypt" to R 34.13-2015. GOST CTR increments the full block
   big-endian (`ctracpkm/ctracpkm.go`). A little-endian increment desyncs from
   block 2 onward — invisible on a 16-byte payload (single block), but Magma's
   40-byte output spans 5 blocks and Kuznyechik's 48-byte output spans 3, so a
   wrong increment is caught by the Magma etalon.

## Test vectors

### Existing tests

Tests live in `kexp15/kexp15_test.go` (no build tags required):

- `TestKexp15_Magma_EngineEtalon` — the authoritative Magma KAT, taken verbatim
  from gost-engine `tmp/engine/test_keyexpimp.c:47-76`.
- `TestKexp15_Magma_RFC9189` — the published Magma vector from RFC 9189
  Appendix A.1.3.1 (TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC, rfc9189.txt:2353-2365).
- `TestKexp15_Kuznyechik_RFC9189` — the published Kuznyechik vector from
  RFC 9189 Appendix A.1.3.2 (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC,
  rfc9189.txt:3188-3201).
- `TestKexp15_Kuznyechik_Smoke` — output length and determinism for the
  Kuznyechik path with distinct input.
- `TestKexp15_ErrorCases` — input validation (empty `S`, wrong key/IV lengths,
  bad variant).

Differential fuzz testing against the gogost-backed oracle lives in
`../gostcrypto-compat/parity/kexp15/kexp15_parity_test.go` (the mandated
location per the workspace CLAUDE.md license-boundary design).

### Complete Magma KAT (runnable immediately)

Source: `tmp/engine/test_keyexpimp.c:47-76`. Variant = Magma
(`iv_len=4, mac_len=8, block=8`).

```
S  (shared_key, 32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
K_Exp_ENC (magma_key): 202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637
K_Exp_MAC (mac key):   08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f
IV (4B):               67bed654

KExp15(Magma, S, K_Exp_ENC, K_Exp_MAC, IV) =  (40 bytes)
  cfd5a12d5b81b6e1 e99c916d07900c6a c12703fb3abded55 567bf3742c899c75 5dafe7b42e3a8bd9
```

Intermediate (derivable, useful for stepwise debugging):
- `iv_full = 67bed654 00000000` (IV in low 4 bytes, zero pad).
- The last 8 bytes of the output (`5dafe7b42e3a8bd9`) are
  `CTR-Encrypt` of `CEK_MAC = OMAC(K_Exp_MAC, IV||S)[:8]`; the first 32 bytes
  are `CTR-Encrypt(S)`.

To run:
```sh
go test -run TestKexp15_Magma_EngineEtalon ./kexp15/ -v
```
(Pass `dangerouslyDisableSandbox: true` per CLAUDE.md when running `go test`.)

### Cross-checking the OMAC and CTR layers independently

Use the gost-engine OpenSSL 3 CLI (CLAUDE.md "CLI oracles") to verify each
layer in isolation against the same inputs:

```sh
# Magma OMAC tag over (IV||S):
OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
/opt/homebrew/opt/openssl@3/bin/openssl dgst -engine gost \
  -mac magma-mac -macopt hexkey:08090a0b...1c1d1e1f /path/to/iv_concat_S.bin
# Magma CTR keystream over (S||MAC) with iv_full (8B):
OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
/opt/homebrew/opt/openssl@3/bin/openssl enc -engine gost \
  -magma-ctr -K 2021...3637 -iv 67bed654 -in /path/to/plain.bin
```

## Re-implementation checklist

Each step is independently verifiable against a vector.

1. **Variant params.** Map `Kuznyechik → {block:16, iv_len:8, mac_len:16}` and
   `Magma → {block:8, iv_len:4, mac_len:8}`. Validate the input lengths:
   `cipherKey == 32`, `macKey == 32`, `len(iv) == iv_len`, `len(S) >= 1`.
   Test: error cases (`TestKexp15_ErrorCases`).

2. **Block cipher.** Obtain a `cipher.Block` for Kuznyechik (R 34.12-2015,
   128-bit) and Magma (64-bit). Verify with R 34.13-2015 §A.1.1 / §A.2.1
   single-block KATs before going further.

3. **OMAC1/CMAC.** Implement CMAC over the block cipher with `Rb=0x87`
   (128-bit) / `Rb=0x1b` (64-bit), subkeys `K1`/`K2`, `0x80` padding,
   leftmost-`mac_len` truncation, non-destructive `Sum`. Verify against
   R 34.13-2015 OMAC KATs (or the repo's `omac/omac_test.go`).

4. **CTR.** Implement R 34.13-2015 CTR with full-block big-endian counter
   increment, counter incremented after each keystream block, one continuous
   stream. Verify against R 34.13-2015 §A.1.2 / §A.2.2 CTR KATs.

5. **Build `iv_full`.** Allocate `block` zero bytes; copy `iv` into the front.
   (Low bytes = IV, high bytes = 0.)

6. **Compute `CEK_MAC`.** `OMAC(macKey)` over `iv` then `S`; take leftmost
   `mac_len` bytes.

7. **Encrypt.** `CTR-Encrypt(cipherKey, iv_full)` of the contiguous buffer
   `S || CEK_MAC`. Output is `len(S) + mac_len` bytes.

8. **Validate end-to-end** against the Magma etalon above
   (`cfd5a12d…2e3a8bd9`), then against the RFC 9189 vectors
   (A.1.3.1 Magma, A.1.3.2 Kuznyechik).

## Conformance & fuzz testing

This primitive has **no gogost equivalent** — gogost ships no `kexp15` API,
only the raw block ciphers our envelope sits on top of. The clean-room
implementation is validated by:

1. **Pinned KATs** in `kexp15/kexp15_test.go`:
   - The gost-engine Magma etalon (`tmp/engine/test_keyexpimp.c:47-76`).
   - RFC 9189 Appendix A.1.3.1 Magma vector (`rfc9189.txt:2353-2365`).
   - RFC 9189 Appendix A.1.3.2 Kuznyechik vector (`rfc9189.txt:3188-3201`).

2. **Differential fuzz** in `../gostcrypto-compat/parity/kexp15/kexp15_parity_test.go`
   (`FuzzKexp15Conformance`): fuzzes both variants, arbitrary-length `S`,
   32-byte cipher/MAC keys, variant-sized IVs against the in-repo oracle.
   This is the mandated location per the workspace license-boundary design.

### Run commands

```sh
# In-module tests (no build tags needed):
go test -run TestKexp15 ./kexp15/ -v

# Parity gate (from workspace root or gostcrypto-compat dir):
( cd ../gostcrypto-compat && go test ./parity/kexp15/ -v )
```

(Pass `dangerouslyDisableSandbox: true` per CLAUDE.md when running `go test`.)

## References

- **R 1323565.1.017-2018** — TC26 recommendation defining KExp15 / KImp15.
- **RFC 9189**, "GOST Cipher Suites for TLS Protocol Version 1.2", §8.1
  (TLSTREE) and **§8.2.1** (KExp15 / KImp15 algorithms); assigns suites
  0xC100 (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`) and 0xC101
  (`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`).
  `kexp15/rfc/rfc9189.txt`
- **RFC 9367**, "GOST Cipher Suites for Transport Layer Security (TLS) Protocol
  Version 1.3"; suites 0xC103–0xC106 use MGM AEAD (not KExp15).
  `kexp15/rfc/rfc9367.txt`
- **RFC 4493**, "The AES-CMAC Algorithm" — CMAC subkeys and `Rb=0x87`.
  `kexp15/rfc/rfc4493.txt`
- **RFC 8645**, "Re-keying Mechanisms for Symmetric Keys" — `Rb=0x1b` for the
  64-bit block; ACPKM background. `kexp15/rfc/rfc8645.txt`
- **GOST R 34.12-2015** — Kuznyechik (128-bit) and Magma (64-bit) block ciphers.
- **GOST R 34.13-2015** — block cipher modes (CTR, OMAC/CMAC) and their KATs.

Key source citations:
- `kexp15/kexp15.go:98-152` — `Kexp15` envelope.
- `kexp15/kexp15.go:70-89` — variant params.
- `omac/omac.go` — OMAC1/CMAC (subkeys, padding, truncation).
- `ctracpkm/ctracpkm.go` — CTR (counter, big-endian increment).
- `kexp15/kexp15_test.go` — KATs (Magma engine etalon, RFC 9189 A.1.3.1, A.1.3.2).
- `tmp/engine/gost_keyexpimp.c:34-109` — `gost_kexp15` ground truth.
- `tmp/engine/gost_keyexpimp.c:115-199` — `gost_kimp15` (inverse + MAC compare).
- `tmp/engine/gost_omac.c:82-97,214-230` — engine OMAC final + XOF length /
  truncation.
- `tmp/engine/test_keyexpimp.c:47-76,134-136` — Magma KAT inputs/output.
