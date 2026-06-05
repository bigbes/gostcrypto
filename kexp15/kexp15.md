# KExp15 / KImp15 key export wrapping (R 1323565.1.017-2018)

## What it is

KExp15 is the GOST **key-transport envelope**: it wraps a secret key `S`
(typically a 32-byte pre-master / session key) so that it can be carried over
the wire authenticated and encrypted under two independent export keys. KImp15
is the exact inverse (decrypt, then verify the MAC).

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

The construction is **OMAC-then-CTR**:

```
CEK_MAC = OMAC(K_Exp_MAC, IV || S)            (truncated to mac_len)
SExp    = CTR-Encrypt(K_Exp_ENC, IV_full, S || CEK_MAC)
```

- Standard identity: **R 1323565.1.017-2018** (the Russian TC26 export-key
  recommendation). Referenced normatively by:
  - **RFC 9189 §8.2.1** ("KExp15 and KImp15 algorithms"), which defines the
    construction for the GOST 2012 TLS 1.2 cipher suites.
  - **RFC 9367** (GOST 2012 cipher suites for TLS 1.2, the RFC 9189 successor
    used by the 0xC100 / 0xC101 suites) re-uses the same envelope.
- Block-cipher variants (R 34.12-2015):
  - **Kuznyechik** — 128-bit block. `iv_len = 8`, `mac_len = 16`, `block = 16`.
  - **Magma** — 64-bit block. `iv_len = 4`, `mac_len = 8`, `block = 8`.

### Where this repo uses it

- `internal/gost/kexp15_gost.go` — `Kexp15(variant, sharedKey, cipherKey, macKey, iv)`
  and the `KexpVariant` enum (`KexpKuznyechik`, `KexpMagma`). This is the
  primitive being documented.
- The single call site is the GOST 2018 key exchange:
  `tls/internal/ke/gost2018.go:202`
  ```go
  wrapped, err := gost.Kexp15(kexpVariant(e.variant), preMaster, expkeys[32:], expkeys[:32], iv)
  ```
  Here `expkeys` is the 64-byte output of `KEG2012_256` (VKO + KDFTREE), split
  as `expkeys[:32] = mac_key (K_Exp_MAC)` and `expkeys[32:] = cipher_key
  (K_Exp_ENC)`. The `iv` is `ukm[24 : 24+iv_len]`
  (`tls/internal/ke/gost2018.go:197`). The wrapped output becomes the `psexp`
  field of the `PSKeyTransport_gost` ASN.1 structure
  (`gost2018.go:207-209`) sent in ClientKeyExchange.
- These suites are RFC 9367 0xC100 (Kuznyechik-CTR-OMAC) and 0xC101
  (Magma-CTR-OMAC), plus the RFC 9189 GOST2012 suites.

### Status

**in-repo-reimpl.** `internal/gost/kexp15_gost.go` implements the envelope
itself in Go: it does the IV padding, the OMAC call, the concatenation, and the
CTR call directly, using the repo's own `internal/gost.OMAC`
(`internal/gost/omac.go`) and `internal/gost.CTR` (`internal/gost/ctr_gost.go`)
— both already license-clean reimplementations. The **only** gogost dependency
in the kexp15 file is the raw block cipher: `gost3412128.NewCipher` /
`gost341264.NewCipher` (`internal/gost/kexp15_gost.go:22-23,96-100`). Once a
license-clean Kuznyechik/Magma block cipher exists (TODO.md "BSD
reimplementation of gogost primitives", item 1), this file imports zero gogost.

The C ground truth is gost-engine's `gost_kexp15`
(`tmp/engine/gost_keyexpimp.c:34-109`), which is what the Go code mirrors
line-for-line.

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

Step by step, as implemented (`internal/gost/kexp15_gost.go:87-130`, matching
`tmp/engine/gost_keyexpimp.c:62-98`):

1. **Build the full counter from the half-IV.**
   Allocate `iv_full = block` zero bytes, copy `IV` into the **front** (low
   indices), leave the back zero.
   `gost_keyexpimp.c:63-64`: `memset(iv_full, 0, 16); memcpy(iv_full, iv, ivlen);`
   `kexp15_gost.go:89-90`. So Kuznyechik `iv_full = IV(8) || 00·8`,
   Magma `iv_full = IV(4) || 00·4`.

2. **Compute the MAC over `IV || S`** with `K_Exp_MAC`, using OMAC1/CMAC of the
   block cipher, then truncate to the leftmost `mac_len` bytes.
   `gost_keyexpimp.c:72-78`: `EVP_DigestUpdate(mac, iv, ivlen)` then
   `EVP_DigestUpdate(mac, shared_key, shared_len)`, finalized via
   `EVP_DigestFinalXOF(mac, mac_buf, mac_len)`.
   `kexp15_gost.go:105-115`: `NewOMAC(macBlock, mac_len)` → `Write(iv)` →
   `Write(sharedKey)` → `Sum(nil)`.
   - **Truncation is plain leftmost-bytes**: the engine computes the full
     `block`-byte CMAC tag and `memcpy`s the first `dgst_size` bytes
     (`tmp/engine/gost_omac.c:95`: `memcpy(md, mac, c->dgst_size)`). Our
     `OMAC.Sum` returns `state[:tagSize]` (`omac.go:164`). No big/little-endian
     reordering on truncation — the leading bytes of the CBC chain value.

3. **CTR-encrypt `S || CEK_MAC`** with `K_Exp_ENC` and `iv_full`.
   `gost_keyexpimp.c:89-94`: two `EVP_CipherUpdate` calls — first the
   `shared_key`, then `mac_buf` — over a single CTR stream (one cipher init,
   one continuous keystream). `kexp15_gost.go:117-128` concatenates
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
  (`internal/gost/omac.go:142-165`.)

For TLS the MAC input is `IV || S` = 36 bytes (Magma, IV=4 + S=32) or 40 bytes
(Kuznyechik, IV=8 + S=32), i.e. a non-block-multiple → always the `K2` /
0x80-pad path.

### CTR counter (R 34.13-2015)

- Counter is the full block, **big-endian increment**: the last byte increments
  first, carry propagates toward index 0 (`internal/gost/ctr_gost.go:167-174`,
  matching gost-engine `ctr128_inc` / `ctr64_inc`).
- The keystream block `i` is `E_K(counter)`; counter is incremented **after**
  each block is generated (`ctr_gost.go:152-155`).
- **No ACPKM** in kexp15: the wrapped payload (≤ 48 bytes) never crosses a
  rekey section. Use plain `NewCTR`, not `NewCTRACPKM`.

## RFC ↔ implementation deltas

Each delta below is a place where a fresh implementer can go wrong; both the
RFC clause and the source line are cited.

1. **IV occupies the LOW bytes of the counter, remainder zero — not centered,
   not high.** RFC 9189 §8.2.1 says "IV" without specifying placement in the
   CTR counter block. gost-engine resolves it: `memset(iv_full,0,16);
   memcpy(iv_full, iv, ivlen)` (`tmp/engine/gost_keyexpimp.c:63-64`) — IV first,
   zeros after. `kexp15_gost.go:89-90`. Getting this backwards (zeros first) is
   the most common reimplementation bug and produces a completely different
   keystream.

2. **MAC is over `IV || S`, encryption is over `S || CEK_MAC` — the IV is NOT
   encrypted and the order differs between the two layers.** RFC 9189 §8.2.1
   step 1 hashes `IV | S`; step 2 encrypts `S | CEK_MAC`. The IV appears only
   as MAC prefix; it is never part of the ciphertext (it travels separately, in
   TLS as part of the UKM). Engine: MAC update order is `iv` then `shared_key`
   (`gost_keyexpimp.c:75-76`); cipher update order is `shared_key` then
   `mac_buf` (`gost_keyexpimp.c:92-93`). `kexp15_gost.go:109-121`.

3. **`K_Exp_MAC` keys the MAC, `K_Exp_ENC` keys the CTR — do not swap them.**
   Each is fed to a *separate* block-cipher instance: `macBlock` from `macKey`,
   `ctrBlock` from `cipherKey` (`kexp15_gost.go:96-100`). In the TLS call site
   the 64-byte KEG output is split `expkeys[:32]=mac_key`,
   `expkeys[32:]=cipher_key` (`gost2018.go:189-202`, engine
   `gost_ec_keyx.c` `gost_kexp15(..., cipher_nid, expkeys+32, mac_nid,
   expkeys+0, ...)`). Swapping them passes no test and fails the live
   handshake.

4. **MAC truncation is leftmost bytes of the full CMAC tag — no endianness
   flip.** The engine computes the full `block`-byte CMAC, then
   `memcpy(md, mac, dgst_size)` (`tmp/engine/gost_omac.c:95`). It does NOT
   reverse byte order on truncation (unlike some GOST contexts where values are
   little-endian). Our `OMAC.Sum` returns `stateSnap[:tagSize]`
   (`omac.go:164`). Magma keeps the leftmost 8 of the 8-byte tag (i.e. the whole
   tag); Kuznyechik keeps the leftmost 16 of 16 (whole tag) — so in *both* TLS
   variants `mac_len == block`, meaning no actual truncation happens at the TLS
   call. Truncation logic still matters if you reuse the primitive with a
   shorter `mac_len`.

5. **OMAC `EVP_DigestFinalXOF` is finalize-on-copy and non-destructive.** The
   engine MAC is an EVP XOF digest; `EVP_MD_CTRL_XOF_LEN` sets `dgst_size` up
   front (`gost_keyexpimp.c:74`, `gost_omac.c:214-230`), and finalization
   copies the context. Our `OMAC.Sum` snapshots `state`/`buf` and does not
   mutate the receiver (`omac.go:142-165`). This matters if you build the MAC
   incrementally and reuse the context — see CLAUDE.md "GOST IMIT MAC — EVP
   streaming semantics" (finalize-on-copy). For kexp15 it is a single
   `Write,Write,Sum` so the gotcha does not bite, but a naive reimplementation
   that mutates state in `Sum` would break if extended.

6. **No CryptoPro key meshing, no ACPKM in kexp15.** The third known
   gogost↔engine divergence (TODO.md: CryptoPro key meshing every 1024 bytes,
   `gost_crypt.c:1510-1524`) does **not** apply here: the MAC processes ≤ 40
   bytes and the CTR processes ≤ 48 bytes, both far below the 1024-byte mesh
   threshold and below any ACPKM section size (4096 Kuznyechik / 1024 Magma).
   A reimplementer should use the *raw* OMAC and *raw* CTR (no meshing), exactly
   as `kexp15_gost.go` does. The other two TODO.md divergences (R 34.11-94
   empty-input finalization, S-box row order) are irrelevant: kexp15 uses no
   Streebog/R34.11 hashing, and the block cipher S-box order is internal to the
   block cipher (Kuznyechik/Magma) and cancels out — net cipher output matches
   the engine bit-for-bit (verified by the Magma etalon below).

7. **CTR is a single continuous stream across the `S` | `MAC` boundary.** The
   engine issues two `EVP_CipherUpdate` calls but on one initialized cipher
   context, so the keystream does not reset at the boundary
   (`gost_keyexpimp.c:91-93`). Our code XORs one contiguous `S || CEK_MAC`
   buffer with one `CTR` (`kexp15_gost.go:119-128`). Do **not** re-init the
   counter for the MAC bytes.

8. **Counter increment is big-endian (last byte first).** RFC 9189 leaves
   "CTR-Encrypt" to R 34.13-2015. GOST CTR increments the full block
   big-endian (`ctr_gost.go:167-174`). A little-endian increment desyncs from
   block 2 onward — invisible on a 16-byte payload (single block), but Magma's
   40-byte output spans 5 blocks and Kuznyechik's 48-byte output spans 3, so a
   wrong increment is caught by the Magma etalon.

## Test vectors

### Existing tests

- `internal/gost/kexp15_gost_test.go:TestKexp15_Magma_EngineEtalon` — the
  authoritative Magma KAT, taken verbatim from gost-engine
  `tmp/engine/test_keyexpimp.c:47-76`.
- `TestKexp15_ErrorCases` — input validation (empty `S`, wrong key/IV lengths,
  bad variant).
- `TestKexp15_Kuznyechik_EngineOracle` — **skipped**: no published Kuznyechik
  kexp15 vector exists in `tmp/engine/test_keyexpimp.c` (only the Magma path is
  exercised by the C `main()` at `test_keyexpimp.c:134-136`). See TODO.md
  "Skipped — not in scope". The Kuznyechik path shares the same code, validated
  indirectly by the Magma etalon plus the standalone Kuznyechik OMAC/CTR KATs in
  `omac_*_test.go` / `ctr_test.go`.

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
go test -tags gost -run TestKexp15_Magma_EngineEtalon ./internal/gost/ -v
```
(Pass `dangerouslyDisableSandbox: true` per CLAUDE.md when running `go test`.)

### Cross-checking the OMAC and CTR layers independently

Use the gost-engine OpenSSL 3 CLI (CLAUDE.md "CLI oracles") to verify each
layer in isolation against the same inputs:

```sh
# Magma OMAC tag over (IV||S):
/opt/homebrew/opt/openssl@3/bin/openssl dgst -engine gost \
  -mac magma-mac -macopt hexkey:08090a0b...1c1d1e1f /path/to/iv_concat_S.bin
# Magma CTR keystream over (S||MAC) with iv_full (8B):
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
   R 34.13-2015 OMAC KATs (or the repo's `omac_*_test.go`).

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
   (`cfd5a12d…2e3a8bd9`). Then implement KImp15 (CTR-decrypt, recompute OMAC,
   constant-time compare the trailing `mac_len` bytes — engine uses
   `CRYPTO_memcmp`, `gost_keyexpimp.c:186`) and round-trip
   `KImp15(KExp15(S)) == S`.

## Conformance & fuzz testing

This primitive has **no gogost equivalent** — gogost ships no `kexp15` API,
only the raw block ciphers our envelope sits on top of (see Status above). So
the clean-room implementer (`mynew` below) differential-tests against two
references: the **pinned Magma etalon** from this doc (and the engine's C KAT
it was lifted from, `tmp/engine/test_keyexpimp.c:47-76`) for exact equality,
and — for randomized inputs where no precomputed vector exists — a **round-trip
oracle**: `mynew.Kexp15` must agree with this repo's `internal/gost.Kexp15`
(the in-repo reference, `internal/gost/kexp15_gost.go:68`) byte-for-byte. There
is no in-repo `KImp15`, so "round-trip" is asserted as
`mynew.Kexp15(...) == gost.Kexp15(...)` over fuzzed shared/cipher/MAC keys + IV
for **both** the Magma and Kuznyechik variants; the only fixed-output anchor is
the Magma etalon, since the engine's C `main()` exercises only the Magma path
(`tmp/engine/test_keyexpimp.c:134-136`). For an independent third opinion on a
single layer you can shell out to the gost-engine OpenSSL 3 CLI oracle
(`magma-mac` / `magma-ctr`, see CLAUDE.md "CLI oracles" and the helper below) —
but the CLI computes OMAC and CTR *separately*, not the assembled envelope, so
it cross-checks layers rather than the whole `Kexp15`.

### KAT conformance test

Seeded with the exact pinned Magma vector from "Complete Magma KAT" above
(`tmp/engine/test_keyexpimp.c:47-76`). Asserts both `mynew.Kexp15` and the
in-repo `gost.Kexp15` reproduce the etalon output.

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"encoding/hex"
	"testing"

	gost "go.bigb.es/tlsdialer/internal/gost"
	mynew "your.module/path/to/cleanroom" // clean-room reimplementation
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestKexp15Conformance(t *testing.T) {
	cases := []struct {
		name                          string
		variant                       gost.KexpVariant
		shared, cipherKey, macKey, iv string
		want                          string
	}{
		{
			// tmp/engine/test_keyexpimp.c:47-76 (Magma etalon).
			name:      "magma/engine-etalon",
			variant:   gost.KexpMagma,
			shared:    "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			cipherKey: "202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637",
			macKey:    "08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f",
			iv:        "67bed654",
			want:      "cfd5a12d5b81b6e1e99c916d07900c6ac12703fb3abded55567bf3742c899c755dafe7b42e3a8bd9",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shared := mustHex(t, tc.shared)
			cipherKey := mustHex(t, tc.cipherKey)
			macKey := mustHex(t, tc.macKey)
			iv := mustHex(t, tc.iv)
			want := mustHex(t, tc.want)

			// In-repo reference (internal/gost/kexp15_gost.go:68).
			ref, err := gost.Kexp15(tc.variant, shared, cipherKey, macKey, iv)
			if err != nil {
				t.Fatalf("gost.Kexp15: %v", err)
			}
			if !bytes.Equal(ref, want) {
				t.Fatalf("reference disagrees with pinned vector:\n got  %x\n want %x", ref, want)
			}

			// Clean-room implementation under test.
			got, err := mynew.Kexp15(mynew.KexpVariant(tc.variant), shared, cipherKey, macKey, iv)
			if err != nil {
				t.Fatalf("mynew.Kexp15: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("clean-room mismatch:\n got  %x\n want %x", got, want)
			}
		})
	}
}
```

### Fuzz harness (differential, both variants)

Seeds the corpus from the KAT inputs, then for each fuzz input normalizes the
random `[]byte` slices into this primitive's fixed-size arguments (32-byte
cipher/MAC keys, variant-sized IV — `iv_len = block/2`: 4 for Magma, 8 for
Kuznyechik — and a non-empty `S`). Runs the clean-room impl and the in-repo
reference on **identical** inputs and `t.Fatalf`s on any divergence. Because
there is no in-repo unwrap, equality against the reference *is* the round-trip
property here.

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"testing"

	gost "go.bigb.es/tlsdialer/internal/gost"
	mynew "your.module/path/to/cleanroom"
)

// fixKey clamps b to exactly n bytes (zero-padded / truncated).
func fixKey(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func FuzzKexp15Conformance(f *testing.F) {
	// Seed from the Magma KAT (tmp/engine/test_keyexpimp.c:47-76).
	f.Add(
		mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		mustHexF("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"),
		mustHexF("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"),
		mustHexF("67bed654"),
		false, // variant selector: false = Magma, true = Kuznyechik
	)

	f.Fuzz(func(t *testing.T, shared, cipherRaw, macRaw, ivRaw []byte, kuz bool) {
		if len(shared) == 0 {
			shared = []byte{0x01} // S must be non-empty
		}
		variant := gost.KexpMagma
		ivLen := 4
		if kuz {
			variant = gost.KexpKuznyechik
			ivLen = 8
		}
		cipherKey := fixKey(cipherRaw, 32)
		macKey := fixKey(macRaw, 32)
		iv := fixKey(ivRaw, ivLen)

		ref, errRef := gost.Kexp15(variant, shared, cipherKey, macKey, iv)
		got, errGot := mynew.Kexp15(mynew.KexpVariant(variant), shared, cipherKey, macKey, iv)

		if (errRef == nil) != (errGot == nil) {
			t.Fatalf("error mismatch: ref=%v mynew=%v", errRef, errGot)
		}
		if errRef != nil {
			return
		}
		if !bytes.Equal(ref, got) {
			t.Fatalf("differential mismatch (kuz=%v):\n ref   %x\n mynew %x", kuz, ref, got)
		}
	})
}
```

`mustHexF` is the package-level `hex.DecodeString` helper (panicking on bad
input, since seed literals are static) — define it once alongside `mustHex`.

For a layer-level cross-check against the engine when a whole-envelope
disagreement appears, shell out to the OpenSSL 3 gost-engine oracle rather
than importing anything (no gogost/OpenSSL `Kexp15` API exists):

```go
// engineMagmaOMAC returns the gost-engine magma-mac tag over data under macKey.
// Layer oracle only — the CLI has no assembled-envelope command.
func engineMagmaOMAC(t *testing.T, macKey, data []byte) []byte {
	t.Helper()
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		"/opt/homebrew/opt/openssl@3/bin/openssl", "dgst",
		"-engine", "gost", "-mac", "magma-mac",
		"-macopt", "hexkey:"+hex.EncodeToString(macKey), in,
	)
	cmd.Env = append(os.Environ(),
		"OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("engine magma-mac: %v", err)
	}
	// Output form: "MAC(stdin)= <hex>\n"; take the trailing hex field.
	fields := bytes.Fields(out)
	tag, err := hex.DecodeString(string(fields[len(fields)-1]))
	if err != nil {
		t.Fatalf("parse engine tag: %v", err)
	}
	return tag
}
```

(Imports for the oracle helper: `os`, `os/exec`, `path/filepath`,
`encoding/hex`, `bytes`.)

### Run commands

```sh
go test -tags gost -run TestKexp15Conformance ./yourpkg/
go test -tags gost -fuzz=FuzzKexp15Conformance -fuzztime=30s ./yourpkg/
```

(Pass `dangerouslyDisableSandbox: true` per CLAUDE.md when running `go test`.)

## References

- **R 1323565.1.017-2018** — TC26 recommendation defining KExp15 / KImp15.
- **RFC 9189**, "GOST Cipher Suites for TLS 1.2", §8.1 (TLSTREE) and **§8.2.1**
  (KExp15 / KImp15 algorithms). https://github.com/bigbes/gostcrypto/blob/master/kexp15/rfc/rfc9189.txt
- **RFC 9367**, "GOST Cipher Suites for TLS 1.2" (successor; 0xC100 / 0xC101
  suites reuse the envelope). https://github.com/bigbes/gostcrypto/blob/master/kexp15/rfc/rfc9367.txt
- **RFC 4493**, "The AES-CMAC Algorithm" — CMAC subkeys and `Rb=0x87`.
  https://github.com/bigbes/gostcrypto/blob/master/kexp15/rfc/rfc4493.txt
- **RFC 8645**, "Re-keying Mechanisms for Symmetric Keys" — `Rb=0x1b` for the
  64-bit block; ACPKM background. https://github.com/bigbes/gostcrypto/blob/master/kexp15/rfc/rfc8645.txt
- **GOST R 34.12-2015** — Kuznyechik (128-bit) and Magma (64-bit) block ciphers.
- **GOST R 34.13-2015** — block cipher modes (CTR, OMAC/CMAC) and their KATs.

Key source citations:
- `internal/gost/kexp15_gost.go:68-131` — `Kexp15` envelope.
- `internal/gost/kexp15_gost.go:46-55` — variant params.
- `internal/gost/omac.go:40-165` — OMAC1/CMAC (subkeys, padding, truncation).
- `internal/gost/ctr_gost.go:55-174` — CTR (counter, big-endian increment).
- `internal/gost/kexp15_gost_test.go:40-59` — Magma etalon test.
- `tls/internal/ke/gost2018.go:189-209` — sole call site (KEG split, IV from UKM).
- `tmp/engine/gost_keyexpimp.c:34-109` — `gost_kexp15` ground truth.
- `tmp/engine/gost_keyexpimp.c:115-199` — `gost_kimp15` (inverse + MAC compare).
- `tmp/engine/gost_omac.c:82-97,214-230` — engine OMAC final + XOF length /
  truncation.
- `tmp/engine/test_keyexpimp.c:47-76,134-136` — Magma KAT inputs/output.
