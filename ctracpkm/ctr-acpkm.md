# CTR mode + ACPKM key meshing (RFC 8645)

This is a **clean-room re-implementation guide**. A reader must be able to
reimplement GOST CTR mode and ACPKM intra-record key meshing in Go *without*
reading `go.stargrave.org/gogost/v7` (GPL-3.0, vendored at
`third_party/gogost`), using only this document plus the cited RFCs.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

**Status: in-repo reimplementation.** This primitive is **not** sourced from
gogost. gogost's `gost3413` package contains only `padding.go` — it has no CTR
and no ACPKM. The repo provides its own CTR + ACPKM in
`internal/gost/ctr_gost.go` (`NewCTR`, `NewCTRACPKM`), layered over any
`crypto/cipher.Block` (the block cipher itself — Kuznyechik `gost3412128`,
Magma `gost341264` — still comes from gogost, but that is a *separate*
primitive with its own guide). The de-facto spec this file documents is the
behavioral contract in `internal/gost/ctr_gost.go`, cross-checked against
gost-engine v3.0.3 (Tarantool's upstream) and RFC 8645.

## What it is

GOST R 34.13-2015 **CTR (gamma counter) mode** turns a block cipher into a
stream cipher: each plaintext byte is XORed with a keystream ("gamma") byte.
The gamma is produced by encrypting a monotonically increasing counter block.

**ACPKM** ("Advanced Cryptographic Prolongation of Key Material",
RFC 8645 = draft-irtf-cfrg-re-keying) is an *internal re-keying* mechanism:
after every `N` bytes of keystream (one "section"), the cipher key is
transformed into a fresh key by encrypting a fixed public constant `D` under
the current key. The counter is **not** reset by ACPKM — only the key changes.
This bounds the amount of data processed under any single key without renewing
the master key.

### Where this repo uses it

- **TLS record protection for RFC 9367 GOST suites** — Kuznyechik-CTR-ACPKM
  + OMAC (TLS suite `0xC100`) and Magma-CTR-ACPKM + OMAC (`0xC101`). The
  protector is `ctrOMACProtector` in
  `tls/internal/record/protection_ctromac_gost.go`; it calls
  `gost.NewCTRACPKM` once per record in both `Seal` (line 205) and `Open`
  (line 250). Wire format: `CTR(plaintext) || CTR(OMAC-tag)` as one
  continuous keystream.
- **Plain CTR (no ACPKM)** is also used inside the kexp15 key-export wrapper:
  `internal/gost/kexp15_gost.go:123` calls `NewCTR`, and
  `internal/gost/primitives_gost.go:391` returns a plain CTR stream.

Per-suite section sizes wired in the protector:
`acpkmSection = 4096` for Kuznyechik
(`protection_ctromac_gost.go:99`, citing
`tmp/engine/gost_grasshopper_cipher.c:334`) and `1024` for Magma
(`protection_ctromac_gost.go:135`, citing `tmp/engine/gost_crypt.c:517`).

## Specification

### Sizes

| Quantity            | Kuznyechik (GOST 34.12 "Кузнечик") | Magma (GOST 34.12 "Магма") |
|---------------------|------------------------------------|----------------------------|
| Block size `n`      | 16 bytes (128 bit)                 | 8 bytes (64 bit)           |
| Key size `k`        | 32 bytes (256 bit)                 | 32 bytes (256 bit)         |
| CTR counter block   | 16 bytes                           | 8 bytes                    |
| TLS record IV/nonce | 8 bytes (= `n/2`)                  | 4 bytes (= `n/2`)          |
| ACPKM section `N`   | 4096 bytes (TLS) / per-protocol    | 1024 bytes (TLS)           |
| `D` length          | 32 bytes (= `k`)                   | 32 bytes (= `k`)           |
| `J` = `k/n`         | 2 encrypts per rekey               | 4 encrypts per rekey       |

### CTR mode (GOST R 34.13-2015 §5.3)

CTR produces gamma block `Γ_i = E_K(CTR_i)`, then `C_i = P_i ⊕ MSB(Γ_i)`.
The counter starts at an initial value and increments by 1 per block.

Counter layout for a fresh CTR stream (the GOST-R-34.13 "CTR" construction
used by the engine and this repo): the IV occupies the **high half** of the
counter block (`n/2` bytes) and the low half is the running counter starting
at zero:

```
CTR_0 = IV(n/2 bytes) || 0x00 * (n/2)
```

In this repo the *full* `n`-byte counter is supplied to `NewCTR` already
assembled (high half = nonce, low half = zeros). `internal/gost/ctr_test.go`
constructs it explicitly: an 8-byte engine `iv_ctr` zero-padded to 16 bytes
for Kuznyechik, a 4-byte IV zero-padded to 8 for Magma. The TLS protector
builds it in `adjustIV` (`protection_ctromac_gost.go:154`) by placing the
record nonce in the high `n/2` bytes and adding the 64-bit sequence number
into it (big-endian carry add), low half stays zero.

**Increment is big-endian** (last byte first, carry propagates toward the
low-indexed/high-order bytes). RFC 8645 / the GOST standard treat the counter
as a single big-endian integer over the whole block. Engine reference:
`inc_counter` (`tmp/engine/gost_grasshopper_cipher.c:581-594`) decrements the
byte index from the top, adds 1, returns when no wrap. `ctr128_inc`
(`:597-600`) and `ctr64_inc` (`tmp/engine/gost_crypt.c:807-810`) just call it
with `counter_bytes = 16` / `8`. Repo mirror: `incCounter`
(`internal/gost/ctr_gost.go:167-174`).

### ACPKM transformation (RFC 8645 §6.2.1)

Normative formula (RFC 8645 §6.2.1):

> `K^{i+1} = ACPKM(K^i) = MSB_k( E_{K^i}(D_1) | ... | E_{K^i}(D_J) )`
> where `J = ceil(k/n)`.

The constant `D` is the public 1024-bit string
`D = (80 | 81 | 82 | ... | fe | ff)` (sequential bytes `0x80`…`0xFF`). Each
`D_j` is the `j`-th `n`-byte block of `D`. Because here `k = 32` bytes, only
the **first 32 bytes** of `D` are ever used (`0x80`…`0x9F`):

```
D (32 bytes used) =
  80 81 82 83 84 85 86 87  88 89 8a 8b 8c 8d 8e 8f
  90 91 92 93 94 95 96 97  98 99 9a 9b 9c 9d 9e 9f
```

- Kuznyechik (`n=16`, `J=2`): new key = `E(D[0:16]) || E(D[16:32])`.
- Magma (`n=8`, `J=4`): new key =
  `E(D[0:8]) || E(D[8:16]) || E(D[16:24]) || E(D[24:32])`.

All `E(...)` use the **current** section key (the one being retired), and the
concatenation of the `J` ciphertext blocks (exactly 32 bytes) becomes the next
section key. `MSB_k` is a no-op here because the concatenation is already
exactly `k = 32` bytes.

Repo constant: `acpkmD` (`internal/gost/ctr_gost.go:32-37`). Engine constants:
`ACPKM_D_const` (`tmp/engine/gost89.c:247-252`, used by Magma) and
`ACPKM_D_2018` (`tmp/engine/gost_grasshopper_cipher.c:155-160`, used by
Kuznyechik) — **byte-for-byte identical**.

### ACPKM re-keying schedule (RFC 8645 §2 / §6.2.1)

The section size `N` MUST be a multiple of the block size `n` (RFC 8645
§6.2.1: "The section size N MUST be divisible by the block size n"). Plaintext
is split into sections of `N` bytes. Section 1 is encrypted under the initial
key `K^1 = K`; before encrypting section `i+1` the key is advanced
`K^{i+1} = ACPKM(K^i)`. The counter keeps running across section boundaries
(it is **never** reset by ACPKM).

`internal/gost/ctr_gost.go` requires `sectionSize % blockSize == 0`
(line 103) and `sectionSize == 0` disables ACPKM entirely, degrading to plain
CTR (`NewCTRACPKM(..., 0)` ≡ `NewCTR`; asserted by
`TestCTRACPKM_MatchesPlainCTR_WhenSectionZero`).

### ACPKM-Master (RFC 8645 §6.3.1) — informational

For deriving multiple keys (not used by the TLS suites but exercised by the
"master" KAT below):

> `K[1] | ... | K[l] = ACPKM-Master(T*, K, d, l) = CTR-ACPKM-Encrypt(T*, K, 1^{n/2}, 0^{d*l})`

i.e. run CTR-ACPKM with section size `T*` over a zero buffer of length
`d*l` bits, starting counter `1^{n/2}` (high half all-ones). The repo
`Kuznyechik-CTR-ACPKM-Master-96` test (`cipher_modes_test.go:176`) reproduces
exactly this: 144 zero bytes, IV = 8 bytes of `0xFF`, section size 96.

## RFC ↔ implementation deltas

Each delta cites BOTH the RFC and the source line. These are the points where
a naive reading of the RFC diverges from what gost-engine (and therefore this
repo, the parity target) actually does.

1. **Counter byte order is big-endian over the whole block, but the IV sits in
   the HIGH half.** RFC 8645 §6 writes counters as `1^{n/2}` etc. — the
   non-zero/initial part is the most-significant half, the counter runs in the
   least-significant half. A reimplementer who places the nonce in the low
   bytes (little-endian intuition — GOST is little-endian in *many* places,
   e.g. key/curve scalars) will get wrong gamma from block 2 onward.
   Reference: `adjustIV` lays nonce into `out[0:n/2]`, zeros `out[n/2:n]`
   (`protection_ctromac_gost.go:154-172`); increment touches the tail first
   (`incCounter`, `ctr_gost.go:167-174`; engine `inc_counter`,
   `gost_grasshopper_cipher.c:581-594`). The repo test
   `TestCTR_CounterIncrement` (`ctr_test.go:121`) pins this: block 2's gamma
   must equal a fresh CTR seeded at `IV+1`.

2. **ACPKM rekeys BEFORE generating the first block of the new section, not
   after the last block of the old one** — and the threshold is `>=`, evaluated
   at block boundaries. Engine `apply_acpkm_grasshopper`
   (`gost_grasshopper_cipher.c:660-667`) and `apply_acpkm_magma`
   (`gost_crypt.c:814-821`): `if (!section_size || *num < section_size) return;
   acpkm_next(); *num &= BLOCK_MASK;` — the check fires when the per-section
   byte counter `num` reaches `section_size`, *just before* the block encrypt
   inside the per-block loop. Repo mirror: `XORKeyStream`
   (`ctr_gost.go:140-156`) checks `c.sinceRekey >= c.sectionSize` at the top of
   each new-gamma-block path, rekeys, then resets `sinceRekey = 0`. Getting
   this off-by-one wrong (rekeying after, or using `>` ) shifts every section
   boundary and silently corrupts everything past the first section. Pinned by
   `Kuznyechik-CTR-ACPKM-32` (`cipher_modes_test.go:154`), section size 32, 112
   bytes = 3.5 sections.

3. **ACPKM does NOT reset the counter** — RFC 8645 §6.2.1 advances only the
   key; the counter is continuous across sections. The engine's
   `*num &= BLOCK_MASK` clears only the *intra-block* offset bookkeeping, not
   the IV. Repo comment makes this explicit: "The counter IV is NOT reset by
   ACPKM — only by the TLSTree ctrl at record boundaries"
   (`ctr_gost.go:84-85`); `rekeyACPKM` (`ctr_gost.go:122-129`) replaces only
   `c.block`, never `c.iv`. A reimplementer who re-zeros the counter on rekey
   will diverge after the first section.

4. **The retiring key encrypts `D`, and `E` is the cipher's ENCRYPT direction
   for both encrypt and decrypt of the stream.** CTR is a stream cipher:
   decryption is the same XOR with the same gamma, so the block cipher is
   always used in *encrypt* mode, including inside ACPKM (`acpkm_next` calls
   `grasshopper_encrypt_block`, `gost_grasshopper_cipher.c:171`;
   `acpkm_magma_key_meshing` calls `magmacrypt` =
   encrypt, `gost89.c:773`). Repo: `rekeyACPKM` calls `c.block.Encrypt`
   (`ctr_gost.go:126`). Never use `Decrypt` here.

5. **`D` is identical for Magma and Kuznyechik; the two engine symbols are a
   copy.** `ACPKM_D_const` (Magma, `gost89.c:247`) and `ACPKM_D_2018`
   (Kuznyechik, `gost_grasshopper_cipher.c:155`) are the same 32 bytes
   (`0x80`…`0x9F`). Do not hand-derive a different constant per cipher.

6. **This is RFC 8645 ACPKM, NOT CryptoPro RFC 4357 key meshing.** They are
   different mechanisms that both "re-key every 1024 bytes" and are easy to
   conflate. CryptoPro meshing (used by the legacy IMIT/CNT GOST 28147 path,
   `TODO.md` "RESOLVED 2026-04-20", `tmp/engine/gost_crypt.c:1510-1524`)
   ECB-*decrypts* the key against a different constant. ACPKM *encrypts* a
   public constant. The third known divergence in `TODO.md` (CryptoPro key
   meshing) does NOT apply to this primitive — ACPKM has no analogous gogost
   bug because gogost has no ACPKM at all; the repo owns the whole
   implementation. (The other two `TODO.md` divergences — S-box row order and
   R 34.11-94 empty-input finalization — also do not touch CTR/ACPKM.)

7. **Section size is per-suite and protocol-defined, not a single constant.**
   RFC 8645 §6.2.1 leaves `N` to the protocol. The engine sets `4096` for
   Kuznyechik CTR-ACPKM (`gost_grasshopper_cipher.c:334`) and `1024` for Magma
   (`gost_crypt.c:517`); CMS uses `256*1024`
   (`gost_grasshopper_cipher.c:988-989`). A reimplementer must take `N` as a
   parameter, not bake it in.

8. **`gost28147.CTR.XORKeyStream` from gogost is unusable for streaming** —
   per `CLAUDE.md` "gogost/v7 library gotchas" it over-increments the counter
   on block-aligned inputs and discards partial-block gamma across calls. This
   is precisely *why* CTR is reimplemented in-repo. Our `XORKeyStream` carries
   `num` (bytes consumed from the current gamma block) across calls so that
   split writes match one-shot writes byte-for-byte
   (`TestCTR_PartialBlock`, `ctr_test.go:188`).

## Test vectors

### Inline runnable vector (Kuznyechik CTR-ACPKM, section size 32)

From `internal/gost/cipher_modes_test.go:154` (`Kuznyechik-CTR-ACPKM-32`),
ported from `tmp/engine/test_ciphers.c`. Section size 32 forces 3 rekeys over
112 bytes — a complete end-to-end ACPKM exercise.

```
key (32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
IV  (16B): 1234567890abcef0 0000000000000000   (8-byte nonce, zero-padded)
section N: 32 bytes

plaintext (112B):
  1122334455667700ffeeddccbbaa9988
  00112233445566778899aabbcceeff0a
  112233445566778899aabbcceeff0a00
  2233445566778899aabbcceeff0a0011
  33445566778899aabbcceeff0a001122
  445566778899aabbcceeff0a00112233
  5566778899aabbcceeff0a0011223344

ciphertext (112B):
  f195d8bec10ed1dbd57b5fa240bda1b8
  85eee733f6a13e5df33ce4b33c45dee4
  4bceeb8f646f4c55001706275e85e800
  587c4df568d094393e4834afd0805046
  cf30f57686aeece11cfc6c316b8a896e
  dffd07ec813636460c4f3b743423163e
  6409a9c282fac8d469d221e7fbd6de5d
```

Note the first 32 bytes equal the plain Kuznyechik CTR KAT (GOST R 34.13-2015
A.1.2) because the first section uses the unmeshed key — see the plain-CTR KAT
below, whose first 32 bytes are `f195d8be...3c45dee4`.

### Magma ACPKM key-meshing KAT (K2)

From `internal/gost/magma_acpkm_test.go:39`
(`tmp/engine/test_gost89.c:60`). Verifies one ACPKM transform in isolation:

```
K  (32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
ACPKM(K) = E_K(D[0:8])||E_K(D[8:16])||E_K(D[16:24])||E_K(D[24:32]) with Magma:
K2 (32B): 863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0
```

### Plain CTR KATs (no ACPKM)

- Kuznyechik CTR, GOST R 34.13-2015 A.1.2 — `ctr_test.go:40`
  (`TestCTR_Kuznyechik_KAT`). Same key/plaintext as above (the first 64
  plaintext bytes); expected ciphertext (64 bytes, pinned in full by
  `ctr_test.go:54-57`):
  ```
  f195d8bec10ed1dbd57b5fa240bda1b8
  85eee733f6a13e5df33ce4b33c45dee4
  a5eae88be6356ed3d5e877f13564a3a5
  cb91fab1f20cbab6d1c6d15820bdba73
  ```
- Magma CTR, GOST R 34.13-2015 A.2.2 — `ctr_test.go:83`
  (`TestCTR_Magma_KAT`):
  ```
  key:        ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  IV (8B):    1234567800000000   (4-byte nonce zero-padded)
  plaintext:  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
  ciphertext: 4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d
  ```

### Other coverage

- `TestCTR_CounterIncrement` (`ctr_test.go:121`) — big-endian carry.
- `TestCTR_PartialBlock` (`ctr_test.go:188`) — split-write == one-shot.
- `TestCTRACPKM_Roundtrip` (`ctr_test.go:217`) — 3.5 sections, encrypt/decrypt
  agree, for both ciphers.
- `Kuznyechik-CTR-ACPKM-Master-96` (`cipher_modes_test.go:176`) — ACPKM-Master,
  144 zero bytes, IV `ff*8`, N=96.

## Re-implementation checklist

Each step is independently testable against a vector above.

1. **Block cipher.** Obtain a `crypto/cipher.Block` for Kuznyechik (16-byte
   block) and Magma (8-byte block). (Out of scope here — separate guide.)
   Verify with the ECB KAT in `cipher_modes_test.go:85` if available.
2. **Counter increment.** Implement big-endian `incCounter`: from the last
   byte upward, `++`, stop on no-wrap. Test: incrementing `...FF` rolls the
   carry into the next-higher byte.
3. **Plain CTR.** Build CTR over a full `n`-byte counter (nonce in high `n/2`,
   zeros in low `n/2`): per block, `gamma = E(counter)`, increment, XOR.
   Carry the partial-block offset (`num`) across `XORKeyStream` calls.
   Verify against the Magma and Kuznyechik plain-CTR KATs and
   `TestCTR_CounterIncrement` / `TestCTR_PartialBlock`.
4. **ACPKM constant.** Hard-code the 32 bytes `0x80`…`0x9F`. Verify it equals
   the first 32 bytes of RFC 8645's `D`.
5. **ACPKM transform.** `rekey(K)`: for `i` in `0, n, 2n, ...` up to 32, set
   `newKey[i:i+n] = E_K(D[i:i+n])`; return the 32 bytes; rebuild the block
   from `newKey`. Use ENCRYPT direction. Verify against the Magma K2 KAT.
6. **ACPKM scheduling in CTR.** Track `sinceRekey` (keystream bytes produced
   under the current key). At each new-gamma-block boundary, if
   `sectionSize > 0 && sinceRekey >= sectionSize`: rekey, reset
   `sinceRekey = 0`. Do NOT reset the counter. Require
   `sectionSize % blockSize == 0`; `sectionSize == 0` ⇒ plain CTR. Verify
   against `Kuznyechik-CTR-ACPKM-32` and that N=0 matches plain CTR.
7. **Round-trip.** Confirm decrypt = encrypt (same gamma) over multiple
   sections, both ciphers (`TestCTRACPKM_Roundtrip`).
8. **TLS counter assembly (only if wiring the record layer).** High `n/2`
   bytes = record nonce + sequence number (big-endian carry add); low `n/2`
   bytes = 0. See `adjustIV` (`protection_ctromac_gost.go:154`).

## Conformance & fuzz testing

This primitive has **no gogost reference to diff against** — gogost ships no
CTR and no ACPKM (`third_party/gogost/gost3413/` is `padding.go` only). The
clean-room differential strategy therefore has three reference targets: (1) the
in-repo `internal/gost.NewCTR` / `NewCTRACPKM` (the de-facto spec); (2) the
pinned hex vectors already in this doc (KATs, primary anchor); and (3) the
gost-engine CLI oracle for randomized cross-checks — shelled out, since the
engine exposes no Go API for CTR-ACPKM. Because CTR is a stream cipher,
the cheapest invariant for fuzzing is **encrypt/decrypt round-trip** (the same
gamma decrypts what it encrypted); the stronger check is byte-equality of the
clean-room keystream against the in-repo impl. Fuzz random key + IV + an
**arbitrary-length stream long enough to cross several ACPKM section
boundaries** (drive `sectionSize` small — e.g. one or two blocks — so a few
hundred bytes already exercises multiple rekeys).

Replace `mynew` with your clean-room package. Its constructors must match the
in-repo signatures verbatim:
`NewCTR(block cipher.Block, iv []byte) (*CTR, error)` and
`NewCTRACPKM(newBlock func([]byte) cipher.Block, key, iv []byte, sectionSize int) (*CTR, error)`,
each yielding a value with `XORKeyStream(dst, src []byte)`
(`internal/gost/ctr_gost.go:57,86,134`). `newBlock` must return your own
Kuznyechik/Magma `cipher.Block`; the in-repo tests key it off gogost's
`gost3412128.NewCipher` / `gost341264.NewCipher` (`ctr_test.go:227-229`) —
use whichever block impl your clean-room build owns on the reference side.

### KAT conformance (seeded from this doc's pinned vectors)

Reuses the exact `Kuznyechik-CTR-ACPKM-32` bytes from the "Test vectors"
section above (`internal/gost/cipher_modes_test.go:154`). Both the clean-room
impl and the in-repo reference must reproduce the pinned ciphertext.

```go
//go:build gost

package mypkg_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	ref "go.bigb.es/tlsdialer/internal/gost"   // in-repo reference
	mynew "github.com/.../yourpkg"                    // clean-room impl under test

	// block ciphers — your clean-room build supplies these; the in-repo
	// tests use gogost's (ctr_test.go:227).
	"go.stargrave.org/gogost/v7/gost3412128"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestCTRACPKMConformance(t *testing.T) {
	// Kuznyechik-CTR-ACPKM-32 — cipher_modes_test.go:154.
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "1234567890abcef00000000000000000") // 8B nonce, zero-padded to 16
	section := 32
	plain := mustHex(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011"+
			"33445566778899aabbcceeff0a001122"+
			"445566778899aabbcceeff0a00112233"+
			"5566778899aabbcceeff0a0011223344")
	want := mustHex(t,
		"f195d8bec10ed1dbd57b5fa240bda1b8"+
			"85eee733f6a13e5df33ce4b33c45dee4"+
			"4bceeb8f646f4c55001706275e85e800"+
			"587c4df568d094393e4834afd0805046"+
			"cf30f57686aeece11cfc6c316b8a896e"+
			"dffd07ec813636460c4f3b743423163e"+
			"6409a9c282fac8d469d221e7fbd6de5d")

	newKuz := func(k []byte) cipher.Block { return gost3412128.NewCipher(k) }

	// Reference (in-repo) — must hit the pinned ciphertext.
	rc, err := ref.NewCTRACPKM(newKuz, key, iv, section)
	if err != nil {
		t.Fatalf("ref.NewCTRACPKM: %v", err)
	}
	got := make([]byte, len(plain))
	rc.XORKeyStream(got, plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("reference mismatch:\n got  %x\n want %x", got, want)
	}

	// Clean-room — must also hit the pinned ciphertext, and thus equal ref.
	mc, err := mynew.NewCTRACPKM(newKuz, key, iv, section)
	if err != nil {
		t.Fatalf("mynew.NewCTRACPKM: %v", err)
	}
	gotNew := make([]byte, len(plain))
	mc.XORKeyStream(gotNew, plain)
	if !bytes.Equal(gotNew, want) {
		t.Fatalf("clean-room mismatch:\n got  %x\n want %x", gotNew, want)
	}
}
```

(Add `"crypto/cipher"` to the import block — elided above for brevity.)

### Differential fuzz harness

Seeds from the KAT, then normalizes each random `[]byte` into the fixed-size
arguments: 32-byte key, full 16-byte counter (8-byte nonce in the high half,
low half zero — see "CTR mode" above), a small block-aligned `sectionSize` to
force boundary crossings, and an arbitrary-length stream. It checks both the
clean-room/reference **keystream equality** and the **round-trip** invariant.

```go
//go:build gost

package mypkg_test

import (
	"bytes"
	"crypto/cipher"
	"testing"

	ref "go.bigb.es/tlsdialer/internal/gost"
	mynew "github.com/.../yourpkg"
	"go.stargrave.org/gogost/v7/gost3412128"
)

func FuzzCTRACPKMConformance(f *testing.F) {
	f.Add( // KAT inputs as the seed corpus.
		mustHexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		mustHexF("1234567890abcef0"),
		uint16(32),
		mustHexF("1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"))

	f.Fuzz(func(t *testing.T, rawKey, rawNonce []byte, rawSection uint16, plain []byte) {
		// Normalize into this primitive's fixed-size arguments.
		key := make([]byte, 32)
		copy(key, rawKey) // truncate/zero-pad to exactly 32 bytes

		const bs = 16 // Kuznyechik block size
		iv := make([]byte, bs)
		copy(iv[:bs/2], rawNonce) // nonce -> high half, low half stays zero

		// sectionSize must be a positive multiple of bs; keep it small to
		// cross several ACPKM boundaries over short inputs.
		section := (int(rawSection)%8 + 1) * bs

		newKuz := func(k []byte) cipher.Block { return gost3412128.NewCipher(k) }

		// 1. Clean-room keystream must equal the in-repo reference.
		rc, err := ref.NewCTRACPKM(newKuz, key, iv, section)
		if err != nil {
			t.Skip() // invalid combination rejected identically by both
		}
		mc, err := mynew.NewCTRACPKM(newKuz, key, iv, section)
		if err != nil {
			t.Fatalf("clean-room rejected what ref accepted: %v", err)
		}
		refCT := make([]byte, len(plain))
		newCT := make([]byte, len(plain))
		rc.XORKeyStream(refCT, plain)
		mc.XORKeyStream(newCT, plain)
		if !bytes.Equal(refCT, newCT) {
			t.Fatalf("keystream divergence (section=%d, len=%d):\n ref %x\n new %x",
				section, len(plain), refCT, newCT)
		}

		// 2. Round-trip: clean-room decrypt of its own ciphertext = plaintext.
		dec, err := mynew.NewCTRACPKM(newKuz, key, iv, section)
		if err != nil {
			t.Fatalf("re-init: %v", err)
		}
		back := make([]byte, len(newCT))
		dec.XORKeyStream(back, newCT)
		if !bytes.Equal(back, plain) {
			t.Fatalf("round-trip mismatch (section=%d):\n got  %x\n want %x",
				section, back, plain)
		}
	})
}

func mustHexF(s string) []byte { b, _ := hex.DecodeString(s); return b }
```

(Add `"encoding/hex"` to the import block for `mustHexF`.)

For a heavier cross-check, diff a randomized clean-room ciphertext against the
gost-engine CLI oracle. The engine has no Go API for CTR-ACPKM, so shell out
per CLAUDE.md's "CLI oracles for primitive cross-check" (note: the bare
`-kuznyechik-ctr` CLI is **plain** CTR — to exercise ACPKM rekeying you must
drive a section-sized stream or use the engine's ACPKM-enabled mode):

```go
// engineCTR returns the gost-engine plain-Kuznyechik-CTR ciphertext for a
// 32-byte hex key and 8-byte hex iv. No gogost/OpenSSL Go binding exists for
// this mode; CLAUDE.md mandates the CLI oracle. Use only as a *plain*-CTR
// cross-check (no ACPKM) or against an ACPKM-driving engine invocation.
func engineCTR(t *testing.T, keyHex, ivHex string, plain []byte) []byte {
	t.Helper()
	in := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(in, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		"/opt/homebrew/opt/openssl@3/bin/openssl", "enc", "-engine", "gost",
		"-kuznyechik-ctr", "-K", keyHex, "-iv", ivHex, "-in", in)
	cmd.Env = append(os.Environ(),
		"OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gost-engine oracle: %v", err)
	}
	return out
}
```

### Run

```sh
go test -tags gost -run TestCTRACPKMConformance ./yourpkg/
go test -tags gost -fuzz=FuzzCTRACPKMConformance -fuzztime=30s ./yourpkg/
```

## References

- **RFC 8645** — "Re-keying Mechanisms for Symmetric Keys".
  https://github.com/bigbes/gostcrypto/blob/master/ctracpkm/rfc/rfc8645.txt
  - §2 — re-keying overview (internal vs external).
  - §6.2.1 — ACPKM transformation `K^{i+1} = MSB_k(E_{K^i}(D_1)|...|E_{K^i}(D_J))`,
    constant `D = (80|81|...|fe|ff)`, "section size N MUST be divisible by the
    block size n".
  - §6.3.1 — ACPKM-Master `= CTR-ACPKM-Encrypt(T*, K, 1^{n/2}, 0^{d*l})`.
- **GOST R 34.13-2015** — block cipher modes of operation.
  §5.3 — CTR (gamma counter) mode. Test vectors: A.1.2 (Kuznyechik CTR),
  A.2.2 (Magma CTR).
- **GOST R 34.12-2015** — Kuznyechik (128-bit) and Magma (64-bit) block
  ciphers.
- **R 1323565.1.017-2018** — TC26 cryptographic mechanisms; source of the
  ACPKM `D` constant and TLS section-size choices (Kuznyechik 4096, Magma 1024).
- **RFC 9367** — GOST cipher suites for TLS 1.2 (suites `0xC100`/`0xC101`);
  consumer of this primitive in the record layer.

### Source `file:line` citations

Repo (in-repo reimplementation — the de-facto spec):
- `internal/gost/ctr_gost.go:32-37` — `acpkmD` constant.
- `internal/gost/ctr_gost.go:57-70` — `NewCTR`.
- `internal/gost/ctr_gost.go:86-117` — `NewCTRACPKM` (section validation).
- `internal/gost/ctr_gost.go:122-129` — `rekeyACPKM` (ACPKM transform).
- `internal/gost/ctr_gost.go:134-163` — `XORKeyStream` (rekey scheduling).
- `internal/gost/ctr_gost.go:167-174` — `incCounter` (big-endian carry).
- `tls/internal/record/protection_ctromac_gost.go:99,135` — section sizes.
- `tls/internal/record/protection_ctromac_gost.go:154-172` — `adjustIV`.
- `tls/internal/record/protection_ctromac_gost.go:205,250` — call sites.
- Tests: `internal/gost/ctr_test.go`, `internal/gost/cipher_modes_test.go:154,176`,
  `internal/gost/magma_acpkm_test.go:39`.

gost-engine v3.0.3 (parity target):
- `tmp/engine/gost89.c:247-252` — `ACPKM_D_const` (Magma D).
- `tmp/engine/gost89.c:768-777` — `acpkm_magma_key_meshing`.
- `tmp/engine/gost_grasshopper_cipher.c:155-160` — `ACPKM_D_2018` (Kuznyechik D).
- `tmp/engine/gost_grasshopper_cipher.c:162-178` — `acpkm_next`.
- `tmp/engine/gost_grasshopper_cipher.c:581-600` — `inc_counter`/`ctr128_inc`.
- `tmp/engine/gost_grasshopper_cipher.c:660-720` — `apply_acpkm_grasshopper`,
  `gost_grasshopper_cipher_do_ctracpkm`.
- `tmp/engine/gost_grasshopper_cipher.c:334` — Kuznyechik section_size = 4096.
- `tmp/engine/gost_crypt.c:807-810` — `ctr64_inc`.
- `tmp/engine/gost_crypt.c:814-869` — `apply_acpkm_magma`, `magma_cipher_do_ctr`.
- `tmp/engine/gost_crypt.c:517` — Magma key_meshing (section) = 1024.
- `tmp/engine/test_ciphers.c`, `tmp/engine/test_gost89.c:60` — KAT sources.

gogost (NOT used for this primitive):
- `third_party/gogost/gost3413/` — contains only `padding.go`; no CTR/ACPKM.
