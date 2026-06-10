# OMAC / CMAC (GOST R 34.13-2015 MAC mode)

This is a **clean-room re-implementation guide**. A reader must be able to
reimplement the GOST MAC mode (OMAC1 / CMAC) in Go *without* reading
`go.stargrave.org/gogost/v7`, using only this document plus the cited RFCs and
GOST standard.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

**Status: clean-room implementation in this module.** This primitive is **not**
sourced from gogost. The code lives at `omac/omac.go` in the `gostcrypto`
module (`New`, `OMAC.Write`, `OMAC.Sum`), layered over any
`crypto/cipher.Block`. The block ciphers (Kuznyechik `kuznyechik.NewCipher`,
Magma `magma.NewCipher`) are also clean-room implementations in this module —
see `../kuznyechik/kuznyechik-gost34122015.md` and `../magma/magma.md`. The
de-facto spec this file documents is the behavioral contract in `omac/omac.go`,
cross-checked against gost-engine v3.0.3 (Tarantool's upstream) and RFC 4493.
Parity / differential fuzz tests live in
`../gostcrypto-compat/parity/omac/` (GPL-licensed; never imported by this
module).

## What it is

GOST R 34.13-2015 **MAC mode** ("режим выработки имитовставки", §5.6) is
exactly **OMAC1 = CMAC** (RFC 4493, NIST SP 800-38B) instantiated with a GOST
block cipher instead of AES. It is a CBC-MAC variant that fixes CBC-MAC's
length-extension weakness by XORing the final block with one of two derived
subkeys (`K1` for a complete final block, `K2` for a padded one).

It is **the same algorithm for both ciphers**; only the block size, the GF
reduction constant `Rb`, and the (truncated) tag length differ:

| Quantity                | Kuznyechik (Grasshopper)      | Magma                        |
|-------------------------|-------------------------------|------------------------------|
| Block size `n`          | 16 bytes (128 bit)            | 8 bytes (64 bit)             |
| Key size                | 32 bytes (256 bit)            | 32 bytes (256 bit)           |
| `Rb` (GF reduction)     | `0x87`                        | `0x1b`                       |
| Full CMAC width         | 16 bytes                      | 8 bytes                      |
| Truncated tag (TLS/std) | 8 bytes (CTR-OMAC) / 16       | 4 bytes (KAT) / 8            |

gost-engine's own OMAC simply calls OpenSSL's standard `CMAC_*` routines and
truncates the result — confirming this is plain CMAC. See
`tmp/engine/gost_omac.c:79` (`CMAC_Update`), `:93` (`CMAC_Final`), and the
truncation `memcpy(md, mac, c->dgst_size)` at `tmp/engine/gost_omac.c:95`.

### Where this repo uses it

- **TLS record protection for RFC 9189 GOST suites** — Kuznyechik-CTR-OMAC
  (`0xC100`) and Magma-CTR-OMAC (`0xC101`). The protector `ctrOMACProtector`
  calls `omac.New(macBlock, tagSize)` once per record in both `Seal` and
  `Open`. Here `tagSize` is the **full** block width: `16` for Kuznyechik and
  `8` for Magma. This call site lives in the `gostls` module (sibling of
  `gostcrypto`), not in this module. See the sibling guide
  `../ctracpkm/ctr-acpkm.md` for the CTR half of these suites.
- **kexp15 key-export wrapper** — `kexp15/kexp15.go` computes
  `mac = OMAC(mac_key, iv || shared_key)` truncated to `macLen`, then
  CTR-encrypts `shared_key || mac`. See `../kexp15/kexp15.md`.

## Specification

### CMAC subkey derivation (RFC 4493 §2.3)

Two subkeys `K1`, `K2` are derived from the cipher key before processing any
message. Let `E_K` be the block cipher under key `K`, `n` the block size in
bits, `0^n` the all-zero block, and `Rb` the per-block-size GF(2^n) reduction
constant (see below). RFC 4493 §2.3, "Subkey Generation Algorithm":

```
1.  L = E_K(0^n)
2.  if MSB(L) == 0  then  K1 = L << 1
    else                  K1 = (L << 1) XOR Rb
3.  if MSB(K1) == 0 then  K2 = K1 << 1
    else                  K2 = (K1 << 1) XOR Rb
```

`<<` is a **left shift of the whole block treated as one big-endian bit
string** (MSB = the most-significant bit of byte 0). `MSB(X)` is that same
leading bit. `Rb` is a small constant XORed into the **last (lowest-order)
byte** when the shift overflows the top bit. This is the standard
"multiply-by-x in GF(2^n)" operation.

> **Endianness caution.** GOST is little-endian in many other places (key
> scalars, curve points, CTR nonce intuition). The CMAC shift is the
> opposite: a **big-endian** GF(2^n) shift. Byte 0 holds the most-significant
> bits; the carry from `byte[i]` flows into `byte[i-1]`. Reusing GOST's usual
> little-endian habit here produces wrong subkeys.

### The `Rb` reduction constants — per block size

`Rb` is the low byte of the irreducible polynomial that defines GF(2^n):

- **128-bit block (Kuznyechik): `Rb = 0x87`** — polynomial
  `x^128 + x^7 + x^2 + x + 1` (RFC 4493 §2.3, which defines CMAC for the
  128-bit AES block; the same constant applies to any 128-bit cipher).
- **64-bit block (Magma): `Rb = 0x1b`** — polynomial
  `x^64 + x^4 + x^3 + x + 1` (RFC 8645 §6.3.6, OMAC-ACPKM-Master, which fixes
  `R_64 = 0^59|11011`, i.e. binary `11011 = 0x1b`; this is also the standard
  64-bit CMAC constant for DES-style blocks in SP 800-38B Appendix).

In both cases the constant is a single byte; the rest of the `Rb` block is
zero, so it only ever affects the last byte of the shifted value.

### MAC computation (RFC 4493 §2.4 = GOST R 34.13-2015 §5.6)

Split the message `M` into `n`-bit blocks `M_1 … M_{m}` (the last block
`M_m*` possibly shorter). RFC 4493 §2.4, "MAC Generation Algorithm":

```
1.  (K1, K2) = subkeys  (above)
2.  if M is a multiple of n and non-empty:
        M_last = M_m  XOR  K1                 # complete final block
    else (incl. empty message):
        M_last = padding(M_m*) XOR K2         # incomplete / empty final block
        where padding(x) = x || 0x80 || 0x00…  (pad to n bits)
3.  X = 0^n
    for i = 1 .. m-1:
        X = E_K( X XOR M_i )                  # CBC chain
    T = E_K( X XOR M_last )
4.  MAC = MSB_tlen(T)                          # truncate to tag length
```

The whole construction is CBC-MAC over `M_1 … M_{m-1}`, then a final block
that is `M_last = M_m ⊕ K1` (complete) or `pad(M_m*) ⊕ K2` (incomplete).
GOST R 34.13-2015 §5.6 specifies exactly this with `R = E_K(0)` and the same
two-subkey selection; the padding (`procedure 2`, single `1` bit then zeros,
i.e. byte `0x80`) is GOST's pad-mode 2.

## RFC ↔ implementation deltas

Each delta cites BOTH the RFC/standard and the source line. These are the
points where a naive reading diverges from the parity target.

1. **`Rb` is chosen by block size, with a hard panic on anything else.**
   `rbForBlockSize` (`omac/omac.go:92-101`) selects `rb = 0x87` for
   `bs == 16` and `rb = 0x1b` for `bs == 8`, and `panic`s otherwise.
   `cmacSubkeys` (`omac/omac.go:108-117`) calls it. The 64-bit constant `0x1b`
   is the spot most reimplementers get wrong — RFC 4493 only states `0x87`; the
   64-bit value comes from RFC 8645 §6.3.6 (OMAC-ACPKM-Master,
   `R_64 = 0^59|11011 = 0x1b`). Engine equivalent: OpenSSL's `CMAC_Init`
   derives both subkeys internally per the cipher's block size
   (`tmp/engine/gost_omac.c:149`, `CMAC_Init(... cipher ...)`).

2. **The shift is big-endian over the whole block.** `shiftLeftXorRb`
   (`omac/omac.go:127-142`): `msb = in[0] >> 7` reads the leading bit of byte
   0; `out[i] = (in[i] << 1) | (in[i+1] >> 7)` shifts left carrying the next
   byte's top bit down; the final byte is `in[last] << 1`, then
   `out[last] ^= rb` iff `msb == 1`. `Rb` lands in the **last** byte. RFC 4493
   §2.3 defines exactly this "one-bit left shift of the entire 128-bit string".
   A little-endian shift (carry flowing the other way, `Rb` in byte 0) is the
   classic bug.

3. **Last-block selection keys on `len(buf) == blockSize`, and a buffered full
   block is a legal, intentional state.** `Write` deliberately does **not**
   flush a full block if it is the trailing data — it holds up to `blockSize`
   bytes in `buf` so `Sum` can tell "exactly `n` unprocessed bytes" (the `K1`
   path) from "fewer than `n`" (the `K2`/padding path)
   (`omac/omac.go:151-173`, esp. the `len(o.buf) == o.blockSize && len(p) > 0`
   guard at `omac/omac.go:165`). In `Sum`: if `len(o.buf) == blockSize`,
   `last = buf XOR K1` (`omac/omac.go:186-190`); else pad with `0x80`
   then zeros and XOR `K2` (`omac/omac.go:192-200`). This matches RFC 4493
   §2.4 step 4's "if M_n is complete … else …". An off-by-one (flushing the
   full final block early, then padding an empty block with `K2`) yields a
   wrong tag on every block-aligned message.

4. **Padding is `0x80` then zeros (GOST pad-mode 2 = RFC 4493 padding).** The
   empty / partial block becomes `bufSnap || 0x80 || 0x00…` before the `K2`
   XOR (`omac.go:155-159`). The empty-message case (`len(bufSnap) == 0`) writes
   `0x80` at index 0 — note this is NOT the GOST R 34.11-94 empty-input quirk
   in `TODO.md`; CMAC's empty-message handling is unambiguous and unaffected.

5. **Truncation = take the leading `tagSize` bytes (MSB).**
   `Sum` computes `T = E_K(stateSnap XOR last)` where `stateSnap` is the
   snapshot of the running CBC chain value and `last` is the K1/K2-adjusted
   final block; then returns `t[:o.tagSize]` (`omac/omac.go:204-212`).
   Note: `stateSnap` is the CBC chain snapshot — it is XOR-ed into the final
   block computation, not returned directly. The truncation is of `t`, the
   cipher output. `New` validates `1 <= tagSize <= blockSize`
   (`omac/omac.go:69-71`). This is RFC 4493's `MSB_tlen` and matches
   gost-engine: `omac_imit_final` does `memcpy(md, mac, c->dgst_size)`
   (`tmp/engine/gost_omac.c:95`), where `dgst_size` defaults to the full block
   (`tmp/engine/gost_omac.c:50-55`: 8 for Magma, 16 for Grasshopper) and can
   be narrowed via `EVP_MD_CTRL_XOF_LEN` to any `1..8` (Magma) or `1..16`
   (Kuznyechik) (`tmp/engine/gost_omac.c:218-231`). The `gostls` module's
   CTR-OMAC suites use the full width (16/8); the published standard KATs
   truncate to 8/4 (below); kexp15 truncates to its `macLen`
   (`kexp15/kexp15.go`).

6. **`Sum` is non-destructive; the receiver survives repeated `Sum` and later
   `Write`.** `Sum` snapshots `state` and `buf` and operates on the copies
   (`omac/omac.go:180-212`). This mirrors OpenSSL's EVP "finalize-on-copy"
   semantics (the same property documented for IMIT in `CLAUDE.md`) and is
   required so a protector can MAC, then keep streaming. Pinned by
   `TestOMAC_SumIdempotent` and `TestOMAC_SumAfterWrite`
   (`omac/omac_test.go:147,166`). A reimplementation that mutates `state`
   inside `Sum` will corrupt any subsequent `Write`.

7. **The block cipher is used in ENCRYPT direction throughout** — including for
   `L = E_K(0)` (`omac/omac.go:111`) and every CBC step
   (`cbcStep`, `omac/omac.go:224-231`). CMAC never decrypts. (Trivially true
   here because `cbcStep` only calls `block.Encrypt`, but worth stating: do not
   "decrypt to verify" — recompute and compare in constant time at the caller.)

## Test vectors

All vectors live in `omac/omac_test.go` (standard GOST R 34.13-2015 KATs plus
gost-engine oracle KATs).

### Inline verified Kuznyechik OMAC KAT (engine oracle)

Cross-checked against the gost-engine CLI from `CLAUDE.md` and re-verified for
this document:

```sh
printf 'hello' | OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
  /opt/homebrew/opt/openssl@3/bin/openssl dgst -engine gost \
  -mac kuznyechik-mac \
  -macopt hexkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# => kuznyechik-mac(stdin)= 96e6c1913fd788e3922e617fdd341edf
```

```
cipher:   Kuznyechik (16-byte block)
key (32B): AA × 32   (all bytes 0xAA)
message:   "hello"   (5 ASCII bytes: 68 65 6c 6c 6f)  — partial final block → K2 path
tag (16B): 96e6c1913fd788e3922e617fdd341edf   (full, untruncated)
```

This is the exact assertion in `TestOMAC_Kuznyechik_EngineOracleKAT`
(`omac/omac_test.go:29-43`). The oracle command above was confirmed against
the gost-engine when this guide was written and returned the identical tag.
Because `"hello"` is shorter than a block, this vector also exercises the
`K2`/padding branch end-to-end.

### Standard GOST R 34.13-2015 KATs (truncated)

- **Kuznyechik, GOST R 34.13-2015 A.1.6** — `omac/omac_test.go:47`
  (`TestOMAC_Kuznyechik_KAT`), vector from `tmp/engine/test_digest.c:71-104`:
  ```
  key (32B): 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
  P  (64B):  1122334455667700ffeeddccbbaa9988
             00112233445566778899aabbcceeff0a
             112233445566778899aabbcceeff0a00
             2233445566778899aabbcceeff0a0011
  tag (8B):  336f4d296059fbe3      (leading 8 bytes of the 16-byte CMAC)
  ```
  `P` is a multiple of the block size → **`K1`** (complete-block) path.

- **Magma, GOST R 34.13-2015 A.2.6** — `omac/omac_test.go:70`
  (`TestOMAC_Magma_KAT`), vector from `tmp/engine/test_digest.c:79-109`:
  ```
  key (32B): ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  P  (32B):  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
  tag (4B):  154e7210              (leading 4 bytes of the 8-byte CMAC)
  ```
  `P` is a multiple of 8 → **`K1`** path; truncated to 4 bytes.

### Property coverage

- `TestOMAC_SumIdempotent` (`omac/omac_test.go:147`) — two `Sum`s, no `Write`
  between, equal bytes.
- `TestOMAC_SumAfterWrite` (`omac/omac_test.go:166`) — `Write half1; Sum;
  Write half2; Sum` equals a fresh OMAC over the concatenation (proves `Sum`
  does not mutate state, and that split `Write`s match a one-shot `Write`).
- `TestOMAC_EngineTclVectors` (`omac/omac_test.go:95`) — full-width engine tcl
  vectors for both Magma and Kuznyechik from
  `tmp/engine/tcl_tests/mac.try:112-119`.

## Re-implementation checklist

Each step is independently testable against a vector above.

1. **Block cipher.** Obtain a `crypto/cipher.Block` for Kuznyechik (16-byte
   block) and Magma (8-byte block). Out of scope here — see
   `../kuznyechik/kuznyechik-gost34122015.md`.
2. **GF shift.** Implement `shiftLeftXorRb(in, rb)`: big-endian 1-bit left
   shift of the whole block; if the original MSB (`in[0]>>7`) was 1, XOR `rb`
   into the **last** byte. Test: `0x80 00…00 << 1` with `Rb=0x87` gives
   `00…00 ⊕ 0x87` = `00…0087`.
3. **Subkeys.** `L = E_K(0^n)`; `K1 = shiftLeftXorRb(L, Rb)`;
   `K2 = shiftLeftXorRb(K1, Rb)`. Pick `Rb = 0x87` for `n=16`, `0x1b` for
   `n=8`; reject any other block size.
4. **Streaming `Write`.** Buffer incoming bytes; flush a full block into the
   CBC chain (`X = E_K(X ⊕ block)`) **only when more data follows**. Keep up to
   `n` bytes (a full block is allowed) buffered for `Sum`.
5. **`Sum` final block.** Snapshot state+buf (non-destructive). If buffered
   length == `n`: `last = buf ⊕ K1`. Else: pad `buf || 0x80 || 0x00…` to `n`,
   `last = pad ⊕ K2`. Then `T = E_K(stateSnap ⊕ last)`; return `T[:tagSize]`.
6. **Tag width.** Validate `1 ≤ tagSize ≤ n`. Truncate by taking the leading
   (MSB) `tagSize` bytes. Verify full-width against the engine oracle KAT
   (`hello`/`0xAA×32` → `96e6c191…341edf`), and truncated against the A.1.6
   (8-byte) and A.2.6 (4-byte) KATs.
7. **Non-destructive `Sum`.** Confirm `Sum` twice == equal, and `Sum` then
   `Write` then `Sum` == fresh OMAC over the whole input.
8. **Caller-side verify.** Compare tags in constant time
   (`crypto/subtle.ConstantTimeCompare`); never branch on a byte mismatch.

## Conformance & fuzz testing

gogost ships no standalone OMAC primitive, so differential fuzz testing uses
the reference implementation in `gostcrypto-compat/parity/omac/` (GPL-licensed,
separate module, never imported by `gostcrypto`). The fuzz harness there
(`FuzzDiffAgainstGost`) compares this module's `omac.New` against the gogost
reference over random keys and message lengths, including split-point variance
and the empty-message K2 path. Run the gate with:

```sh
( cd ../gostcrypto-compat && go test ./parity/omac/ )
```

The in-package KAT tests (`omac/omac_test.go`) anchor the fixed vectors against
gost-engine: the A.1.6 / A.2.6 / `hello`-oracle KATs serve as the pinned
anchors; the `gostcrypto-compat` parity gate proves correctness over the full
input space for both ciphers. The gost-engine `dgst -mac kuznyechik-mac` CLI
oracle from `CLAUDE.md` cross-checks the `hello` vector. Pin the A.1.6 /
A.2.6 / `hello`-oracle KATs as fixed anchors, then fuzz a **random key +
arbitrary-length message** for *both* block sizes — Kuznyechik (128-bit,
`kuznyechik.NewCipher`, `Rb=0x87`) and Magma (64-bit, `magma.NewCipher`,
`Rb=0x1b`) — comparing this module's implementation against the gogost reference
on every input. The engine CLI is only practical to drive in the table test
(process spawn per call is too slow to fuzz), so the fuzz loop diffs against
the gogost-backed parity reference.

The CLI oracle has no Go API; shell out to it exactly as `CLAUDE.md` specifies
(only Kuznyechik full-width 16-byte tags are published this way):

```go
package omac_test

import (
	"encoding/hex"
	"os/exec"
	"strings"
)

// engineOMACKuznyechik returns the full 16-byte gost-engine OMAC over msg.
// No gogost/Go API exists for this MAC — it shells out to the CLI oracle
// documented in CLAUDE.md ("CLI oracles for primitive cross-check").
func engineOMACKuznyechik(key, msg []byte) ([]byte, error) {
	cmd := exec.Command(
		"/opt/homebrew/opt/openssl@3/bin/openssl", "dgst",
		"-engine", "gost", "-mac", "kuznyechik-mac",
		"-macopt", "hexkey:"+hex.EncodeToString(key),
	)
	cmd.Env = append(cmd.Environ(),
		"OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf")
	cmd.Stdin = strings.NewReader(string(msg))
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// "kuznyechik-mac(stdin)= 96e6c191...341edf\n"
	_, h, _ := strings.Cut(string(out), "= ")
	return hex.DecodeString(strings.TrimSpace(h))
}
```

Table-driven KAT test, seeded with the **exact pinned hex** already in this doc
(engine-oracle `hello` vector, A.1.6 Kuznyechik, A.2.6 Magma). The actual
package is `omac` from `github.com/bigbes/gostcrypto/omac`.

> **Note on the example API shape.** The documented surface is the streaming
> `New(block, tagSize) → Write → Sum` shape of `omac.New` (see the `file:line`
> citations). `New` panics on invalid tagSize or unsupported block size — it
> does NOT return an error. A clean-room implementer should construct with
> `New`, `Write`, `Sum`, not use a one-shot helper.

```go
package omac_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	"github.com/bigbes/gostcrypto/omac"
)

func TestOMACConformance(t *testing.T) {
	cases := []struct {
		name    string
		newBlock func(key []byte) interface{ BlockSize() int; Encrypt(dst, src []byte); Decrypt(dst, src []byte) }
		key     string
		msg     string // hex
		ascii   string // non-empty → use as ASCII message bytes
		tagSize int
		want    string
	}{
		{
			// engine-oracle vector, omac.md "Inline verified Kuznyechik OMAC KAT"
			name:    "kuz/hello/oracle/full16",
			newBlock: func(k []byte) interface{ BlockSize() int; Encrypt(dst, src []byte); Decrypt(dst, src []byte) } {
				return kuznyechik.NewCipher(k)
			},
			key:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ascii:   "hello",
			tagSize: 16,
			want:    "96e6c1913fd788e3922e617fdd341edf",
		},
		{
			// GOST R 34.13-2015 A.1.6 — tmp/engine/test_digest.c:71-104
			name:    "kuz/A.1.6/trunc8",
			newBlock: func(k []byte) interface{ BlockSize() int; Encrypt(dst, src []byte); Decrypt(dst, src []byte) } {
				return kuznyechik.NewCipher(k)
			},
			key: "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			msg: "1122334455667700ffeeddccbbaa9988" +
				"00112233445566778899aabbcceeff0a" +
				"112233445566778899aabbcceeff0a00" +
				"2233445566778899aabbcceeff0a0011",
			tagSize: 8,
			want:    "336f4d296059fbe3",
		},
		{
			// GOST R 34.13-2015 A.2.6 — tmp/engine/test_digest.c:79-109
			name:    "magma/A.2.6/trunc4",
			newBlock: func(k []byte) interface{ BlockSize() int; Encrypt(dst, src []byte); Decrypt(dst, src []byte) } {
				return magma.NewCipher(k)
			},
			key:     "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			msg:     "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
			tagSize: 4,
			want:    "154e7210",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, _ := hex.DecodeString(tc.key)
			var msg []byte
			if tc.ascii != "" {
				msg = []byte(tc.ascii)
			} else {
				msg, _ = hex.DecodeString(tc.msg)
			}
			want, _ := hex.DecodeString(tc.want)

			m := omac.New(tc.newBlock(key), tc.tagSize) // panics on bad args, no error
			m.Write(msg)
			got := m.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x, want %x", got, want)
			}
		})
	}
}
```

Fuzz harness — seeds from the KAT inputs, normalizes the random `[]byte` into
OMAC's fixed-size arguments (32-byte key, full-width tag), runs the
implementation against the pinned KAT vectors, and fails on divergence. The
differential fuzz (against the gogost reference) lives in
`gostcrypto-compat/parity/omac/` as `FuzzDiffAgainstGost`. OMAC is
deterministic, so this is direct differential parity (not a round-trip).

Run the in-package tests:

```sh
CGO_ENABLED=0 go test ./omac/
```

Run the parity gate (requires `gostcrypto-compat` checked out as a sibling):

```sh
( cd ../gostcrypto-compat && go test ./parity/omac/ )
```

## References

- **RFC 4493** — "The AES-CMAC Algorithm" (D. Song et al., June 2006).
  https://github.com/bigbes/gostcrypto/blob/master/omac/rfc/rfc4493.txt
  - §2.3 — Subkey Generation (`L = E_K(0^n)`, `K1`/`K2`, `Rb = 0x87`,
    big-endian `<< 1`).
  - §2.4 — MAC Generation (CBC chain, `K1` complete vs `K2` padded final block,
    `MSB_tlen` truncation).
  - §2.1 — Basic Definitions: `Rb` definition and the GF(2^128) `<< 1`
    operation.
- **RFC 8645** — "Re-keying Mechanisms for Symmetric Keys" (CryptoPro, 2019).
  https://github.com/bigbes/gostcrypto/blob/master/ctracpkm/rfc/rfc8645.txt
  - §6.3.6 — OMAC-ACPKM-Master: fixes `R_64 = 0^59|11011`, the 64-bit
    reduction constant `Rb = 0x1b`.
- **GOST R 34.13-2015** — "Block cipher operation modes".
  - §5.6 — MAC mode ("выработка имитовставки"), `R = E_K(0)`, two-subkey
    selection, pad-mode 2 (`0x80` then zeros).
  - A.1.6 — Kuznyechik MAC KAT (8-byte truncated tag `336f4d296059fbe3`).
  - A.2.6 — Magma MAC KAT (4-byte truncated tag `154e7210`).
- **NIST SP 800-38B** — "The CMAC Mode for Authentication" (equivalent
  definition of OMAC1/CMAC).
- **GOST R 34.12-2015 / RFC 7801** — Kuznyechik & Magma block ciphers.

### Source `file:line` citations

This module (`github.com/bigbes/gostcrypto`, clean-room, BSD-2-Clause):
- `omac/omac.go:65-84` — `New`, tagSize validation, subkey precompute.
- `omac/omac.go:92-101` — `rbForBlockSize` (`Rb` per block size, panic on unknown).
- `omac/omac.go:108-117` — `cmacSubkeys` (`L = E_K(0)`, `K1`, `K2`).
- `omac/omac.go:127-142` — `shiftLeftXorRb` (big-endian shift, `Rb` in last byte).
- `omac/omac.go:151-173` — `Write` (deferred full-block flush; full-block-in-buf invariant).
- `omac/omac.go:224-231` — `cbcStep` (XOR-then-Encrypt; encrypt direction only).
- `omac/omac.go:180-212` — `Sum` (non-destructive; `K1` vs `K2`/pad; `t[:tagSize]` truncation).
- `kexp15/kexp15.go` — `OMAC(mac_key, iv || shared_key)`, truncated to `macLen`.
- TLS record call sites: in the `gostls` sibling module (not `gostcrypto`).
- Tests: `omac/omac_test.go`.

gost-engine v3.0.3 (parity target — confirms plain CMAC + truncation):
- `tmp/engine/gost_omac.c:79` — `CMAC_Update`.
- `tmp/engine/gost_omac.c:93` — `CMAC_Final`.
- `tmp/engine/gost_omac.c:95` — `memcpy(md, mac, c->dgst_size)` truncation.
- `tmp/engine/gost_omac.c:48-56` — default `dgst_size` (8 Magma / 16 Grasshopper).
- `tmp/engine/gost_omac.c:149` — `CMAC_Init` (derives `K1`/`K2` per cipher block size).
- `tmp/engine/gost_omac.c:218-231` — `EVP_MD_CTRL_XOF_LEN` configurable tag length (1..8 / 1..16).
- `tmp/engine/test_digest.c:71-109` — Kuznyechik A.1.6 and Magma A.2.6 KAT sources.

gogost (NOT used for this primitive):
- This OMAC is the module's own clean-room code; gogost is not imported by `omac.go`.
- Differential parity tests against gogost live in `gostcrypto-compat/parity/omac/`
  (GPL-licensed; never imported by this module).
