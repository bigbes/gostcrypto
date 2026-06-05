# OMAC / CMAC (GOST R 34.13-2015 MAC mode)

This is a **clean-room re-implementation guide**. A reader must be able to
reimplement the GOST MAC mode (OMAC1 / CMAC) in Go *without* reading
`go.stargrave.org/gogost/v7`, using only this document plus the cited RFCs and
GOST standard.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

**Status: in-repo reimplementation.** This primitive is **not** sourced from
gogost. The repo provides its own OMAC/CMAC in `internal/gost/omac.go`
(`NewOMAC`, `OMAC.Write`, `OMAC.Sum`), layered over any `crypto/cipher.Block`
(the block cipher itself — Kuznyechik `gost3412128`, Magma `gost341264` — still
comes from gogost, but that is a *separate* primitive with its own guide:
`../kuznyechik/kuznyechik-gost34122015.md`). The de-facto spec this file
documents is the behavioral contract in `internal/gost/omac.go`, cross-checked
against gost-engine v3.0.3 (Tarantool's upstream) and RFC 4493.

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

- **TLS record protection for RFC 9367 GOST suites** — Kuznyechik-CTR-OMAC
  (`0xC100`) and Magma-CTR-OMAC (`0xC101`). The protector
  `ctrOMACProtector` calls `gost.NewOMAC(macBlock, p.tagSize)` once per record
  in both `Seal` (`tls/internal/record/protection_ctromac_gost.go:192`) and
  `Open` (`:262`). Here `tagSize` is the **full** block width:
  `16` for Kuznyechik (`:95`) and `8` for Magma (`:131`). See the sibling guide
  `../ctracpkm/ctr-acpkm.md` for the CTR half of these suites.
- **kexp15 key-export wrapper** — `internal/gost/kexp15_gost.go:105` computes
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
   `cmacSubkeys` (`internal/gost/omac.go:62-82`) selects `rb = 0x87` for
   `bs == 16` and `rb = 0x1b` for `bs == 8`, and `panic`s otherwise
   (`omac.go:75-76`). The 64-bit constant `0x1b` is the spot most
   reimplementers get wrong — RFC 4493 only states `0x87`; the 64-bit value
   comes from RFC 8645 §6.3.6 (OMAC-ACPKM-Master, `R_64 = 0^59|11011 =
   0x1b`). Engine equivalent: OpenSSL's `CMAC_Init`
   derives both subkeys internally per the cipher's block size
   (`tmp/engine/gost_omac.c:149`, `CMAC_Init(... cipher ...)`).

2. **The shift is big-endian over the whole block.** `shiftLeftXorRb`
   (`omac.go:86-97`): `msb = in[0] >> 7` reads the leading bit of byte 0;
   `out[i] = (in[i] << 1) | (in[i+1] >> 7)` shifts left carrying the next
   byte's top bit down; the final byte is `in[last] << 1`, then
   `out[last] ^= rb` iff `msb == 1` (`omac.go:88-95`). `Rb` lands in the
   **last** byte. RFC 4493 §2.3 defines exactly this "one-bit left shift of
   the entire 128-bit string". A little-endian shift (carry flowing the other
   way, `Rb` in byte 0) is the classic bug.

3. **Last-block selection keys on `len(buf) == blockSize`, and a buffered full
   block is a legal, intentional state.** `Write` deliberately does **not**
   flush a full block if it is the trailing data — it holds up to `blockSize`
   bytes in `buf` so `Sum` can tell "exactly `n` unprocessed bytes" (the `K1`
   path) from "fewer than `n`" (the `K2`/padding path)
   (`omac.go:99-129`, esp. the `len(o.buf) == o.blockSize && len(p) > 0`
   guard at `omac.go:122`). In `Sum`: if `len(bufSnap) == blockSize`,
   `finalBlock = bufSnap XOR K1` (`omac.go:150-152`); else pad with `0x80`
   then zeros and XOR `K2` (`omac.go:154-159`). This matches RFC 4493 §2.4
   step 4's "if M_n is complete … else …". An off-by-one (flushing the full
   final block early, then padding an empty block with `K2`) yields a wrong
   tag on every block-aligned message.

4. **Padding is `0x80` then zeros (GOST pad-mode 2 = RFC 4493 padding).** The
   empty / partial block becomes `bufSnap || 0x80 || 0x00…` before the `K2`
   XOR (`omac.go:155-159`). The empty-message case (`len(bufSnap) == 0`) writes
   `0x80` at index 0 — note this is NOT the GOST R 34.11-94 empty-input quirk
   in `TODO.md`; CMAC's empty-message handling is unambiguous and unaffected.

5. **Truncation = take the leading `tagSize` bytes (MSB).**
   `Sum` returns `stateSnap[:o.tagSize]` (`omac.go:164`). `NewOMAC` validates
   `1 <= tagSize <= blockSize` (`omac.go:42-44`). This is RFC 4493's
   `MSB_tlen` and matches gost-engine: `omac_imit_final` does
   `memcpy(md, mac, c->dgst_size)` (`tmp/engine/gost_omac.c:95`), where
   `dgst_size` defaults to the full block (`tmp/engine/gost_omac.c:50-55`:
   8 for Magma, 16 for Grasshopper) and can be narrowed via
   `EVP_MD_CTRL_XOF_LEN` to any `1..8` (Magma) or `1..16` (Kuznyechik)
   (`tmp/engine/gost_omac.c:218-231`). The repo's TLS CTR-OMAC suites use the
   full width (16/8); the published standard KATs truncate to 8/4 (below);
   kexp15 truncates to its `macLen` (`internal/gost/kexp15_gost.go:105`).

6. **`Sum` is non-destructive; the receiver survives repeated `Sum` and later
   `Write`.** `Sum` snapshots `state` and `buf` and operates on the copies
   (`omac.go:142-165`). This mirrors OpenSSL's EVP "finalize-on-copy" semantics
   (the same property documented for IMIT in `CLAUDE.md`) and is required so a
   protector can MAC, then keep streaming. Pinned by `TestOMAC_SumIdempotent`
   and `TestOMAC_SumAfterWrite` (`internal/gost/omac_test.go:116,152`). A
   reimplementation that mutates `state` inside `Sum` will corrupt any
   subsequent `Write`.

7. **The block cipher is used in ENCRYPT direction throughout** — including for
   `L = E_K(0)` (`omac.go:66-67`) and every CBC step
   (`cbcStep`, `omac.go:133-136`). CMAC never decrypts. (Trivially true here
   because `cbcStep` only calls `block.Encrypt`, but worth stating: do not
   "decrypt to verify" — recompute and compare in constant time at the caller.)

## Test vectors

All vectors live in `internal/gost/omac_test.go` (standard GOST R 34.13-2015
KATs) and `internal/gost/omac_engine_test.go` (live gost-engine CLI oracle).

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

This is the exact assertion in `TestOMAC_Kuznyechik_EngineOracle`
(`internal/gost/omac_engine_test.go:19-36`); the oracle command above was
re-run while writing this guide and returned the identical tag. Because
`"hello"` is shorter than a block, this vector also exercises the `K2`/padding
branch end-to-end.

### Standard GOST R 34.13-2015 KATs (truncated)

- **Kuznyechik, GOST R 34.13-2015 A.1.6** — `omac_test.go:24`
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

- **Magma, GOST R 34.13-2015 A.2.6** — `omac_test.go:75`
  (`TestOMAC_Magma_KAT`), vector from `tmp/engine/test_digest.c:79-109`:
  ```
  key (32B): ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  P  (32B):  92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41
  tag (4B):  154e7210              (leading 4 bytes of the 8-byte CMAC)
  ```
  `P` is a multiple of 8 → **`K1`** path; truncated to 4 bytes.

### Property coverage

- `TestOMAC_SumIdempotent` (`omac_test.go:116`) — two `Sum`s, no `Write`
  between, equal bytes.
- `TestOMAC_SumAfterWrite` (`omac_test.go:152`) — `Write half1; Sum; Write
  half2; Sum` equals a fresh OMAC over the concatenation (proves `Sum` does not
  mutate state, and that split `Write`s match a one-shot `Write`).

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

This OMAC has **no gogost equivalent** (gogost ships no standalone OMAC — see
`internal/gost/omac.go:5-19`, the repo's own code), so differential testing
runs the clean-room impl against two *non-gogost* references: (1) the in-repo
`internal/gost.NewOMAC` (the de-facto spec this guide documents) and (2) the
gost-engine `dgst -mac kuznyechik-mac` CLI oracle from `CLAUDE.md`. Pin the
A.1.6 / A.2.6 / `hello`-oracle KATs as fixed anchors, then fuzz a **random key
+ arbitrary-length message** for *both* block sizes — Kuznyechik (128-bit,
`gost3412128.NewCipher`, `Rb=0x87`) and Magma (64-bit, `gost341264.NewCipher`,
`Rb=0x1b`) — comparing clean-room vs in-repo on every input. The engine CLI is
only practical to drive in the table test (process spawn per call is too slow
to fuzz), so the fuzz loop diffs clean-room against the in-repo reference and
treats the oracle as the pinned-KAT anchor.

The CLI oracle has no Go API; shell out to it exactly as `CLAUDE.md` specifies
(only Kuznyechik full-width 16-byte tags are published this way):

```go
//go:build gost

package yourpkg

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
(engine-oracle `hello` vector, A.1.6 Kuznyechik, A.2.6 Magma). `mynew` is the
clean-room package under test.

> **Note on the example API shape.** The harness below uses an illustrative
> one-shot helper `mynew.OMAC(cipherName, key, msg, tagSize) ([]byte, error)`
> purely to keep the example compact — this is *not* the documented surface.
> The de-facto spec this guide documents is the streaming
> `New(block, tagSize) → Write → Sum` shape of `internal/gost.NewOMAC` (see
> the `file:line` citations). A clean-room implementer should expose the
> streaming surface and adapt these examples to it (e.g. construct, `Write`,
> `Sum`), not literally implement the one-shot helper.

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"

	gost "go.bigb.es/tlsdialer/internal/gost" // in-repo reference
	mynew "github.com/.../mynew/omac"    // clean-room impl under test
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestOMACConformance(t *testing.T) {
	cases := []struct {
		name    string
		cipher  string // "kuz" | "magma"
		key     string
		msg     string // hex; "" for the ASCII "hello" oracle vector
		ascii   string
		tagSize int
		want    string
		oracle  bool // also cross-check the gost-engine CLI
	}{
		{
			// engine-oracle vector, omac.md "Inline verified Kuznyechik OMAC KAT"
			name:    "kuz/hello/oracle/full16",
			cipher:  "kuz",
			key:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ascii:   "hello",
			tagSize: 16,
			want:    "96e6c1913fd788e3922e617fdd341edf",
			oracle:  true,
		},
		{
			// GOST R 34.13-2015 A.1.6 — tmp/engine/test_digest.c:71-104
			name:    "kuz/A.1.6/trunc8",
			cipher:  "kuz",
			key:     "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
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
			cipher:  "magma",
			key:     "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			msg:     "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41",
			tagSize: 4,
			want:    "154e7210",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(t, tc.key)
			var msg []byte
			if tc.ascii != "" {
				msg = []byte(tc.ascii)
			} else {
				msg = mustHex(t, tc.msg)
			}
			want := mustHex(t, tc.want)

			// 1. clean-room impl under test.
			got, err := mynew.OMAC(tc.cipher, key, msg, tc.tagSize)
			if err != nil {
				t.Fatalf("mynew.OMAC: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("clean-room: got %x, want %x", got, want)
			}

			// 2. in-repo reference (the de-facto spec).
			var block interface {
				BlockSize() int
				Encrypt(dst, src []byte)
				Decrypt(dst, src []byte)
			}
			switch tc.cipher {
			case "kuz":
				block = gost3412128.NewCipher(key)
			case "magma":
				block = gost341264.NewCipher(key)
			}
			ref, err := gost.NewOMAC(block, tc.tagSize)
			if err != nil {
				t.Fatalf("gost.NewOMAC: %v", err)
			}
			ref.Write(msg)
			if r := ref.Sum(nil); !bytes.Equal(r, want) {
				t.Fatalf("in-repo ref: got %x, want %x", r, want)
			}

			// 3. gost-engine CLI oracle (Kuznyechik full-width only).
			if tc.oracle {
				o, err := engineOMACKuznyechik(key, msg)
				if err != nil {
					t.Fatalf("engine oracle: %v", err)
				}
				if !bytes.Equal(o, want) {
					t.Fatalf("engine oracle: got %x, want %x", o, want)
				}
			}
		})
	}
}
```

Fuzz harness — seeds from the KAT inputs, normalizes the random `[]byte` into
OMAC's fixed-size arguments (32-byte key, full-width tag), runs clean-room vs
the in-repo reference on identical bytes for both block sizes, and fails on any
divergence. OMAC is deterministic, so this is direct differential parity (not a
round-trip):

```go
//go:build gost

package yourpkg

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3412128"
	"go.stargrave.org/gogost/v7/gost341264"

	gost "go.bigb.es/tlsdialer/internal/gost"
	mynew "github.com/.../mynew/omac"
)

func FuzzOMACConformance(f *testing.F) {
	// Seed from the pinned KAT inputs (key||msg).
	seed := func(keyHex, msgHex string) {
		k, _ := hex.DecodeString(keyHex)
		m, _ := hex.DecodeString(msgHex)
		f.Add(append(append([]byte{}, k...), m...))
	}
	seed("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
		"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a")
	seed("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		"92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")
	f.Add([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhello"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Normalize: first 32 bytes (cycled) = key, remainder = message.
		key := make([]byte, 32)
		for i := range key {
			if len(raw) > 0 {
				key[i] = raw[i%len(raw)]
			}
		}
		var msg []byte
		if len(raw) > 32 {
			msg = raw[32:]
		}

		check := func(name string, newBlock func() interface {
			BlockSize() int
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
		}, cipherName string, tagSize int) {
			got, err := mynew.OMAC(cipherName, key, msg, tagSize)
			if err != nil {
				t.Fatalf("%s mynew.OMAC: %v", name, err)
			}
			ref, err := gost.NewOMAC(newBlock(), tagSize)
			if err != nil {
				t.Fatalf("%s gost.NewOMAC: %v", name, err)
			}
			ref.Write(msg)
			want := ref.Sum(nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s mismatch: key=%x msg=%x clean=%x ref=%x",
					name, key, msg, got, want)
			}
		}

		check("kuz", func() interface {
			BlockSize() int
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
		} {
			return gost3412128.NewCipher(key)
		}, "kuz", 16)
		check("magma", func() interface {
			BlockSize() int
			Encrypt(dst, src []byte)
			Decrypt(dst, src []byte)
		} {
			return gost341264.NewCipher(key)
		}, "magma", 8)
	})
}
```

Run:

```sh
go test -tags gost -run TestOMACConformance ./yourpkg/
go test -tags gost -fuzz=FuzzOMACConformance -fuzztime=30s ./yourpkg/
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

Repo (in-repo reimplementation — the de-facto spec):
- `internal/gost/omac.go:40-56` — `NewOMAC`, tagSize validation, subkey precompute.
- `internal/gost/omac.go:62-82` — `cmacSubkeys` (`L = E_K(0)`, `Rb` per block size, panic).
- `internal/gost/omac.go:86-97` — `shiftLeftXorRb` (big-endian shift, `Rb` in last byte).
- `internal/gost/omac.go:99-129` — `Write` (deferred full-block flush; full-block-in-buf invariant).
- `internal/gost/omac.go:133-136` — `cbcStep` (XOR-then-Encrypt; encrypt direction only).
- `internal/gost/omac.go:142-165` — `Sum` (non-destructive; `K1` vs `K2`/pad; `[:tagSize]` truncation).
- `tls/internal/record/protection_ctromac_gost.go:95,131` — full-width tag sizes (16 / 8).
- `tls/internal/record/protection_ctromac_gost.go:192,262` — `Seal`/`Open` call sites.
- `internal/gost/kexp15_gost.go:103-119` — `OMAC(mac_key, iv || shared_key)`, truncated to `macLen`.
- Tests: `internal/gost/omac_test.go`, `internal/gost/omac_engine_test.go`.

gost-engine v3.0.3 (parity target — confirms plain CMAC + truncation):
- `tmp/engine/gost_omac.c:79` — `CMAC_Update`.
- `tmp/engine/gost_omac.c:93` — `CMAC_Final`.
- `tmp/engine/gost_omac.c:95` — `memcpy(md, mac, c->dgst_size)` truncation.
- `tmp/engine/gost_omac.c:48-56` — default `dgst_size` (8 Magma / 16 Grasshopper).
- `tmp/engine/gost_omac.c:149` — `CMAC_Init` (derives `K1`/`K2` per cipher block size).
- `tmp/engine/gost_omac.c:218-231` — `EVP_MD_CTRL_XOF_LEN` configurable tag length (1..8 / 1..16).
- `tmp/engine/test_digest.c:71-109` — Kuznyechik A.1.6 and Magma A.2.6 KAT sources.

gogost (NOT used for this primitive):
- This OMAC is the repo's own code; gogost is not imported by `omac.go`.
