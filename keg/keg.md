# KEG — key export generation (RFC 9189 TLS GOST KEX)

KEG ("key export generation") is the GOST 2018 TLS 1.2 key-derivation step that
turns a Diffie-Hellman-style shared secret into the 64-byte symmetric key block
used to *export* (wrap) the TLS pre-master secret. It is specified in
**R 1323565.1.020-2018 §6.4.5.1** and used by the GOST 2012 cipher suites of
**RFC 9189** (TLS 1.2 GOST suites, e.g. `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`,
`TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`, suite IDs `0xC102`/`0xC103`, and the
RFC 9367 follow-ons `0xC100`/`0xC101`). It is the engine function `gost_keg`.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

KEG sits between two other primitives:

```
VKO 2012-256  (RFC 7836 shared-secret agreement)   ──┐
                                                      ├──►  KEG  ──►  64-byte expkeys
KDFTree2012_256 (R 50.1.113-2016 / RFC 7836 §4.4)  ──┘                │
                                                                      ├─ expkeys[ 0:32] = MAC key
                                                                      └─ expkeys[32:64] = cipher key
```

The 64-byte output then feeds `gost_kexp15` (KExp15 key wrap) to encrypt the
32-byte pre-master secret. KEG itself produces *only* the key block; it does not
do the wrapping.

## Where this repo uses it

- Wrapper / de-facto spec: `internal/gost/keg_gost.go` — `KEG2012_256(curve, serverPubRaw, clientPrivRaw, ukmSource)`.
- KDF helper it calls: `internal/gost/kdftree_gost.go` — `KDFTree2012_256`.
- TLS call site (client ClientKeyExchange build): `tls/internal/ke/gost2018.go:187-202`.
  There `expkeys[:32]` is passed as the **MAC** key and `expkeys[32:]` as the
  **cipher** key to `gost.Kexp15`, and the IV is `ukm[24:24+ivLen]`.
- Handshake wiring: `tls/internal/handshake/kex_gost.go:51`.

**statusKind: gogost-backed.** `KEG2012_256` does not reimplement the GOST
primitives — it calls gogost's `gost3410.KEK2012256` (VKO) and reuses our
`KDFTree2012_256`, which itself calls gogost's `gost34112012256.New`
(Streebog-256) as the HMAC hash. The UKM-adjust and label/seed plumbing are
local; the cryptographic cores come from `go.stargrave.org/gogost/v7`
(GPL-3.0, vendored at `third_party/gogost`). A GPL-free reimplementation must
supply Streebog-256, HMAC, and VKO 2012-256 (EC point multiply on the TC26
curves) and then wire them exactly as this doc describes.

## Specification

KEG for the 256-bit case (`NID_id_GostR3410_2012_256`) is the engine function
`gost_keg`, ground truth at `tmp/engine/gost_ec_keyx.c:132-179`. The algorithm:

### Inputs

| Name          | Size      | Meaning |
|---------------|-----------|---------|
| `ukm_source`  | 32 bytes  | UKM material. In RFC 9189 TLS this is `Streebog256(client_random ‖ server_random)` (64-byte concatenation → 32-byte digest), see `tls/internal/ke/gost2018.go:160-165`. |
| `pub_key`     | EC point  | Peer's GOST 2012-256 public key (in this repo, 64-byte raw `LE X ‖ LE Y`; note gogost/engine raw order is `LE X ‖ LE Y`). |
| `priv_key`    | scalar    | Local GOST 2012-256 private key (32-byte LE). |
| Curve         | —         | A GOST R 34.10-2012 256-bit curve, e.g. TC26 ParamSet A (OID `1.2.643.7.1.2.1.1.1`). |

### Step 1 — UKM adjustment

`tmp/engine/gost_ec_keyx.c:136-146`:

```
real_ukm[0..15] = 0
if ukm_source[0..15] == 16 zero bytes:
    real_ukm[15] = 1                      // avoid a zero VKO factor
else:
    real_ukm = reverse(ukm_source[0..15]) // byte-reverse the first 16 bytes
```

Only the **first 16 bytes** of `ukm_source` feed VKO; they are byte-reversed.
The all-zero special case sets `real_ukm = 00…00 01` (16 bytes) so the VKO
scalar factor is never 0.

### Step 2 — VKO 2012-256 shared secret

`tmp/engine/gost_ec_keyx.c:159-161`:

```
tmpkey[0..31] = VKO_compute_key(pub_key, priv_key, real_ukm, ukm_size=16,
                                vko_dgst = NID_id_GostR3411_2012_256)
```

VKO (RFC 7836 §4.3, "VKO_GOSTR3411_2012_256") computes:

1. `scalar = (UKM · d) mod q` where `d` is the private key and `q` the curve
   order. **UKM is read little-endian** (`BN_lebin2bn(real_ukm, 16, scalar)`,
   `tmp/engine/gost_ec_keyx.c:60`). Because `real_ukm` was already byte-reversed
   in Step 1, the net integer equals the big-endian reading of `ukm_source[0..15]`.
2. `(X, Y) = scalar · pub_key` (EC point multiply, with cofactor handling — see
   the deltas section; TC26 256-A has cofactor 4).
3. Serialize `databuf = LE(X, half_len) ‖ LE(Y, half_len)` where `half_len` is
   the field byte length (32 for 256-bit), `tmp/engine/gost_ec_keyx.c:99-100`.
4. `tmpkey = Streebog256(databuf)` — i.e. `EVP_Digest(databuf)` with
   GOST R 34.11-2012-256, `tmp/engine/gost_ec_keyx.c:108-111`.

Output `tmpkey` is 32 bytes.

### Step 3 — KDFTree expansion to 64 bytes

`tmp/engine/gost_ec_keyx.c:166-169`:

```
keyout[0..63] = gost_kdftree2012_256(
                    key   = tmpkey,            // 32 bytes
                    label = "kdf tree",        // 8 ASCII bytes, no NUL
                    seed  = ukm_source + 16,   // bytes [16:24], 8 bytes
                    keyout_len = 64,
                    representation = 1)
```

`gost_kdftree2012_256` (R 50.1.113-2016 §4.5 / RFC 7836 §4.4 KDF_TREE_GOSTR3411_2012_256),
ground truth `tmp/engine/gost_keyexpimp.c:201-259`. For each iteration
`i = 1 .. keyout_len/32`:

```
block_i = HMAC_Streebog256( key,
              I2BE(i, representation)   // representation=1 ⇒ single byte i
            ‖ label                     // "kdf tree"
            ‖ 0x00                      // one zero separator byte
            ‖ seed                      // ukm_source[16:24]
            ‖ L )                       // big-endian bit-length, leading zeros stripped
keyout[(i-1)*32 : i*32] = block_i
```

For 64-byte output there are **2 iterations** (`i = 1`, `i = 2`).

**The length field `L`** is `be32(keyout_len * 8)` = `be32(512)` =
`00 00 02 00`, with leading zero bytes stripped → the two bytes `02 00`
(`tmp/engine/gost_keyexpimp.c:212, 227-231`; our wrapper hardcodes the 2-byte
`0x02 0x00` form at `internal/gost/kdftree_gost.go:36-37`).

So each HMAC message is exactly:

```
i(1) ‖ "kdf tree"(8) ‖ 0x00(1) ‖ seed(8) ‖ 0x02 0x00(2)   = 20 bytes
```

with `i ∈ {0x01, 0x02}`.

### Output split

The 64-byte result is consumed as two 32-byte keys
(`tls/internal/ke/gost2018.go:189`):

```
expkeys[ 0:32] = MAC key      (fed to gost_kexp15 as the OMAC/IMIT key)
expkeys[32:64] = cipher key   (fed to gost_kexp15 as the CTR/encrypt key)
```

Note the **MAC key comes first**. This is the order `gost_kexp15` expects
(`expkeys+0 = mac`, `expkeys+32 = cipher`, `tmp/engine/gost_ec_keyx.c:486-498`).

### Sizes / constants summary

| Quantity                         | Value |
|----------------------------------|-------|
| `ukm_source` length              | 32 bytes (exactly) |
| VKO UKM length (`real_ukm`)      | 16 bytes (`ukm_source[0:16]`, reversed) |
| KDF seed                         | `ukm_source[16:24]`, 8 bytes |
| (IV, consumed downstream by KEX) | `ukm_source[24:24+ivLen]` — *not* part of KEG |
| VKO output (`tmpkey`)            | 32 bytes |
| KEG output (`keyout`/`expkeys`)  | 64 bytes |
| KDF label                        | `"kdf tree"` (8 bytes, no NUL terminator) |
| KDF separator                    | `0x00` |
| KDF length suffix `L`            | `0x02 0x00` (512 bits, big-endian, leading zeros stripped) |
| KDF representation               | 1 (one-byte iteration counter) |
| KDF hash                         | Streebog-256 (GOST R 34.11-2012-256) inside HMAC |

## RFC ↔ implementation deltas

Every point where the implementations reinterpret or under-specify the RFC.
Each cites the RFC plus the source line.

1. **UKM is little-endian, twice-reversed in this stack.** R 1323565.1.020-2018
   gives the VKO factor as an integer. The engine forms `real_ukm` by
   *byte-reversing* `ukm_source[0:16]` (`tmp/engine/gost_ec_keyx.c:144-145`) and
   then reads it **little-endian** in `BN_lebin2bn` (`:60`). gogost's path is the
   same integer by a different route: our wrapper reverses to `realUKM`
   (`internal/gost/keg_gost.go:56-57`), then `gost3410.NewUKM` reverses *again*
   to convert LE→big.Int (`third_party/gogost/gost3410/ukm.go:23-28`). Net: the
   VKO scalar = `bigEndianInt(ukm_source[0:16])`. A from-scratch impl must not
   "simplify" by removing one reversal — match the *net* integer, and test
   against the oracle vector below.

2. **All-zero-UKM special case.** Not in the bare RFC formula. If
   `ukm_source[0:16]` is 16 zero bytes, set the last byte of `real_ukm` to 1
   (`tmp/engine/gost_ec_keyx.c:140-142`, mirrored at
   `internal/gost/keg_gost.go:53-54`). Without this the VKO scalar would be 0 and
   the agreement degenerate. Easy to miss; deterministic test it.

3. **Cofactor multiplication inside VKO.** TC26 256-bit ParamSet A has cofactor
   4. The engine relies on `gost_ec_point_mul` to clear the cofactor (the
   explicit `BN_lshift(scalar,2)` is `#if 0`-disabled,
   `tmp/engine/gost_ec_keyx.c:65-78`). gogost multiplies the UKM factor by the
   curve cofactor `prv.C.Co` explicitly inside `KEK`
   (`third_party/gogost/gost3410/vko.go:28-34`). A reimplementation must apply
   the cofactor exactly once; getting this wrong yields a wrong (but
   plausible-looking) `tmpkey` and a 64-byte block that still has the right shape
   — only the KAT will catch it.

4. **VKO point serialization endianness.** `databuf = LE(X) ‖ LE(Y)`
   (`tmp/engine/gost_ec_keyx.c:99-100`, `BN_bn2lebinpad`). GOST is little-endian
   here in a place most ECC code is big-endian. The hash input order is X then Y.

5. **VKO raw public-key order vs. engine SPKI.** gogost `PublicKey.Raw()` and the
   engine SubjectPublicKeyInfo OCTET STRING both encode `LE X ‖ LE Y`. Ground
   truth: gogost `RawLE()` builds `BE(Y) ‖ BE(X)` then reverses the whole buffer
   → `LE X ‖ LE Y` (`third_party/gogost/gost3410/public.go:65-86`); the engine
   serializes `BN_bn2lebinpad(X) ‖ BN_bn2lebinpad(Y)` = `LE X ‖ LE Y`
   (`tmp/engine/gost_ec_keyx.c:99-100`). **Caveat:** the in-repo test comments at
   `internal/gost/keg_gost_test.go:24-25, 111-112` label this "LE Y ‖ LE X" — those
   comments are mislabeled; the bytes themselves and both reference implementations
   are `LE X ‖ LE Y`. Do not transpose X/Y on the strength of those comments.

6. **KDF length field is variable-width, leading-zeros-stripped.** RFC 7836's
   KDF_TREE uses a fixed `L`; the engine computes `be32(len*8)` then strips
   leading zero bytes (`tmp/engine/gost_keyexpimp.c:212, 227-231`), so 512 bits
   becomes the 2-byte `02 00`, not `00 00 02 00`. Our wrapper hardcodes the
   2-byte form (`internal/gost/kdftree_gost.go:36-37`) which is correct *only for
   32 ≤ keyout_len ≤ 8160*. For KEG (64 bytes) this is always `0x02 0x00`.

7. **KDF iteration counter width is `representation`, not fixed 4 bytes.** KEG
   calls with `representation = 1`, so the counter is a **single byte** `i`
   (`tmp/engine/gost_ec_keyx.c:168`, engine `rep_ptr = &iter_net + (4 - representation)`
   at `:235-236`). Our wrapper emits one byte `byte(i)`
   (`internal/gost/kdftree_gost.go:42-43`). A 4-byte counter would change every
   HMAC input and break the KAT.

8. **KDF label has no NUL and a separate `0x00` separator follows it.** The
   message is `i ‖ label ‖ 0x00 ‖ seed ‖ L`. The `0x00` is an explicit separator
   byte (`tmp/engine/gost_keyexpimp.c:243`), *not* a C string terminator — the
   label `"kdf tree"` is exactly 8 bytes with the separator added after it. Don't
   fold them.

9. **MAC-key / cipher-key ordering.** KEG just yields 64 bytes; the split
   convention (`[:32]=MAC`, `[32:]=cipher`) lives at the call site
   (`tls/internal/ke/gost2018.go:189-202`) and matches `gost_kexp15`
   (`tmp/engine/gost_ec_keyx.c:486-498`). Document this so the consumer doesn't
   swap halves.

10. **Streebog empty-input divergence does NOT apply here.** The known
    gogost↔engine empty-input finalization divergence (TODO.md "Disagreements",
    GOST R 34.11-94) is irrelevant: KEG hashes a 64-byte VKO `databuf` (never
    empty) and HMAC over non-empty messages. Streebog-2012 (not the -94 hash) is
    used throughout, and HMAC never feeds an empty message. The CryptoPro
    key-meshing divergence (TODO.md, IMIT) also does not touch KEG — KEG has no
    GOST 28147 MAC. No TODO.md divergence affects this primitive.

## Test vectors

### In-repo KATs

- `internal/gost/keg_gost_test.go:105-166` — `TestKEG2012_256_EngineOracle`.
  Validated against gost-engine 3.0.3 via
  `openssl pkeyutl -derive -engine gost` (the exact command is quoted at
  `internal/gost/keg_gost_test.go:7-13`).
- `internal/gost/keg_gost_test.go:40-81` — `TestKEG2012_256_RoundTrip`, proving
  symmetry `KEG(B_pub, A_priv, ukm) == KEG(A_pub, B_priv, ukm)`
  (mirrors `tmp/engine/test_derive.c:338-364`).
- `internal/gost/kdftree_gost.go` is exercised by `gost2015_acpkm_omac_init`
  parity; KDF ground truth: `tmp/engine/test_keyexpimp.c:164`.

### Complete runnable vector (256-bit, TC26 ParamSet A)

Curve: GOST R 34.10-2012 256-bit, TC26 ParamSet A (OID `1.2.643.7.1.2.1.1.1`,
gogost `CurveIdtc26gost341012256paramSetA`).

```
priv A (LE, 32 B):
  9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d
pub A  (LE X ‖ LE Y, 64 B):
  a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c
  6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4
priv B (LE, 32 B):
  bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607
pub B  (LE X ‖ LE Y, 64 B):
  c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888
  8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602

ukm_source (32 B):
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    → real_ukm  = reverse(00..0f) = 0f0e0d0c0b0a09080706050403020100
    → kdf seed  = ukm_source[16:24] = 1011121314151617

KEG output expkeys (64 B), symmetric for (privA,pubB) and (privB,pubA):
  bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900
  39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b

  → MAC key    expkeys[ 0:32] = bc2b44f5…9d671900
  → cipher key expkeys[32:64] = 39eb73d0…2db1e62b
```

To reproduce against the engine oracle directly:

```sh
OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
  /opt/homebrew/opt/openssl@3/bin/openssl pkeyutl -derive -engine gost \
    -inkey privA_tc26.pem -peerkey pubB_tc26.pem \
    -pkeyopt ukmhex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    -out keg_AB.bin
```

## Re-implementation checklist

Each step is independently testable against a vector; do them in order.

1. **Streebog-256 (GOST R 34.11-2012-256, RFC 6986).** Implement and KAT against
   RFC 6986 / engine digest vectors. Needed both as the VKO finalizer and as the
   HMAC hash. (Reuse the project's Streebog reimpl when it lands; see TODO.md
   "BSD reimplementation" item 2.)
2. **HMAC-Streebog-256.** Standard HMAC (block size 64) over Streebog-256. Verify
   with any HMAC-Streebog test vector.
3. **KDFTree2012_256.** Implement `i(1B) ‖ "kdf tree" ‖ 0x00 ‖ seed(8B) ‖ 0x02 0x00`,
   2 HMAC iterations, concatenated to 64 bytes. Unit-test with a fixed 32-byte
   `key` and 8-byte `seed` against `internal/gost/kdftree_gost.go` output.
4. **VKO 2012-256 (RFC 7836).** EC point multiply on TC26 256-A (cofactor 4!),
   serialize `LE(X) ‖ LE(Y)`, Streebog-256. KAT: feed `real_ukm`, `priv A`,
   `pub B` from the vector above and check `tmpkey` equals the intermediate (you
   can expose it temporarily to assert it, then derive the final 64 bytes).
5. **UKM adjust.** `real_ukm = reverse(ukm_source[0:16])`, with the all-zero
   special case → trailing `01`. Unit-test both branches.
6. **Assemble KEG.** real_ukm → VKO → KDFTree(tmpkey, "kdf tree", ukm_source[16:24], 64).
   Assert the full 64-byte vector above and the symmetry property
   (swap priv/pub between A and B → identical output).
7. **Split & wire.** Confirm consumers read `[:32]` as MAC, `[32:]` as cipher key,
   and the IV `ukm_source[24:24+ivLen]` is taken by the *caller*, not KEG.

## Conformance & fuzz testing

Differential strategy for a clean-room KEG: there is **no gogost-level "KEG"
primitive** to diff against — gogost only exposes the VKO and KDF cores, and KEG
assembles them. So the two reference targets are (1) the in-repo
`internal/gost.KEG2012_256` (`internal/gost/keg_gost.go:36`), which is itself
gogost-backed and the de-facto spec this repo matches, and (2) the pinned
RFC 9189 / engine-oracle vector inlined in this doc (the 64-byte `expkeys` block
from the TC26 ParamSet A row above, cross-checked against
`openssl pkeyutl -derive -engine gost`). The fuzz contract: feed random
private-key + UKM material through both the clean-room impl and the in-repo
reference, normalize to KEG's fixed-size arguments (64-byte raw pub, 32-byte LE
priv, 32-byte UKM), and assert the two 64-byte outputs are byte-identical. KEG is
pair-symmetric (`KEG(B_pub, A_priv, ukm) == KEG(A_pub, B_priv, ukm)`,
`internal/gost/keg_gost_test.go:40`), so the fuzzer also asserts that round-trip
property — a free oracle that needs no external key.

Note on the curve handle: `internal/gost.Curve` is an opaque wrapper whose
`inner` field is **unexported**, so a clean-room test *outside* the `gost`
package cannot write `&gost.Curve{inner: …}`. Construct the 256-bit TC26-A curve
via the exported constructor the package provides:
`gost.CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})`
(OID `1.2.643.7.1.2.1.1.1`). The examples below use that form. The clean-room
impl under test is imported as `mynew`.

### Table-driven KAT

Reuses the exact pinned hex from the "Complete runnable vector" row above; no new
bytes are invented.

```go
//go:build gost

package keg_conformance

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	gost "go.bigb.es/tlsdialer/internal/gost" // in-repo reference
	mynew "example.com/keg"          // clean-room impl under test
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestKEGConformance(t *testing.T) {
	curve, err := gost.CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
	if err != nil {
		t.Fatalf("CurveByOID: %v", err)
	}

	const (
		privAHex = "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d"
		pubBHex  = "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888" +
			"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602"
		privBHex = "bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607"
		pubAHex  = "a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c" +
			"6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4"
		ukmHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		wantHex = "bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900" +
			"39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b"
	)

	cases := []struct {
		name              string
		pub, priv         string
	}{
		{"privA_pubB", pubBHex, privAHex},
		{"privB_pubA", pubAHex, privBHex}, // symmetric: same expkeys
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, ukm := mustHex(t, tc.pub), mustHex(t, tc.priv), mustHex(t, ukmHex)
			want := mustHex(t, wantHex)

			ref, err := gost.KEG2012_256(curve, pub, priv, ukm)
			if err != nil {
				t.Fatalf("reference KEG: %v", err)
			}
			if !bytes.Equal(ref[:], want) {
				t.Fatalf("reference != pinned vector:\n got %x\nwant %x", ref[:], want)
			}

			got, err := mynew.KEG2012_256(curve, pub, priv, ukm)
			if err != nil {
				t.Fatalf("clean-room KEG: %v", err)
			}
			if got != ref {
				t.Fatalf("clean-room != reference:\n got %x\n ref %x", got[:], ref[:])
			}
		})
	}
}
```

### Fuzz harness

Seeds the corpus from the KAT inputs, then for each random draw derives a fresh
A/B keypair so the symmetric round-trip oracle holds without a pinned answer.
`GenerateEphemeralKey(curve, io.Reader)` (`internal/gost/keg_gost_test.go:53`) is
the in-repo helper that turns a byte seed into a `(privRaw, pubRaw)` pair.

```go
//go:build gost

package keg_conformance

import (
	"bytes"
	"encoding/asn1"
	"testing"

	gost "go.bigb.es/tlsdialer/internal/gost"
	mynew "example.com/keg"
)

func FuzzKEGConformance(f *testing.F) {
	curve, err := gost.CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
	if err != nil {
		f.Fatalf("CurveByOID: %v", err)
	}

	// Seed from the KAT: two 32-byte key seeds + one 32-byte UKM = 96 bytes.
	f.Add(bytes.Repeat([]byte{0x11}, 96))
	f.Add(append(append(
		mustHexF(f, "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d"),
		mustHexF(f, "bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607")...),
		mustHexF(f, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")...))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Normalize to KEG's fixed-size arguments: 32B seedA, 32B seedB, 32B ukm.
		buf := make([]byte, 96)
		copy(buf, raw)
		seedA, seedB, ukm := buf[0:32], buf[32:64], buf[64:96]

		privA, pubA, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(seedA))
		if err != nil {
			t.Skip() // degenerate seed; not a KEG bug
		}
		privB, pubB, err := gost.GenerateEphemeralKey(curve, bytes.NewReader(seedB))
		if err != nil {
			t.Skip()
		}

		// Reference (in-repo) and clean-room must agree on KEG(B_pub, A_priv).
		ref, err := gost.KEG2012_256(curve, pubB, privA, ukm)
		if err != nil {
			t.Fatalf("reference KEG: %v", err)
		}
		got, err := mynew.KEG2012_256(curve, pubB, privA, ukm)
		if err != nil {
			t.Fatalf("clean-room KEG: %v", err)
		}
		if got != ref {
			t.Fatalf("clean-room != reference\nseedA=%x seedB=%x ukm=%x\n got %x\n ref %x",
				seedA, seedB, ukm, got[:], ref[:])
		}

		// Free oracle: pair symmetry KEG(B_pub,A_priv) == KEG(A_pub,B_priv).
		sym, err := mynew.KEG2012_256(curve, pubA, privB, ukm)
		if err != nil {
			t.Fatalf("clean-room KEG (symmetric): %v", err)
		}
		if sym != got {
			t.Fatalf("clean-room KEG not pair-symmetric\n A→B %x\n B→A %x", got[:], sym[:])
		}
	})
}

func mustHexF(f *testing.F, s string) []byte {
	f.Helper()
	b := make([]byte, len(s)/2)
	if _, err := hexDecode(b, s); err != nil {
		f.Fatalf("bad hex: %v", err)
	}
	return b
}
```

(`mustHex`/`hexDecode` use `encoding/hex`; collapse the two helpers if both files
live in one package.) No gost-engine CLI helper is needed here — KEG's reference
is the in-repo Go function plus the pinned vector, both callable directly. (The
OMAC / CTR-ACPKM / KExp15 / KeyWrap guides shell out to the
`openssl ... -engine gost` oracle from CLAUDE.md instead, because those have no
gogost API surface; KEG does, via the in-repo wrapper.)

### Run

```sh
go test -tags gost -run TestKEGConformance ./yourpkg/
go test -tags gost -fuzz=FuzzKEGConformance -fuzztime=30s ./yourpkg/
```

## References

- **R 1323565.1.020-2018 §6.4.5.1** — KEG ("key export generation") definition.
- **RFC 9189** — *GOST Cipher Suites for TLS 1.2*. Suites that consume KEG output
  (key transport / `gost_kexp15`). https://github.com/bigbes/gostcrypto/blob/master/keg/rfc/rfc9189.txt
- **draft-smyshlyaev-tls12-gost-suites** — predecessor of RFC 9189; same KEG/KExp15 wiring.
- **RFC 7836** — *Guidelines on the Cryptographic Algorithms to Accompany GOST*.
  §4.3 VKO_GOSTR3411_2012_256; §4.4 KDF_TREE_GOSTR3411_2012_256
  (§4.5 is the simpler single-block KDF_GOSTR3411_2012_256, not used here).
  https://github.com/bigbes/gostcrypto/blob/master/keg/rfc/rfc7836.txt
- **R 50.1.113-2016** — KDF_TREE / KDF_GOSTR3411_2012_256 standard.
- **RFC 6986** — *GOST R 34.11-2012 (Streebog)* hash function.
  https://github.com/bigbes/gostcrypto/blob/master/keg/rfc/rfc6986.txt
- **RFC 7091 / GOST R 34.10-2012** — the signature / key-pair scheme and curves.

Source citations (file:line):

- `internal/gost/keg_gost.go:36-80` — `KEG2012_256` wrapper (de-facto spec this repo matches).
- `internal/gost/kdftree_gost.go:27-50` — `KDFTree2012_256`.
- `internal/gost/keg_gost_test.go:105-166` — engine-oracle KAT (the vector above).
- `tls/internal/ke/gost2018.go:187-202` — TLS call site + MAC/cipher split + IV.
- `tls/internal/handshake/kex_gost.go:51` — handshake wiring.
- `tmp/engine/gost_ec_keyx.c:132-179` — `gost_keg` ground truth.
- `tmp/engine/gost_ec_keyx.c:27-126` — `VKO_compute_key` ground truth.
- `tmp/engine/gost_keyexpimp.c:201-259` — `gost_kdftree2012_256` ground truth.
- `tmp/engine/test_derive.c:338-364` — symmetric KEG test.
- `third_party/gogost/gost3410/vko2012.go:28-38` — gogost `KEK2012256` (VKO).
- `third_party/gogost/gost3410/vko.go:23-37` — gogost `KEK` (cofactor handling).
- `third_party/gogost/gost3410/ukm.go:23-29` — gogost `NewUKM` (the second reversal).
- `TODO.md` — confirms no listed gogost↔engine divergence touches KEG.
