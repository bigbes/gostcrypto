# TLSTree key derivation (Kuznyechik/Magma CTR-OMAC suites)

## What it is

TLSTREE is the per-record key-diversification function used by the GOST TLS 1.2
CTR-OMAC cipher suites. Given a fixed 32-byte root key and a 64-bit TLS record
sequence number `i`, it deterministically derives a 32-byte per-record key by
running a **three-level tree of KDF_GOSTR3411_2012_256 invocations**, each level
keyed on a progressively wider-masked slice of `i`. The masks are chosen so the
derived key changes only after a fixed number of records, bounding how much data
is ever protected under one leaf key (the security goal of "key tree" / key
meshing).

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

GOST / RFC identity:

- Algorithm and constants: **RFC 9189 §8.1 and §8.1.1** ("GOST Cipher Suites for
  Transport Layer Security (TLS) Protocol Version 1.2").
- Underlying KDF: **KDF_GOSTR3411_2012_256**, RFC 7836 §4.5, built on
  HMAC_GOSTR3411_2012_256 (RFC 7836 §4.1.1), whose hash is GOST R 34.11-2012
  (Streebog-256, RFC 6986).
- GOST standards in play: GOST R 34.11-2012 (Streebog, the HMAC hash) and
  GOST R 34.12-2015 (Kuznyechik / Magma block ciphers — only relevant for which
  *constant set* applies; TLSTREE itself uses no block cipher).

Where this repo uses it (call sites, grepped):

- `tls/internal/record/protection_ctromac_gost.go:58-59` — every
  `ctrOMACProtector` owns two trees, `encTree` and `macTree`. Constructed at
  `:97-98` (Kuznyechik) and `:133-134` (Magma). One protector exists per
  direction (client→server, server→client), so a connection has **four trees
  total**: {enc, mac} × {read, write}.
- `tls/internal/record/protection_ctromac_gost.go` calls `tree.Derive(seqNum)`
  on each Seal/Open to obtain the fresh CTR key and the fresh OMAC key for that
  record.
- `internal/gost/tlstree_gost.go` — the wrappers
  `NewTLSTreeKuznyechikCTROMAC` / `NewTLSTreeMagmaCTROMAC` / `Derive`.
- Suites that pull it in: `0xC100` GOST2012-KUZNYECHIK-KUZNYECHIKOMAC and
  `0xC101` GOST2012-MAGMA-MAGMAOMAC (`tls/internal/suites/gost_suites.go:80-85`).

**Status: `gogost-backed`.** `internal/gost/tlstree_gost.go` forwards directly to
`go.stargrave.org/gogost/v7/gost34112012256.NewTLSTree` /`DeriveCached`
(`third_party/gogost/gost34112012256/tlstree.go`). A GPL-free reimplementation
must replace that forwarding with a local implementation of the algorithm below.

## Specification

### Top-level function (RFC 9189 §8.1)

> `TLSTREE(K_root, i) = KDF_3(KDF_2(KDF_1(K_root, STR_8(i & C_1)), STR_8(i & C_2)), STR_8(i & C_3))`

with

> `KDF_1(K, D) = KDF_GOSTR3411_2012_256(K, "level1", D)`
> `KDF_2(K, D) = KDF_GOSTR3411_2012_256(K, "level2", D)`
> `KDF_3(K, D) = KDF_GOSTR3411_2012_256(K, "level3", D)`

So:

```
K1 = KDF_GOSTR3411_2012_256(K_root, "level1", STR_8(i & C_1))
K2 = KDF_GOSTR3411_2012_256(K1,     "level2", STR_8(i & C_2))
K3 = KDF_GOSTR3411_2012_256(K2,     "level3", STR_8(i & C_3))   // the result
```

- `K_root` is **32 bytes**. Every intermediate `K1`, `K2` and the output `K3`
  is **32 bytes** (KDF output is fixed 256 bits). The constructor MUST enforce
  the 32-byte master-key length and **panic** on any other length (it is a
  programmer error, not a runtime condition — no truncation, no zero-padding).
  This matches the in-repo wrapper (`internal/gost/tlstree_gost.go:32-34,48-50`)
  and is what the panic tests at `internal/gost/tlstree_test.go:119-140` assert.
- `i` is the **64-bit TLS record sequence number**.
- `STR_8(x)` serializes a 64-bit integer to **8 bytes, network byte order
  (big-endian)** — see the endianness note in deltas; this is the surprising
  part. Labels `"level1"`/`"level2"`/`"level3"` are the 6 ASCII bytes
  `0x6C 0x65 0x76 0x65 0x6C 0x31` (…`32`, …`33`).

### Inner KDF (RFC 7836 §4.5)

> `KDF_GOSTR3411_2012_256(K_in, label, seed) = HMAC_GOSTR3411_2012_256(K_in, 0x01 | label | 0x00 | seed | 0x01 | 0x00)`

The HMAC message is the concatenation, in order:

| field         | bytes              | value                                   |
|---------------|--------------------|-----------------------------------------|
| counter       | 1                  | `0x01`                                  |
| label         | 6                  | `"levelN"` (N ∈ {1,2,3})                |
| separator     | 1                  | `0x00`                                  |
| seed          | 8                  | `STR_8(i & C_n)` (big-endian)           |
| length suffix | 2                  | `0x01 0x00` (= 256, the output bit-len) |

Total HMAC input = 1+6+1+8+1+1 = **18 bytes**. HMAC key = `K_in` (the 32-byte
level input). Output = the full 32-byte HMAC tag (no truncation). The trailing
`0x01 0x00` is the network-byte-order representation of L=256 bits with no
leading zero bytes — for this primitive it is always exactly these two bytes
(see RFC 7836 §4.4 `[L]_b`).

The gogost reference writes these six pieces as six separate `hmac.Write` calls
(`third_party/gogost/gost34112012256/kdf.go:32-49`): `{0x01}`, label, `{0x00}`,
seed, `{0x01}`, `{0x00}` — byte-identical to the table above.

### Constant sets (RFC 9189 §8.1.1)

The 64-bit masks `C_1, C_2, C_3` select how many low bits of `i` are allowed to
vary inside a leaf window.

**Kuznyechik-CTR-OMAC — 0xC100, `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`:**

| const | hex (big-endian)     | low varying bits | window size      |
|-------|----------------------|------------------|------------------|
| C_1   | `0xFFFFFFFF00000000`  | 32               | —                |
| C_2   | `0xFFFFFFFFFFF80000`  | 19               | —                |
| C_3   | `0xFFFFFFFFFFFFFFC0`  | 6                | **64 records**   |

**Magma-CTR-OMAC — 0xC101, `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`:**

| const | hex (big-endian)     | low varying bits | window size       |
|-------|----------------------|------------------|-------------------|
| C_1   | `0xFFFFFFC000000000`  | 38               | —                 |
| C_2   | `0xFFFFFFFFFE000000`  | 25               | —                 |
| C_3   | `0xFFFFFFFFFFFFF000`  | 12               | **4096 records**  |

The leaf window (number of consecutive `i` that map to the same final key) is
`~C_3 + 1`: 64 for Kuznyechik (`0x40`), 4096 for Magma (`0x1000`). This is the
basis of the cache check (see deltas) and of the unit-test windowing assertions
(`internal/gost/tlstree_test.go:44-56`).

These exact hex values appear in gogost as big-endian byte literals at
`third_party/gogost/gost34112012256/tlstree.go:30-34` (Kuznyechik) and `:25-29`
(Magma), and in gost-engine as little-endian `uint64` literals at
`tmp/engine/gost_keyexpimp.c:264-267`. They are the same numbers (proof below).

## RFC ↔ implementation deltas

This is the core section. Every place where a reimplementer can go wrong.

### D1 — Endianness of `STR_8(i & C_n)`: big-endian, but watch the two impls

RFC 9189 §8.1 writes `STR_8(i & C_1)`; RFC 7836 §4.4 says integer→bytes is
**network byte order (big-endian)**. The two reference implementations reach the
same bytes by *opposite-looking* code, which is the trap:

- **gogost** masks then serializes big-endian:
  `binary.BigEndian.PutUint64(t.seq, seqNum & t.params[n])`
  (`third_party/gogost/gost34112012256/tlstree.go:83,86,88`). Its mask constants
  are stored big-endian (`:25-34`), so the masking happens on the *integer* and
  the seed bytes come out big-endian. Correct per RFC.
- **gost-engine** reads the 8 wire sequence bytes into a `uint64` honoring host
  endianness — `BUF_reverse` on big-endian hosts, plain `memcpy` on little-endian
  (`tmp/engine/gost_keyexpimp.c:287-291`) — and its mask constants are written
  **little-endian** (`:264-267`, e.g. Kuznyechik `gh_c1 = 0x00000000FFFFFFFF`).
  It then passes `(const unsigned char *)&seed1` straight to the KDF, i.e. the
  raw little-endian bytes of the masked `uint64`.

Both produce the identical 8 seed bytes for a given on-the-wire sequence number,
because the engine's little-endian constant is the byte-reverse of gogost's
big-endian constant *and* the engine's seed read is the byte-reverse of gogost's.
The two byte-reversals cancel. Verified numerically: gogost
`BigEndian.Uint64({FF,FF,FF,FF,00,00,00,00}) = 0xFFFFFFFF00000000`, and the
engine's `gh_c1 = 0x00000000FFFFFFFF` is its byte-reverse — they mask the same
wire bytes identically.

**Reimplementer rule:** treat `i` as a normal `uint64`, AND it with the
big-endian-hex constant from the RFC table above, and serialize the masked value
**big-endian** into 8 seed bytes. Do *not* copy the engine's little-endian
constants together with big-endian serialization, or vice versa — pick one
self-consistent convention. The repo's wrapper inherits gogost's big-endian-all
convention.

### D2 — `DeriveCached` returns the ALL-ZERO key on the first call for `seqNum>0` in the initial window (priming bug)

gogost caches the last derived leaf and short-circuits when the new `seqNum`
shares all three masked windows with the previously derived one
(`third_party/gogost/gost34112012256/tlstree.go:76-82`):

```
if seqNum > 0 &&
   (seqNum & params[0]) == (seqNumPrev & params[0]) &&
   (seqNum & params[1]) == (seqNumPrev & params[1]) &&
   (seqNum & params[2]) == (seqNumPrev & params[2]) {
       return t.key, true   // cache hit
}
```

`seqNumPrev` is the zero-value `0` on a freshly constructed tree, and `t.key`
is an all-zero `make([]byte, Size)` buffer (`:72`) that has **not yet been
filled**. So if the very first call is `DeriveCached(seqNum)` with `seqNum>0`
but `seqNum` in the same leaf window as `0` (e.g. Kuznyechik `seqNum ∈ 1..63`,
Magma `seqNum ∈ 1..4095`), all three comparisons pass against `seqNumPrev=0`,
the cache "hits", and the function returns **32 zero bytes** — never having run
the KDF tree. This is documented in `CLAUDE.md` ("gogost/v7 library gotchas")
and in `internal/gost/tlstree_engine_test.go:14-20`.

**Mitigations / contract for a reimplementer:**

- The repo's wrapper does **not** prime. Callers must call `Derive(0)` first.
  In real TLS this is automatic: the first protected record (Finished) is always
  `seq=0`, which is never a cache hit (`seqNum > 0` guard fails), so it runs the
  full tree and fills the cache (`tmp/engine/test_tlstree.c:119` uses `seq0`
  first, then `seq63`). The engine oracle test primes explicitly
  (`internal/gost/tlstree_engine_test.go:28`).
- A *clean* reimplementation can simply avoid the bug: initialize `seqNumPrev`
  to a sentinel (e.g. `^uint64(0)`) that no real first sequence equals, OR only
  set the "cache valid" flag after the first real derivation, OR skip caching
  entirely and always run the three KDFs (correct, just slower). If you keep a
  cache, the cache-hit predicate is correct *once primed*; the bug is purely the
  unset-`seqNumPrev`/unfilled-`key` startup race.

### D3 — `Derive` vs `DeriveCached` aliasing (destructive shared buffer)

gogost's `DeriveCached` returns `t.key`, a slice that **points into the tree's
internal buffer** and is overwritten on the next call
(`tlstree.go:81,89,91`). `Derive` copies it into a fresh slice (`:94-98`). The
repo wrapper calls the cached form and copies itself
(`internal/gost/tlstree_gost.go:63-70`) so callers always get an independent
32-byte slice. A reimplementation must give the same guarantee the repo relies
on: `Derive` returns a freshly allocated, non-aliasing 32-byte key
(asserted by `internal/gost/tlstree_test.go:67-82,108-112`).

### D4 — KDF message framing must be exact (no surprises, but easy to fumble)

The HMAC input is `0x01 | label | 0x00 | seed | 0x01 | 0x00` (D-table above).
Two common mistakes:

- Omitting the leading `0x01` counter or the trailing `0x01 0x00` length suffix.
  gogost writes all of them (`kdf.go:32-49`); the engine builds the same string
  through `gost_kdftree2012_256` with `representation=1` (one counter byte) and
  `keyout_len=32` → `len_repr = be32(256) = 0x00000100`, then strips leading
  zero bytes leaving `0x01 0x00` (`tmp/engine/gost_keyexpimp.c:212,227-231,
  234-246`). Net suffix = `0x01 0x00`. Match it byte-for-byte.
- Using the wrong HMAC hash. It is HMAC over **Streebog-256** (GOST R 34.11-2012
  256-bit), not GOST R 34.11-94 and not Streebog-512. gogost: `hmac.New(New, key)`
  where `New` is the 256-bit Streebog (`kdf.go:28`).

### D5 — Output length: KDF produces exactly 32 bytes per level (no multi-block iteration)

Because the requested output is 256 bits = one Streebog block, the KDF runs a
**single** HMAC (counter fixed at `0x01`). Do not implement the multi-iteration
KDF_TREE expansion here — TLSTREE needs only the single-block `KDF_GOSTR3411_2012_256`.
(Contrast with `internal/gost/kdftree_gost.go`, which iterates the counter for
64-byte outputs; that path is *not* used by TLSTREE. See the
`gost34112012256.KDF.Derive` note in `CLAUDE.md` — that hardcoded `0x01 0x00`
suffix is exactly what TLSTREE wants, so the gogost `KDF` type is reused as-is.)

### D6 — Not affected by the three known gogost↔engine divergences

Per `TODO.md`, the three documented divergences are: (a) S-box row order
(reverse-stored, compensated — net cipher output agrees), (b) GOST R 34.11-94
empty-input finalization, (c) CryptoPro key meshing in GOST28147 IMIT.

**None apply to TLSTREE.** TLSTREE uses no block cipher and no GOST R 34.11-94;
it uses only HMAC-Streebog-256, which never hashes empty input (the message is
always ≥18 bytes) and has no S-box/meshing surface. The `internal/gost`
engine-oracle test passing bit-for-bit against gost-engine
(`tlstree_engine_test.go:30`) confirms parity.

## Test vectors

### Inline KAT (runnable immediately) — Kuznyechik TLSTREE, seq=63

From `internal/gost/tlstree_engine_test.go:22-34`, cross-checked against
gost-engine's `test_keyexpimp.c` (the `tlstree_gh_etalon[]` array at
`:99-104`, produced by `gost_tlstree(NID_grasshopper_cbc, kroot, out, tlsseq)`
at `:177` with `kroot = 0xFF×32` (`:129`) and `tlsseq[7] = 63` (`:131`)):

```
K_root = FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
         FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF   (32 × 0xFF)
constants = Kuznyechik (C_1=0xFFFFFFFF00000000, C_2=0xFFFFFFFFFFF80000,
                        C_3=0xFFFFFFFFFFFFFFC0)
i = 63   (0x000000000000003F)

TLSTREE(K_root, 63) =
  50 76 42 d9 58 c5 20 c6 d7 ee f5 ca 8a 53 16 d4
  f3 4b 85 5d 2d d4 bc bf 4e 5b f0 ff 64 1a 19 ff
```

Worked masking for this vector (Kuznyechik): with `i=63=0x3F`,
`i & C_1 = 0`, `i & C_2 = 0`, `i & C_3 = 0` (63 < 64 = the leaf window), so all
three seeds are 8 zero bytes — yet each level still keys differently (`K_root` →
K1 → K2 → K3) via the distinct `"level1/2/3"` labels. This is why `Derive(0)`
and `Derive(63)` yield the **same** key (same window) and the priming bug in D2
bites: a naive first call `Derive(63)` returns zeros instead of the value above.

To reproduce against the C oracle, build/run `tmp/engine/test_keyexpimp.c`,
which calls `gost_tlstree(NID_grasshopper_cbc, kroot, out, tlsseq)` (`:177`)
and asserts the 32-byte leaf key directly against `tlstree_gh_etalon[]`
(`:99-104,184`). The engine intermediate constants are at
`gost_keyexpimp.c:264-267`. (`tmp/engine/test_tlstree.c` instead pins the
downstream MAC/CTR *outputs* that consume the TLSTREE key — see the next
section — not the leaf key itself.)

### Higher-level vectors (key feeds CTR + OMAC)

`tmp/engine/test_tlstree.c` pins the downstream outputs that the TLSTREE key
produces, which transitively validate it:

- seq=0 OMAC tag `mac0_etl` = `75 53 09 CB C7 3B B9 49 C5 0E BB 86 16 0A 0F EE`
  (`test_tlstree.c:61-63`).
- seq=63 OMAC tag `mac63_etl` = `0A 3B FD 43 0F CD D8 D8 5C 96 46 86 81 78 4F 7D`
  (`test_tlstree.c:83-85`).
- seq=0 CTR ciphertext `enc0_etl` (31 bytes, `test_tlstree.c:65-68`).
- seq=63 CTR ciphertext head/tail (`test_tlstree.c:87-95`).

These use `K_root = 32×0xFF` for the MAC tree and `K_root = 32×0x00` for the enc
tree (`test_tlstree.c:33-41`).

### Behavioral / windowing assertions (no external KAT)

`internal/gost/tlstree_test.go`:
- length = 32, no aliasing (`:62-82`),
- same leaf window → identical key, cross-window → different key
  (window=64 Kuznyechik, 4096 Magma) (`:84-99`),
- determinism (`:101-112`),
- 32-byte master-key length enforcement (`:119-140`).

## Re-implementation checklist

Each step is independently testable.

1. **Streebog-256 + HMAC.** Have a working GOST R 34.11-2012 256-bit hash
   (RFC 6986) and standard HMAC over it. Test: RFC 6986 Streebog KATs, then an
   HMAC-Streebog-256 KAT. (Prerequisite — not part of TLSTree itself.)
2. **Single-block `KDF_GOSTR3411_2012_256(K, label, seed)`.** Build the 18-byte
   message `0x01 | label | 0x00 | seed | 0x01 | 0x00` and HMAC it with key `K`;
   return the full 32-byte tag. Test: feed `K=32×0xFF`, `label="level1"`,
   `seed=8×0x00`, compare K1 against the engine (or against a one-shot run of
   the gogost path while you still have it).
3. **Constant tables.** Encode the six masks from RFC 9189 §8.1.1 (tables above)
   for Kuznyechik and Magma. Test: assert your `C_3` window equals 64 / 4096.
4. **Seed serialization (D1).** `STR_8(i & C_n)` = big-endian 8 bytes of the
   masked `uint64`. Test: `i=63, C_3=0xFFFFFFFFFFFFFFC0` ⇒ seed = 8 zero bytes;
   `i=64` ⇒ seed = `00 00 00 00 00 00 00 40`.
5. **Three-level `Derive`.** Chain K1=KDF(K_root,"level1",s1),
   K2=KDF(K1,"level2",s2), K3=KDF(K2,"level3",s3); return a freshly allocated
   32-byte copy (D3). Test: the inline Kuznyechik seq=63 KAT
   `5076 42d9 …` above.
6. **Priming / cache correctness (D2).** Either (a) no cache — always run the
   three KDFs, or (b) cache keyed on the masked windows with `seqNumPrev`
   initialized to a non-colliding sentinel and the cache marked valid only after
   the first real derivation. Test: `Derive(63)` as the *first* call on a fresh
   tree MUST return `5076 42d9 …`, not zeros. Then `Derive(0)` then `Derive(63)`
   must be equal (same window).
7. **Wire into the protector.** Confirm enc-tree and mac-tree each `Derive` once
   per record (`protection_ctromac_gost.go`), keys are 32 bytes, and the seq=0
   and seq=63 end-to-end OMAC/CTR etalons from `test_tlstree.c` pass.

## Conformance & fuzz testing

Differential strategy for THIS primitive: the clean-room `Derive` is checked
against two reference targets that already live in the repo — (1) the in-repo
`internal/gost.TLSTree` wrapper (`internal/gost/tlstree_gost.go:63-70`), which
copies out a fresh 32-byte slice, and (2) the pinned Kuznyechik seq=63 hex
vector from the *Test vectors* section above. There is **no CLI oracle leg**
here: TLSTREE is a pure gogost-backed key derivation, not one of the
OMAC/CTR-ACPKM/KEG/KExp15/KeyWrap primitives that only the gost-engine `openssl`
binary can answer for — so both reference legs are in-process Go. Before each
diff against the wrapper, prime it with `Derive(0)` to dodge the documented
zero-key startup trap (D2 above; `internal/gost/tlstree_engine_test.go:27-28`):
a *fresh* `Derive(63)` on the wrapper would return 32 zero bytes, not the real
leaf key. The clean-room impl must NOT reproduce that bug, so the fuzz harness
primes only the reference, never `mynew`. Fuzz over a random 32-byte master key
and a monotonic `seqNum` sequence, and assert the leaf key changes exactly at
the documented window boundary — 64 records for Kuznyechik (`C_3=…C0`), 4096 for
Magma (`C_3=…000`): `Derive(w-1) == Derive(0)` within a window, `Derive(w) !=
Derive(0)` across it.

### KAT — pinned vector, clean-room vs in-repo wrapper

Reuses the exact bytes pinned above (`K_root = 32×0xFF`, seq=63 ⇒
`507642d9…641a19ff`; `internal/gost/tlstree_engine_test.go:30`). Replace the
`mynew` alias with your clean-room package.

```go
//go:build gost

package mynew_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	gostref "go.bigb.es/tlsdialer/internal/gost" // in-repo reference
	mynew "github.com/.../your/tlstree"      // clean-room impl under test
)

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func Test_TLSTree_Conformance(t *testing.T) {
	kFF := bytes.Repeat([]byte{0xFF}, 32)
	cases := []struct {
		name   string
		master []byte
		seq    uint64
		// newRef builds the in-repo reference tree; newNew the clean-room one.
		newRef func([]byte) *gostref.TLSTree
		newNew func([]byte) *mynew.TLSTree
		want   string
	}{
		{
			name:   "kuznyechik/seq63",
			master: kFF,
			seq:    63,
			newRef: gostref.NewTLSTreeKuznyechikCTROMAC,
			newNew: mynew.NewTLSTreeKuznyechikCTROMAC,
			// Pinned in tlstree.md "Inline KAT".
			want: "507642d958c520c6d7eef5ca8a5316d4f34b855d2dd4bcbf4e5bf0ff641a19ff",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := mustHex(tc.want)

			// Reference: prime with Derive(0) to avoid the D2 zero-key trap.
			ref := tc.newRef(tc.master)
			_ = ref.Derive(0)
			gotRef := ref.Derive(tc.seq)
			if !bytes.Equal(gotRef, want) {
				t.Fatalf("reference mismatch: got %x want %x", gotRef, want)
			}

			// Clean-room: must hit the pinned vector on the *first* call
			// (no priming) — it must not carry gogost's startup bug.
			gotNew := tc.newNew(tc.master).Derive(tc.seq)
			if !bytes.Equal(gotNew, want) {
				t.Fatalf("clean-room mismatch: got %x want %x", gotNew, want)
			}
		})
	}
}
```

### Fuzz — clean-room vs in-repo wrapper over random key + seq

Seeds from the KAT inputs, normalizes the raw fuzz `[]byte` into this
primitive's fixed-size args (32-byte master key + a `uint64` seq), runs both
references identically, and additionally asserts the window-boundary invariant.

```go
//go:build gost

package mynew_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	gostref "go.bigb.es/tlsdialer/internal/gost"
	mynew "github.com/.../your/tlstree"
)

func Fuzz_TLSTree_Conformance(f *testing.F) {
	// Seed corpus from the KAT: 32×0xFF master, seq=63, Kuznyechik(0).
	f.Add(bytes.Repeat([]byte{0xFF}, 32), uint64(63), false)
	f.Add(bytes.Repeat([]byte{0x00}, 32), uint64(0), false)
	f.Add(bytes.Repeat([]byte{0x11}, 32), uint64(4096), true)

	f.Fuzz(func(t *testing.T, raw []byte, seq uint64, magma bool) {
		// Normalize the random []byte into a fixed 32-byte master key.
		master := make([]byte, 32)
		copy(master, raw) // short raw → zero-padded; long raw → truncated

		newRef, newNew := gostref.NewTLSTreeKuznyechikCTROMAC, mynew.NewTLSTreeKuznyechikCTROMAC
		window := uint64(64) // Kuznyechik leaf window (C_3 = ...FFC0)
		if magma {
			newRef, newNew = gostref.NewTLSTreeMagmaCTROMAC, mynew.NewTLSTreeMagmaCTROMAC
			window = 4096 // Magma leaf window (C_3 = ...F000)
		}

		// Reference must be primed (D2); clean-room must not be.
		ref := newRef(master)
		_ = ref.Derive(0)
		gotRef := ref.Derive(seq)
		gotNew := newNew(master).Derive(seq)
		if !bytes.Equal(gotRef, gotNew) {
			t.Fatalf("mismatch master=%x seq=%d magma=%v\n ref: %x\n new: %x",
				master, seq, magma, gotRef, gotNew)
		}

		// Window invariant: same leaf window ⇒ identical key; crossing it ⇒ change.
		base := seq - (seq % window) // window start
		mn := newNew(master)
		k0 := mn.Derive(base)
		kIn := newNew(master).Derive(base + window - 1)
		kOut := newNew(master).Derive(base + window)
		if !bytes.Equal(k0, kIn) {
			t.Fatalf("intra-window key changed: master=%x base=%d window=%d", master, base, window)
		}
		if bytes.Equal(k0, kOut) {
			t.Fatalf("cross-window key unchanged: master=%x base=%d window=%d", master, base, window)
		}
	})
}
```

Note on the reference leg: `internal/gost.TLSTree` exposes only
`NewTLSTree{Kuznyechik,Magma}CTROMAC(master []byte) *TLSTree` and
`(*TLSTree).Derive(seqNum uint64) []byte` (`internal/gost/tlstree_gost.go:31,47,63`);
the clean-room impl must mirror that surface for the scaffolding above to
compile unchanged. If you prefer to diff against raw gogost directly instead of
the wrapper, call `gost34112012256.NewTLSTree(gost34112012256.TLSGOSTR341112256WithKuznyechikCTROMAC,
master).Derive(seq)` — but `Derive` there has the same D2 priming requirement,
so prime it identically.

### Run commands

```sh
go test -tags gost -run Test_TLSTree_Conformance ./yourpkg/
go test -tags gost -fuzz=Fuzz_TLSTree_Conformance -fuzztime=30s ./yourpkg/
```

## References

- **RFC 9189** "GOST Cipher Suites for TLS 1.2", §8.1 (TLSTREE definition,
  KDF_1/2/3 with labels level1/level2/level3) and §8.1.1 (C_1/C_2/C_3 constants
  for 0xC100 Kuznyechik-CTR-OMAC and 0xC101 Magma-CTR-OMAC).
  https://github.com/bigbes/gostcrypto/blob/master/tlstree/rfc/rfc9189.txt
- **RFC 7836** "Guidelines on the Cryptographic Algorithms to Accompany the
  Usage of Standards GOST R 34.10-2012 and GOST R 34.11-2012", §4.5
  (KDF_GOSTR3411_2012_256 = HMAC over `0x01|label|0x00|seed|0x01|0x00`), §4.1.1
  (HMAC_GOSTR3411_2012_256), §4.4 (network-byte-order integer serialization).
  https://github.com/bigbes/gostcrypto/blob/master/tlstree/rfc/rfc7836.txt
- **RFC 6986** GOST R 34.11-2012 (Streebog), the HMAC hash.
- GOST standards: GOST R 34.11-2012 (hash), GOST R 34.12-2015 (block ciphers
  selecting the constant set).

Key source citations:

- gogost reference impl (de-facto spec the repo matches, GPL-3.0 — described not
  copied):
  - `third_party/gogost/gost34112012256/tlstree.go:25-34` — constant byte
    literals (Magma `:25-29`, Kuznyechik `:30-34`).
  - `third_party/gogost/gost34112012256/tlstree.go:76-92` — `DeriveCached`
    (cache predicate `:77-82`, three-level KDF chain `:83-89`, priming bug
    surface).
  - `third_party/gogost/gost34112012256/kdf.go:31-53` — KDF message framing
    `0x01|label|0x00|seed|0x01|0x00`.
- gost-engine ground truth (Tarantool's upstream parity target):
  - `tmp/engine/gost_keyexpimp.c:261-305` — `gost_tlstree` (constants `:264-267`,
    seed endianness `:287-294`, three KDF calls `:296-302`).
  - `tmp/engine/gost_keyexpimp.c:201-259` — `gost_kdftree2012_256` (length suffix
    derivation `:212,227-231`, HMAC framing `:238-246`).
  - `tmp/engine/test_keyexpimp.c` — leaf-key KAT: `tlstree_gh_etalon[]`
    (`:99-104`) asserted directly against `gost_tlstree(NID_grasshopper_cbc,…)`
    (`:177,184`) with `kroot=0xFF×32` (`:129`), `tlsseq=63` (`:131`). Source of
    the inline `507642d9…641a19ff` vector.
  - `tmp/engine/test_tlstree.c` — end-to-end *downstream* KAT (seq0/seq63 MAC +
    CTR etalons that consume the leaf key, `:33-95`; TLSTREE ctrl calls
    `:119,144,160,178`) — does NOT pin the leaf key itself.
- Repo wrappers, tests, call sites:
  - `internal/gost/tlstree_gost.go:31-70` — wrappers + `Derive` copy.
  - `internal/gost/tlstree_engine_test.go:22-34` — Kuznyechik seq=63 KAT
    `5076 42d9 …` + priming note.
  - `internal/gost/tlstree_test.go:30-140` — windowing / aliasing / panic tests.
  - `tls/internal/record/protection_ctromac_gost.go:58-59,97-98,133-134` — the
    four-trees-per-connection call sites.
  - `tls/internal/suites/gost_suites.go:80-103` — suite IDs 0xC100/0xC101.
- `CLAUDE.md` — "gogost/v7 library gotchas" (`TLSTree.DeriveCached` zero-key
  priming bug). `TODO.md` — the three divergences, none of which touch TLSTREE
  (D6).
