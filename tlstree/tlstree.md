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

Where this module uses it (call sites, grepped):

- `github.com/bigbes/gostls` (`gostls/`) — the TLS record-layer protector
  `ctrOMACProtector` owns two trees, `encTree` and `macTree`, one per direction
  (client→server / server→client), so a connection has **four trees total**:
  {enc, mac} × {read, write}. Each Seal/Open calls `tree.Derive(seqNum)` to
  obtain the fresh CTR key and the fresh OMAC key for that record.
- Suites that pull it in: `0xC100` GOST2012-KUZNYECHIK-KUZNYECHIKOMAC and
  `0xC101` GOST2012-MAGMA-MAGMAOMAC.

**Status: clean-room, implemented.** `tlstree/tlstree.go` is the completed
GPL-free implementation: it imports only `github.com/bigbes/gostcrypto/streebog`
and the Go standard library. All tests live in `tlstree/tlstree_test.go`.
The differential parity tests (comparing against gogost) live in the
GPL-quarantined `gostcrypto-compat` module at
`gostcrypto-compat/parity/tlstree/tlstree_parity_test.go`.

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
  This is enforced by `NewTLSTree{Kuznyechik,Magma}CTROMAC` and tested in
  `tlstree/tlstree_test.go:TestMasterKeyLength`.
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
basis of the unit-test windowing assertions
(`tlstree/tlstree_test.go:TestWindowing`).

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
the KDF tree. This is documented in `CLAUDE.md` ("gogost/v7 library gotchas").

**Mitigations / contract for a reimplementer:**

- In real TLS this is automatic: the first protected record (Finished) is always
  `seq=0`, which is never a cache hit (`seqNum > 0` guard fails), so it runs the
  full tree and fills the cache (`tmp/engine/test_tlstree.c:119` uses `seq0`
  first, then `seq63`).
- A *clean* reimplementation can simply avoid the bug: initialize `seqNumPrev`
  to a sentinel (e.g. `^uint64(0)`) that no real first sequence equals, OR only
  set the "cache valid" flag after the first real derivation, OR skip caching
  entirely and always run the three KDFs (correct, just slower). If you keep a
  cache, the cache-hit predicate is correct *once primed*; the bug is purely the
  unset-`seqNumPrev`/unfilled-`key` startup race.
- The clean-room implementation in this module (`tlstree.go`) takes the
  always-run approach — no caching — so `TestKAT_FirstCallNotZero` and
  `TestKAT_Kuznyechik_Seq63` guard against the priming trap in
  `tlstree/tlstree_test.go`.

### D3 — `Derive` vs `DeriveCached` aliasing (destructive shared buffer)

gogost's `DeriveCached` returns `t.key`, a slice that **points into the tree's
internal buffer** and is overwritten on the next call
(`third_party/gogost/gost34112012256/tlstree.go:81,89,91`). `Derive` copies it
into a fresh slice (`:94-98`). A reimplementation must give the same guarantee
callers rely on: `Derive` returns a freshly allocated, non-aliasing 32-byte key.
This is asserted by `tlstree/tlstree_test.go:TestDeriveNonAliasing`.

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
(Contrast with `github.com/bigbes/gostcrypto/kdftree`, which iterates the
counter for 64-byte outputs; that path is *not* used by TLSTREE. TLSTREE uses
only the single-block form.)

### D6 — Not affected by the three known gogost↔engine divergences

Per `TODO.md`, the three documented divergences are: (a) S-box row order
(reverse-stored, compensated — net cipher output agrees), (b) GOST R 34.11-94
empty-input finalization, (c) CryptoPro key meshing in GOST28147 IMIT.

**None apply to TLSTREE.** TLSTREE uses no block cipher and no GOST R 34.11-94;
it uses only HMAC-Streebog-256, which never hashes empty input (the message is
always ≥18 bytes) and has no S-box/meshing surface. The in-module KATs
and the compat parity tests in `gostcrypto-compat/parity/tlstree/` confirm parity
with the gogost reference and gost-engine.

## Test vectors

### Inline KAT (runnable immediately) — Kuznyechik TLSTREE, seq=63

Cross-checked against gost-engine's `test_keyexpimp.c` (the
`tlstree_gh_etalon[]` array at
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

`tlstree/tlstree_test.go`:
- length = 32, no aliasing (`TestDeriveNonAliasing`),
- same leaf window → identical key, cross-window → different key
  (window=64 Kuznyechik, 4096 Magma) (`TestWindowing`),
- determinism (`TestDeterminism`),
- 32-byte master-key length enforcement (`TestMasterKeyLength`).

## Re-implementation checklist

Each step is independently testable.

1. **Streebog-256 + HMAC.** Have a working GOST R 34.11-2012 256-bit hash
   (RFC 6986) and standard HMAC over it. Test: RFC 6986 Streebog KATs, then an
   HMAC-Streebog-256 KAT. (Prerequisite — not part of TLSTree itself.)
2. **Single-block `KDF_GOSTR3411_2012_256(K, label, seed)`.** Build the 18-byte
   message `0x01 | label | 0x00 | seed | 0x01 | 0x00` and HMAC it with key `K`;
   return the full 32-byte tag. Test: feed `K=32×0xFF`, `label="level1"`,
   `seed=8×0x00`, compare K1 against gost-engine or the pinned seq=63 KAT
   (the intermediate K1 is implicitly validated by the leaf KAT).
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
   per record in `gostls/`, keys are 32 bytes, and the seq=0 and seq=63
   end-to-end OMAC/CTR etalons from `tmp/engine/test_tlstree.c` pass.

## Conformance & fuzz testing

**Current status:** the clean-room implementation is complete. In-module tests
cover KATs, windowing, aliasing, determinism, and the D2 priming guard. The
differential parity tests (comparing against gogost) live in the GPL-quarantined
module at `gostcrypto-compat/parity/tlstree/tlstree_parity_test.go` — they run
`Test_TLSTree_Conformance` (2 suites × 4 masters × 12 seq numbers) and
`Fuzz_TLSTree_Conformance` (random master + seq + suite, oracle diff + window
invariant).

The differential strategy: `Derive` output is compared against gogost's
`gost34112012256.NewTLSTree(...).Derive(seq)`. Before each diff, the gogost
reference must be primed with `Derive(0)` to avoid the D2 zero-key trap. The
clean-room implementation must NOT be primed — guarded by
`TestKAT_FirstCallNotZero`.

### KAT — pinned gost-engine vector

`K_root = 32×0xFF`, seq=63 ⇒ `507642d9…641a19ff`
(source: `tmp/engine/test_keyexpimp.c:99-104,177,184`, confirmed by
`tlstree/tlstree_test.go:TestKAT_Kuznyechik_Seq63`).

### Parity test location

```
gostcrypto-compat/parity/tlstree/tlstree_parity_test.go
```

Run from the compat module (requires the GPL gogost reference):

```sh
( cd ../gostcrypto-compat && go test ./parity/tlstree/ -v )
( cd ../gostcrypto-compat && go test -fuzz=Fuzz_TLSTree_Conformance -fuzztime=30s ./parity/tlstree/ )
```

### In-module run commands

```sh
( cd gostcrypto && CGO_ENABLED=0 go test ./tlstree/ -v )
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
  copied; vendored in `gostcrypto-compat/third_party/gogost`):
  - `gost34112012256/tlstree.go:25-34` — constant byte literals
    (Magma `:25-29`, Kuznyechik `:30-34`).
  - `gost34112012256/tlstree.go:76-92` — `DeriveCached` (cache predicate
    `:77-82`, three-level KDF chain `:83-89`, priming bug surface).
  - `gost34112012256/kdf.go:31-53` — KDF message framing
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
- Tests and parity:
  - `tlstree/tlstree_test.go` — KATs, windowing, aliasing, determinism, and
    the D2 priming guard (this module).
  - `gostcrypto-compat/parity/tlstree/tlstree_parity_test.go` — differential
    tests and fuzz against the gogost reference.
  - `github.com/bigbes/gostls` — TLS record protector, the production call site.
- `CLAUDE.md` — "gogost/v7 library gotchas" (`TLSTree.DeriveCached` zero-key
  priming bug). `TODO.md` — the three divergences, none of which touch TLSTREE
  (D6).
