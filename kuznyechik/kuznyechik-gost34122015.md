# Kuznyechik (Grasshopper) — GOST R 34.12-2015 128-bit block cipher

## What it is

Kuznyechik (Russian "Кузнечик", "Grasshopper") is the 128-bit block cipher of
the Russian national standard **GOST R 34.12-2015**, republished as
**RFC 7801** ("GOST R 34.12-2015: Block Cipher 'Kuznyechik'", March 2016). It
is an SP-network with:

- block size **16 bytes** (128 bits),
- key size **32 bytes** (256 bits),
- **10 rounds** driven by **10 round keys**, each 16 bytes,
- a fixed 256-entry byte S-box (π), a fixed 16-byte linear transform L over
  GF(2^8), and a Feistel-based key schedule using 32 constants C_1…C_32.

It is a plain block cipher: it transforms exactly one 16-byte block. Modes
(CTR, OMAC, MGM, ACPKM, kexp15) are layered on top elsewhere — this document
covers ONLY the block primitive `Encrypt` / `Decrypt`.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

### Status in this repo

**Clean-room, implemented.** Kuznyechik is implemented in this package
(`kuznyechik.go`) as pure Go, BSD-2-Clause, deriving every constant from RFC 7801
and the spec below — it imports no GOST backend. `NewCipher(key) *Cipher`
returns a `crypto/cipher.Block`. Encrypt/Decrypt use fused `S∘L` / `L⁻¹` lookup
tables built at first use from the verified clean-room transforms; the slow
bit-loop `gf()`/`r()` path remains in the source as the table generator and the
documentation of the math. The implementation is table-driven and not
constant-time — see `SECURITY.md`.

### Where this is used

- This package's `Cipher` is consumed directly by the mode packages in this
  module: `ctracpkm`, `mgm`, `omac`, `kexp15`, `keg` (all `import
  "github.com/bigbes/gostcrypto/kuznyechik"`), and re-exported through the root
  `gostcrypto` facade.
- The pure-Go TLS client (`gostls`, a sibling module) builds the CTR-OMAC record
  layer on top of these mode packages for cipher suite **`0xC100`**
  (`TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`, RFC 9189; see kexp15.go for
  the RFC attribution). The suite's KDF/PRF is Streebog-256 — Kuznyechik is only
  the bulk cipher and the OMAC block primitive.

There is **no standalone OID** for the bare block cipher in the TLS path; it is
identified by the suite ID `0xC100` and the OpenSSL/engine algorithm names
`kuznyechik-ctr`, `kuznyechik-ctr-acpkm`, `kuznyechik-mac`.

---

## Specification

All section numbers below refer to **RFC 7801**. Sizes: input/output block 16
bytes; key 32 bytes; 10 round keys × 16 bytes; no IV (this is the raw block
transform).

### Field and notation

Operations are over the finite field **GF(2)[x]/p(x)** with reduction
polynomial (RFC 7801 §3.2):

```
p(x) = x^8 + x^7 + x^6 + x + 1
```

As a byte modulus this is `0x1C3` (9-bit), i.e. the low-byte XOR mask after a
left shift that overflows bit 7 is **`0xC3`**. A reference GF(2^8) multiply:

```
gf(a, b):                       # third_party/gogost/gost3412128/cipher.go:61
    c = 0
    while b > 0:
        if b & 1: c ^= a
        if a & 0x80: a = (a << 1) ^ 0xC3   # reduce by p(x)
        else:        a = a << 1
        b >>= 1
    return c & 0xFF
```

Bytes within a 128-bit block are indexed `a_15 || a_14 || … || a_0`, where
`a_15` is the **most significant / leftmost** byte (the first byte on the wire)
and `a_0` is the least significant. This big-endian byte indexing matters for
the L transform direction; see deltas below.

### 1. Nonlinear transform S (π S-box) — RFC 7801 §4.1

> "The bijective nonlinear mapping is a substitution Pi = (Vec_8)Pi'(Int_8)."

S applies the 256-byte table π to every one of the 16 bytes independently. The
full table (π[0]…π[255], decimal as published; identical to gogost
`pi` at `cipher.go:31-55` and engine `grasshopper_pi` at
`gost_grasshopper_defines.c:14-47`):

```
252 238 221  17 207 110  49  22 251 196 250 218  35 197   4  77
233 119 240 219 147  46 153 186  23  54 241 187  20 205  95 193
249  24 101  90 226  92 239  33 129  28  60  66 139   1 142  79
  5 132   2 174 227 106 143 160   6  11 237 152 127 212 211  31
235  52  44  81 234 200  72 171 242  42 104 162 253  58 206 204
181 112  14  86   8  12 118  18 191 114  19  71 156 183  93 135
 21 161 150  41  16 123 154 199 243 145 120 111 157 158 178 177
 50 117  25  61 255  53 138 126 109  84 198 128 195 189  13  87
223 245  36 169  62 168  67 201 215 121 214 246 124  34 185   3
224  15 236 222 122 148 176 188 220 232  40  80  78  51  10  74
167 151  96 115  30   0  98  68  26 184  56 130 100 159  38  65
173  69  70 146  39  94  85  47 140 163 165 125 105 213 149  59
  7  88 179  64 134 172  29 247  48  55 107 228 136 217 231 137
225  27 131  73  76  63 248 254 141  83 170 144 202 216 133  97
 32 113 103 164  45  43   9  91 203 155  37 208 190 229 108  82
 89 166 116 210 230 244 180 192 209 102 175 194  57  75  99 182
```

The same table in hex (first byte `0xFC`):

```
FC EE DD 11 CF 6E 31 16 FB C4 FA DA 23 C5 04 4D
E9 77 F0 DB 93 2E 99 BA 17 36 F1 BB 14 CD 5F C1
F9 18 65 5A E2 5C EF 21 81 1C 3C 42 8B 01 8E 4F
05 84 02 AE E3 6A 8F A0 06 0B ED 98 7F D4 D3 1F
EB 34 2C 51 EA C8 48 AB F2 2A 68 A2 FD 3A CE CC
B5 70 0E 56 08 0C 76 12 BF 72 13 47 9C B7 5D 87
15 A1 96 29 10 7B 9A C7 F3 91 78 6F 9D 9E B2 B1
32 75 19 3D FF 35 8A 7E 6D 54 C6 80 C3 BD 0D 57
DF F5 24 A9 3E A8 43 C9 D7 79 D6 F6 7C 22 B9 03
E0 0F EC DE 7A 94 B0 BC DC E8 28 50 4E 33 0A 4A
A7 97 60 73 1E 00 62 44 1A B8 38 82 64 9F 26 41
AD 45 46 92 27 5E 55 2F 8C A3 A5 7D 69 D5 95 3B
07 58 B3 40 86 AC 1D F7 30 37 6B E4 88 D9 E7 89
E1 1B 83 49 4C 3F F8 FE 8D 53 AA 90 CA D8 85 61
20 71 67 A4 2D 2B 09 5B CB 9B 25 D0 BE E5 6C 52
59 A6 74 D2 E6 F4 B4 C0 D1 66 AF C2 39 4B 63 B6
```

S^{-1} (used only by Decrypt) is the inverse permutation: `piInv[pi[i]] = i`.
It need not be tabulated — compute it once at init. (Engine tabulates it as
`grasshopper_pi_inv` at `gost_grasshopper_defines.c:51-84`; useful as a check.)

### 2. Linear transform R and L — RFC 7801 §4.2–4.3

The 16-coefficient vector (RFC 7801 §4.2, the `l(...)` definition), decimal,
**indexed from a_15 down to a_0**:

```
148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
```

In this repo's byte order (`lc[i]` pairs with `blk[i]`, i.e. `lc[0]` is the
coefficient of byte `blk[0]`), the vector is stored as
(`cipher.go:27-30`, identical to engine `grasshopper_lvec` at
`gost_grasshopper_defines.c:88-91`):

```
hex:  94 20 85 10 C2 C0 01 FB 01 C0 C2 10 85 20 94 01
dec: 148 32 133 16 194 192 1 251 1 192 194 16 133 32 148 1
```

**R** (one LFSR step), RFC 7801 §4.3 `R(a_15||…||a_0) = l(a_15,…,a_0) || a_15 || … || a_1`:
compute one new byte `t` as the GF(2^8) dot product of the block with the
coefficient vector, shift every byte one position toward the
least-significant end, and place `t` into the most-significant position.

Concretely (matching gogost test helper `R` at `cipher_test.go:117-124`, where
`blk[0]` is the MS byte):

```
R(blk[0..15]):
    t = blk[15]
    for i in 0..14: t ^= gf(blk[i], lc[i])
    blk[1..15] = blk[0..14]      # shift right (toward LS index)
    blk[0] = t
```

**L = R applied 16 times** (RFC 7801 §4.3, `L(a) = R^16(a)`). The repo's
forward `l()` (`cipher.go:76-125`) fuses the 16 R-steps into one unrolled loop;
the inverse `lInv()` (`cipher.go:127-149`) runs R backwards 16 times.

KAT for one R step (gogost `TestR`, `cipher_test.go:126`): with all-zero block
except `blk[14]=0x01`, after one R the block is `94 00 … 00 01`. This pins both
the coefficient order and the shift direction — a reimplementer should match it
first.

KAT for L (gogost `TestL`, `cipher_test.go:161`): input
`64 a5 94 00 00 … 00` → output `d4 56 58 4d d0 e3 e8 4c c3 16 6e 4b 7f a2 89 0d`.

### 3. Round constants C_i — RFC 7801 §4.4

> "C_i = L(Vec_128(i)), i = 1, 2, …, 32."

`Vec_128(i)` is the 16-byte block whose **least-significant byte (index 15 in
MS-first numbering, `cBlk[i][15]` in the repo) equals i**, all other bytes
zero; then apply L. The repo builds them at `cipher.go:185-189`:

```
for i in 0..31:
    C[i] = zero 16-byte block
    C[i][15] = i + 1          # constants are 1-indexed: C_1..C_32
    L(C[i])
```

KAT (gogost `TestC`, `cipher_test.go:196`): `C_1 = cBlk[0] =
6e a2 76 72 6c 48 7a b8 5d 27 bd 10 dd 84 94 01`;
`C_2 = dc 87 ec e4 d8 90 f4 b3 ba 4e b9 20 79 cb eb 02`.

### 4. Key schedule (10 round keys) — RFC 7801 §4.4

Split the 32-byte key into two 16-byte halves: `K_1 = key[0:16]`,
`K_2 = key[16:32]` — these are round keys 1 and 2 directly (no transform).

The Feistel round function is `F[C](a_1, a_2) = (LSX[C](a_1) XOR a_2, a_1)`,
where `LSX[C](x) = L(S(x XOR C))`. Then (RFC 7801 §4.4):

> `(K_{2i+1}, K_{2i+2}) = F[C_{8(i-1)+8}] … F[C_{8(i-1)+1}] (K_{2i-1}, K_{2i})`,
> i = 1, 2, 3, 4.

i.e. for each i in 1..4, run **8 Feistel rounds** over the current pair using
constants `C_{8(i-1)+1} … C_{8(i-1)+8}` (16 constants per 2 keys × 4 = 32
constants total, all C_1..C_32 used), then emit the resulting pair as the next
two round keys. This yields K_1…K_10.

Repo implementation (`cipher.go:200-225`), with `kr0`/`kr1` as the running pair:

```
kr0 = key[0:16]; kr1 = key[16:32]
ks[0] = kr0; ks[1] = kr1
for i in 0..3:                       # 4 outer iterations
    for j in 0..7:                   # 8 Feistel rounds
        krt = kr0 XOR C[8*i + j]     # X[C]
        krt = S(krt)                 # S
        krt = L(krt)                 # L      → LSX
        krt = krt XOR kr1            # Feistel XOR with right half
        kr1 = kr0                    # swap
        kr0 = krt
    ks[2 + 2*i]     = kr0
    ks[2 + 2*i + 1] = kr1
```

KAT (gogost `TestRoundKeys`, `cipher_test.go:247`) with key
`8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef`:
`K_3 (ks[2]) = db31485315694343 228d6aef8cc78c44` …
`K_10 (ks[9]) = 72 e9 dd 74 16 bc f4 5b 75 5d ba a8 8e 4a 40 43`. Full 10-key
expansion is inlined in that test.

### 5. Encryption / Decryption — RFC 7801 §4.5

`X[k](a) = a XOR k` (round-key add). `LSX[k] = L(S(X[k](a)))`.

**Encrypt** (RFC 7801 §4.5.1,
`E = X[K_10] LSX[K_9] … LSX[K_1]`), repo `cipher.go:227-237`:

```
blk = src
for i in 0..8:                 # 9 LSX rounds
    blk = blk XOR ks[i]
    blk = S(blk)
    blk = L(blk)
blk = blk XOR ks[9]            # final X[K_10]
dst = blk
```

**Decrypt** (RFC 7801 §4.5.2,
`D = X[K_1] L^{-1}S^{-1} X[K_2] … L^{-1}S^{-1} X[K_10]`), repo
`cipher.go:239-248`:

```
blk = src
for i = 9 down to 1:
    blk = blk XOR ks[i]
    blk = Linv(blk)
    blk = Sinv(blk)
blk = blk XOR ks[0]           # final X[K_1]
dst = blk
```

---

## RFC ↔ implementation deltas

Every point a reimplementer is likely to get wrong. Each cites the RFC and the
gogost/engine source line.

1. **Byte order of the L coefficient vector is reversed vs. the RFC text.**
   RFC 7801 §4.2 writes coefficients against `a_15 … a_0` (MS byte first):
   `148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1`. The
   vector is a palindrome **except** for the endpoints (`148` vs `1`), so a
   wrong-direction read produces wrong output, not a silent pass. gogost stores
   it MS-first as `lc` (`cipher.go:27`) and pairs `lc[i]` with `blk[i]` where
   `blk[0]` is the MS byte — so `lc[0]=148` multiplies the MS byte. The engine
   stores the identical `grasshopper_lvec` (`gost_grasshopper_defines.c:88`).
   Pin this with the `R` KAT (§Specification step 2) before anything else.

2. **R shift direction.** RFC 7801 §4.3 defines `R(a) = l(a) || a_15 || … ||
   a_1` — the new byte enters the **top** (MS) and the bottom byte `a_0` falls
   off. With `blk[0]` = MS byte, that means `blk` shifts toward higher indices
   and `blk[0] = t` (engine `gost_grasshopper_core.c:24-30`; gogost helper
   `cipher_test.go:122-123`). Implement on the wrong index convention and the L
   KAT fails.

3. **GF(2^8) reduction constant is `0xC3`, not `0x1B`/`0x87`.** RFC 7801 §3.2
   fixes `p(x)=x^8+x^7+x^6+x+1`. The post-shift XOR mask is the low 8 bits,
   `0xC3` (gogost `gf`, `cipher.go:67`). Do **not** reuse AES's `0x1B` or the
   OMAC Rb `0x87` (which is the *128-bit* polynomial used by OMAC, not the
   field used inside the block cipher). The engine encodes the same field via
   log/antilog tables: `grasshopper_galois_alpha_to[8] = 195 = 0xC3`
   (`gost_grasshopper_galois_precompiled.c`).

4. **π is applied to all 16 bytes, S^{-1} only in Decrypt.** Trivial but: the
   inverse table must be the true permutation inverse of π, not a second copy.
   Derive it (`piInv[pi[i]] = i`, `cipher.go:182-184`) or cross-check against
   engine `grasshopper_pi_inv` (`gost_grasshopper_defines.c:51`).

5. **Round-constant indexing is 1-based and the seed byte is the LS byte.**
   RFC 7801 §4.4: `C_i = L(Vec_128(i))`, i from 1. The repo sets
   `cBlk[i][15] = i+1` (`cipher.go:187`) — index 15 is the LS byte in MS-first
   numbering, and `+1` makes the array's `cBlk[0]` hold `C_1`. Off-by-one here
   silently corrupts the whole key schedule; verify with the `C_1`/`C_2` KAT.

6. **Key schedule is 4 outer × 8 inner Feistel rounds; the X-then-S-then-L
   order matters.** RFC 7801 §4.4 composes `F[C]` as `LSX[C]` on the left half
   XOR right half, then swap. gogost does `XOR C → S → L → XOR kr1 → swap`
   (`cipher.go:214-219`). A common mistake is applying L before S or omitting
   the swap; the `TestRoundKeys` KAT catches it.

7. **Encrypt has 9 LSX rounds + 1 final X; Decrypt is the exact inverse with
   L^{-1}S^{-1}.** RFC 7801 §4.5.1/§4.5.2. Note Encrypt uses forward `S`,`L`;
   Decrypt uses `Linv` **before** `Sinv` (`cipher.go:244-245`) — the inverse of
   `L∘S` is `S^{-1}∘L^{-1}`, applied to the block in that textual order. The
   final whitening key is `K_10` for Encrypt, `K_1` for Decrypt.

8. **No endianness surprise inside the block transform itself.** Unlike GOST
   28147-89 / Magma (which the gogost gotchas section warns about), Kuznyechik
   here is byte-array-oriented end to end: input bytes map directly to
   `blk[0..15]` with `blk[0]` as the first/MS byte, and output is copied back in
   the same order (`cipher.go:229,236`). There is no per-word little-endian
   reversal at the block boundary. (The engine's `set_encrypt_key` even carries
   a comment "this will be have to changed for little-endian systems" at
   `gost_grasshopper_core.c:56` — it copies key bytes straight, so on
   little-endian hosts the byte arrays already match. Match the byte arrays, not
   any word view.)

9. **`crypto/cipher.Block` contract.** `NewKuznyechikCipher`
   (`exports_gost.go:72`) returns a `cipher.Block` with `BlockSize() == 16`.
   gogost's `NewCipher` **panics** on a key whose length != 32
   (`cipher.go:201-203`); `Encrypt`/`Decrypt` copy via `copy(blk[:], src)` so a
   short `src`/`dst` silently truncates rather than panicking. A faithful
   reimpl should keep the 32-byte key panic and document the 16-byte
   src/dst expectation.

10. **None of the three known gogost↔engine divergences touch this primitive.**
    `TODO.md` lists exactly three (GOST 28147 S-box row order, R 34.11-94
    empty-input finalization, CryptoPro key meshing). All are GOST 28147-89 /
    R 34.11-94 issues. Kuznyechik's π, L vector, constants, and round structure
    are **bit-for-bit identical** between gogost (`cipher.go`) and gost-engine
    (`gost_grasshopper_*.c`) — verified above table-by-table. There is no
    row-order or finalization caveat to carry for the block cipher. (Modes
    layered on top — ACPKM section size, OMAC Rb, kexp15 — have their own
    caveats documented at their own call sites, e.g.
    `tls/internal/record/protection_ctromac_gost.go`.)

---

## Test vectors

### Primary KAT — GOST R 34.12-2015 §A.1 / RFC 7801 §5.5–5.6

A reimplementer can run this immediately. Already asserted by
`internal/gost/primitives_test.go:13` (`TestGost_Kuznyechik_Vector`) and gogost
`third_party/gogost/gost3412128/cipher_test.go:311` (`TestVectorEncrypt`).

```
Key (32 B):        8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
Plaintext  (16 B): 1122334455667700ffeeddccbbaa9988
Ciphertext (16 B): 7f679d90bebc24305a468d42b9d4edcd
```

`Encrypt(Key, Plaintext) == Ciphertext` and
`Decrypt(Key, Ciphertext) == Plaintext`.

### Intermediate KATs (pin each stage independently)

From `third_party/gogost/gost3412128/cipher_test.go`:

- **S (one π pass)**, `TestS:82`: input
  `ffeeddccbbaa9988 1122334455667700` → after one S
  `b66cd8887d38e8d7 7765aeea0c9a7efc`.
- **R (one LFSR step)**, `TestR:126`: input `00…00 0100` (i.e. `blk[14]=0x01`)
  → `9400000000000000 0000000000000001`.
- **L (= R^16)**, `TestL:161`: input
  `64a5940000000000 0000000000000000` →
  `d456584dd0e3e84c c3166e4b7fa2890d`.
- **Constants**, `TestC:196`: `C_1 = 6ea276726c487ab8 5d27bd10dd849401`,
  `C_2 = dc87ece4d890f4b3 ba4eb92079cbeb02`.
- **Round keys**, `TestRoundKeys:247`: full K_1…K_10 for the §A.1 key;
  `K_10 = 72e9dd7416bcf45b 755dbaa88e4a4043`.

These five line up exactly with RFC 7801 §5.1–5.4 worked example, so they
double as an RFC cross-check.

### Engine ground-truth tables (for cross-verifying constants)

- π: `tmp/engine/gost_grasshopper_defines.c:14-47`
- π^{-1}: `:51-84`
- L vector: `:88-91`
- GF log/antilog tables (encode the same `0xC3` field):
  `tmp/engine/gost_grasshopper_galois_precompiled.c`

---

## Re-implementation checklist

Each step is independently testable against a vector above. Do them in order;
do not advance until the current vector passes.

1. **GF(2^8) multiply.** Implement `gf(a,b)` with reduction mask `0xC3`. Test:
   `gf(0x02, 0x80) = 0xC3` (i.e. `2*128 = x^8 mod p(x)`), and build a 256×256
   cache if you want table-driven L. Cross-check the whole table against the
   engine's `alpha_to`/`index_of` if available.
2. **π S-box + S transform.** Hard-code the 256-byte table, derive π^{-1}.
   Pass `TestS` (`b66cd888…`).
3. **R step.** Coefficient vector MS-first, new byte into index 0, shift toward
   higher indices. Pass `TestR` (`9400…01`).
4. **L and L^{-1}.** L = 16× R; L^{-1} = 16× inverse-R. Pass `TestL`
   (`d456584d…`) and verify `Linv(L(x)) == x` on random blocks.
5. **Round constants C_1..C_32.** Seed `blk[15] = i` (1-based), apply L. Pass
   `TestC` (`C_1 = 6ea27672…`).
6. **Key schedule.** 4 outer × 8 inner Feistel rounds, order `XOR C → S → L →
   XOR right → swap`; emit the pair after every 8 rounds. Pass `TestRoundKeys`
   (`K_10 = 72e9dd74…`).
7. **Encrypt.** 9× `(XOR ks[i] → S → L)` then final `XOR ks[9]`. Pass the §A.1
   primary KAT (`7f679d90…`).
8. **Decrypt.** 9× `(XOR ks[i] → Linv → Sinv)` for i=9..1 then final
   `XOR ks[0]`. Verify it inverts Encrypt and recovers `1122334455667700…`.
9. **`cipher.Block` wrapper.** `BlockSize()=16`, panic on key length != 32,
   single-block `Encrypt`/`Decrypt` (`NewCipher` in this package). Re-run the
   in-package tests (`kuznyechik_test.go`, `guard_test.go`).
10. **Mode round-trip (integration).** Once the block passes, the mode packages
    that build on it (`ctracpkm`, `mgm`, `omac`, `kexp15`, `keg`) and the
    `gostls` CTR-OMAC record layer for suite `0xC100` exercise it end to end.

---

## Conformance & fuzz testing

In-package KATs live in `kuznyechik_test.go` (white-box, `package kuznyechik`):
the primary §A.1 / RFC 7801 §5.5–5.6 vector (`TestPrimaryKAT`), the 4-block ECB
sequence from GOST R 34.13-2015 §A.1.1 (`TestECB_A11`), per-stage KATs for S, R,
L, the round constants and the round keys (`TestStageKATs`), the deterministic
round-trip sweep (`TestRoundTripRandom`), full-overlap aliasing
(`TestEncryptDecryptInPlace`), key-copy non-retention (`TestNewCipherCopiesKey`),
and the bad-key panics (`TestNewCipherPanicsOnBadKey`). `guard_test.go` pins the
short-buffer panics. `BenchmarkEncrypt`/`BenchmarkDecrypt` measure the
table-driven path.

The **differential gate against the gogost reference is GPL-3.0 and therefore
must not live in this module** — it lives in the sibling `gostcrypto-compat`
module (Apache-/GPL-quarantined) at
`../gostcrypto-compat/parity/kuznyechik/kuznyechik_parity_test.go`, which runs
this package's `NewCipher` against `go.stargrave.org/gogost/v7/gost3412128`
(reference oracle) on the pinned KATs and under the differential fuzz target
`FuzzDiffKuznyechik`. Run it with:

```sh
( cd ../gostcrypto-compat && go test ./parity/kuznyechik/ )
( cd ../gostcrypto-compat && go test -run x -fuzz FuzzDiffKuznyechik -fuzztime 30s ./parity/kuznyechik/ )
```

Nothing in `gostcrypto` may import gogost; the parity oracle is intentionally
quarantined in the compat module per the workspace license boundary.

---

## References

**Standards / RFCs**

- **RFC 7801** — "GOST R 34.12-2015: Block Cipher 'Kuznyechik'", V. Dolmatov
  (Ed.), March 2016. https://github.com/bigbes/gostcrypto/blob/master/kuznyechik/rfc/rfc7801.txt
  - §3.2 reduction polynomial `x^8+x^7+x^6+x+1`
  - §4.1 nonlinear S (π and π^{-1})
  - §4.2 linear coefficient vector `l(…)`
  - §4.3 R and `L = R^16`
  - §4.4 constants `C_i = L(Vec_128(i))` and Feistel key schedule
  - §4.5.1 Encryption `E`, §4.5.2 Decryption `D`
  - §5.1–5.6 worked example and §A.1 test vector
- **GOST R 34.12-2015** — Russian national standard (Kuznyechik is the 128-bit
  cipher; Magma is the 64-bit cipher). RFC 7801 is its English republication.
- **RFC 9367** — GOST cipher suites for TLS 1.2; §4.3 defines
  `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` (`0xC100`), the repo's consumer
  of this primitive.
- **RFC 9189** — GOST cipher suites for TLS 1.2 (key transport / kexp15 context
  for the Kuznyechik usage).

**Key source citations (`file:line`)**

- gogost reference (GPL-3.0 — describe, do not copy):
  - `third_party/gogost/gost3412128/cipher.go:61` `gf` (field multiply, mask
    `0xC3`)
  - `:76` `l`, `:127` `lInv`, `:151` `s`, `:170` `sInv`
  - `:27` `lc` vector, `:31` `pi` table
  - `:176` `init` (constants, π^{-1})
  - `:200` `NewCipher` (key schedule), `:227` `Encrypt`, `:239` `Decrypt`
  - `third_party/gogost/gost3412128/cipher_test.go:82,126,161,196,247,311`
    (stage + final KATs)
- gost-engine ground truth (BSD/OpenSSL-licensed, parity target):
  - `tmp/engine/gost_grasshopper_defines.c:14` π, `:51` π^{-1}, `:88` lvec
  - `tmp/engine/gost_grasshopper_core.c:15` `grasshopper_l`, `:34`
    `grasshopper_l_inv`, `:51` `grasshopper_set_encrypt_key`
  - `tmp/engine/gost_grasshopper_galois_precompiled.c` GF log/antilog tables
- Repo wrappers (current gogost-backed entry points):
  - `internal/gost/primitives_gost.go:83` `KuznyechikEncrypt`, `:92`
    `KuznyechikDecrypt`
  - `internal/gost/exports_gost.go:72` `NewKuznyechikCipher`
  - `internal/gost/primitives_test.go:13` `TestGost_Kuznyechik_Vector`
- `TODO.md` — confirms none of the three gogost↔engine divergences apply to
  Kuznyechik (all three are GOST 28147-89 / R 34.11-94).
