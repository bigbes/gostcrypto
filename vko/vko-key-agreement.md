# VKO key agreement — GOST R 34.10-2001 & 2012

VKO (ВКО, *выработка ключа общего* — "shared key derivation") is the
Diffie-Hellman-style key-agreement function for GOST elliptic-curve keys. One
party combines its own private key, the other party's public key, and a small
"user keying material" (UKM) integer into a single elliptic-curve point, then
hashes that point's coordinates to produce a Key Encryption Key (KEK). It is
symmetric: `KEK(d_A, Q_B, UKM) == KEK(d_B, Q_A, UKM)`.

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

Three variants exist, differing only in the final hash:

| Variant      | Curve size | Hash                         | KEK length | Spec            |
|--------------|------------|------------------------------|------------|-----------------|
| `KEK2001`    | 256-bit    | GOST R 34.11-94 (CryptoPro)  | 32 bytes   | RFC 4357 §5.2   |
| `KEK2012256` | 256/512    | Streebog-256 (GOST 34.11-2012)| 32 bytes  | RFC 7836 §4.3   |
| `KEK2012512` | 512        | Streebog-512 (GOST 34.11-2012)| 64 bytes  | RFC 7836 §4.3   |

GOST/RFC identity: the curve math and signature scheme are **GOST R
34.10-2012** (and the legacy GOST R 34.10-2001). The agreement function itself
is specified in **RFC 4357 §5.2** (2001) and **RFC 7836 §4.3** (2012). The
2012 hash is **GOST R 34.11-2012 / Streebog (RFC 6986)**; the 2001 hash is
**GOST R 34.11-94 (RFC 5831)** with the CryptoPro S-box.

**Status:** `gogost-backed`. `internal/gost/primitives_gost.go` calls
`gogost/v7/gost3410`'s `KEK2001` / `KEK2012256` / `KEK2012512` directly; the
wrapper only marshals `[]byte` ↔ gogost types. A clean-room reimplementation
must replace `KEK*` and the supporting curve arithmetic.

## Where this repo uses it

- **`internal/gost/primitives_gost.go`** — the wrappers:
  - `VKO2001` / `VKO2001OnCurve` / `VKO2001TestCurve` (`primitives_gost.go:220-255`)
  - `VKO2012_256` / `VKO2012_256OnCurve` (`primitives_gost.go:352-370`)
  - `VKO2012_512` (`primitives_gost.go:496-507`)
- **`internal/gost/keg_gost.go:69-72`** — `KEG2012_256` (the RFC 9367 / GOST
  2018 key exchange) calls `KEK2012256` as its inner VKO step.
- **`tls/internal/ke/vkogost.go`** — TLS key-exchange call sites:
  - `VKOGost2001Exchange` (suite **0x0081**, GOST2001-GOST89-GOST89) →
    `gost.VKO2001OnCurve` (`vkogost.go:158`). The VKO output is the KEK fed
    to CryptoPro key-wrap to wrap the 32-byte premaster.
  - `VKOGost2012Exchange` (suites **0xFF85** etc., GOST2012-GOST8912-GOST8912)
    → `gost.VKO2012_256OnCurve` (`vkogost.go` 2012 path).
  - `vkogost.go:126` uses `VKO2001TestCurve` for an internal/test path.
- **`tls/internal/ke/gost2018.go:190`** — RFC 9367 suites (0xC100/0xC101)
  reach VKO through `KEG2012_256`.

In all TLS uses the **UKM is the first 8 bytes of `client_random`**
(`vkogost.go:17`). This raw `client_random[0:8]` rule comes from the legacy
draft-chudov-cryptopro-cptls cipher suites (0x0081 / 0xFF85), not from RFC
9189: RFC 9189's own UKM is derived from `H = Streebog(r_c | r_s)`
(`H[1..8]` for CNT_IMIT, `INT(H[1..16])` for CTR_OMAC — §8.3.1 / §8.3.2),
and its §4.1 is "Record Payload Protection". The repo follows the legacy
raw rule, confirmed against Tarantool-EE 3.5.0. The 2018/KEG path passes a
16-byte reversed UKM (`keg_gost.go:11-14`).

## Specification

### Common structure

Given a local private scalar `d` (an integer mod the subgroup order `q`), a
peer public point `Q = (Q_x, Q_y)`, the curve cofactor `h`, and a UKM integer:

1. Compute the agreement scalar `s = (h · UKM · d) mod q`.
2. Compute the agreement point `K = s · Q` (elliptic-curve scalar
   multiplication). `K = (K_x, K_y)`.
3. Serialize the point as `LE(K_x) || LE(K_y)` — each coordinate
   little-endian, fixed width = curve point size (32 or 64 bytes).
4. `KEK = Hash(LE(K_x) || LE(K_y))`.

The hash choice and output length are the only differences between the three
variants (see table above).

### RFC 4357 §5.2 (VKO GOST R 34.10-2001), verbatim

> This algorithm creates a key encryption key (KEK) using 64 bit UKM, the
> sender's private key, and the recipient's public key (or the reverse of the
> latter pair).
>
> 1) Let K(x,y,UKM) = ((UKM*x)(mod q)) . (y.P) (512 bit), where
>    x - sender's private key (256 bit)
>    x.P - sender's public key (512 bit)
>    y - recipient's private key (256 bit)
>    y.P - recipient's public key (512 bit)
>    UKM - non-zero integer, produced as in step 2 p. 6.1 [GOSTR341001]
>    P - base point on the elliptic curve (two 256-bit coordinates)
>    UKM*x - x multiplied by UKM as integers
>    x.P - a multiple point
> 2) Calculate a 256-bit hash of K(x,y,UKM):
>    KEK(x,y,UKM) = gostR3411 (K(x,y,UKM))
>
> This algorithm MUST NOT be used when x.P = P, y.P = P

Note RFC 4357's formula omits the cofactor `h` because the 2001 CryptoPro
curves all have cofactor 1, so `h` vanishes. The 2012 formula makes it
explicit.

### RFC 7836 §4.3 (VKO GOST R 34.10-2012), verbatim

> KEK_VKO (x, y, UKM) = H_256 (K (x, y, UKM))
> KEK_VKO (x, y, UKM) = H_512 (K (x, y, UKM))
>
> K (x, y, UKM) = (m/q*UKM*x mod q)*(y*P)

where `m` is the elliptic-curve points group order, `q` the cyclic subgroup
order, so `m/q` is the **cofactor `h`**. `H_256` is Streebog-256, `H_512` is
Streebog-512. UKM default value is 1; usable range `1 … 2^(n/2)-1`.

### RFC 7836 §3 — coordinate serialization (verbatim)

> When a point on an elliptic curve is given to an input of a hash function,
> affine coordinates for short Weierstrass form are used: an x coordinate
> value is fed first, a y coordinate value is fed second, both in
> little-endian format.

### Sizes and constants

- Private key scalar `d`: 32 bytes (256-bit curve) or 64 bytes (512-bit
  curve), supplied **little-endian** on the wire.
- Public key point `Q`: `2 × pointSize` bytes; in this repo decoded
  little-endian as `LE(Q_x) || LE(Q_y)` (see delta below).
- UKM: any length on the wire; interpreted as a little-endian integer. TLS
  uses 8 bytes (pre-2018) or a reversed 16-byte value (2018/KEG).
- KEK output: 32 bytes (KEK2001, KEK2012256) or 64 bytes (KEK2012512).
- Point-size rule: `pointSize = 64` if `P.BitLen() > 256`, else `32`
  (`utils.go:36-41`). Note the **256-bit 2012 paramsets** (`paramSetA/B/C/D`)
  have a 256-bit field → 32-byte coordinates, but `VKO2012_256` in this repo
  defaults to a **512-bit** curve (`primitives_gost.go:353`).

### KEK2001 hash detail

`KEK2001` hashes with `gost341194.New(&gost28147.SboxIdGostR341194CryptoProParamSet)`
(`vko2001.go:37`) — GOST R 34.11-94 using the **CryptoPro 34.11-94 S-box**
parameter set. This is distinct from the 28147 cipher S-boxes used by the
key-wrap step that follows in TLS.

## RFC ↔ implementation deltas

This is the section a reimplementer must get exactly right. Each delta cites
both the spec and the source line.

### D1. UKM is little-endian — `NewUKM` reverses bytes

`gost3410.NewUKM(raw)` reverses the byte slice then does a big-endian
`SetBytes` (`ukm.go:23-29`). I.e. the wire UKM is a **little-endian** integer.
gost-engine does the same with `BN_lebin2bn(ukm, ukm_size, scalar)`
(`tmp/engine/gost_ec_keyx.c:60`). RFC 7836 §4.3 calls UKM an integer but does
not spell out endianness; the LE convention is the de-facto standard. A
reimplementer must reverse before interpreting.

Concrete: wire UKM `1d80603c8544c727` → integer `0x27c74485 3c60801d`.

### D2. Cofactor multiplication is conditional, and the test reuses the UKM

gogost's `KEK` (`vko.go:23-37`) computes:

```
keyX, keyY = Exp(d, Q_x, Q_y)        # K1 = d·Q
u = ukm * cofactor                   # u = h·UKM   (NOTE: mutates ukm in place via Mul)
if u != 1:
    keyX, keyY = Exp(u, keyX, keyY)  # K = u·K1 = (h·UKM)·(d·Q)
return Raw(K)
```

Two subtleties:

- The cofactor is applied as an **outer** multiplication `u·(d·Q)`, not folded
  into one scalar mod q. RFC 7836's `(m/q·UKM·x mod q)·(y·P)` reduces the
  whole scalar mod q first; gogost reduces `d` mod q at key load
  (`private.go:45`) and applies UKM/cofactor as separate `Exp` calls. The
  results agree because `Exp` works on the subgroup, but a reimplementer who
  computes `s = (h·UKM·d) mod q` in one shot and does a single `s·Q` is also
  correct and is what gost-engine does (`gost_ec_keyx.c:61` `BN_mod_mul` then
  `gost_ec_point_mul`). **Either factoring is fine; do not double-apply the
  cofactor.**

- **`ukm.Mul(ukm, prv.C.Co)` mutates the caller's `ukm` big.Int**
  (`vko.go:28`). gogost guards against this for the cofactor-1 case via the
  `TestVKOUKMAltering` test (`vko2001_test.go:47-65`) which only passes
  because `Co == 1` leaves the value unchanged after `Set`+`Mul`. On a
  cofactor-4 curve the input `*big.Int` would be clobbered. A reimplementer
  should treat UKM as immutable input and copy it.

- **All 2012 paramsets used in TLS have cofactor 1** (the `id-tc26-…-256/512`
  CryptoPro/TC26 curves), so the `u != 1` branch is normally skipped. The
  cofactor-4 curves (`paramSetA` 256, `paramSetC` 512) **do** apply the
  cofactor — the agreement point is `(h·UKM·d)·Q`. It must be applied **exactly
  once**, but *where* depends on your point-multiply:
  - gost-engine folds it into a cofactor-clearing `gost_ec_point_mul`, so its
    explicit `BN_lshift` by 2 is `#if 0`'d out (`gost_ec_keyx.c:65-78`). Note
    "cofactor clearing" in EC terminology means *multiplying into the prime
    subgroup* — i.e. **applying** the cofactor, not omitting it.
  - gogost and a from-scratch impl with a **generic** double-and-add point-mul
    (which does NOT clear the cofactor) must instead apply it explicitly, as
    the outer `u = h·UKM` multiply shown above.

  Both routes yield the identical KEK — do not apply the cofactor twice, and do
  not drop it. Verified by an inlined cofactor-4 KAT: tc26-256-A, priv
  `0x11`×32, ukm `01 00…00` → KEK `0fb3a1f5…cf529453`, where gogost and the
  clean-room `vko` agree byte-for-byte
  (`vko/cofactor4_test.go`).

### D3. Public-key decode is little-endian `LE(X)||LE(Y)`

`NewPublicKey` is an alias for `NewPublicKeyLE` (`public.go:60-62`). It
reverses the **entire** `2*pointSize` buffer, then reads `X` from the second
half and `Y` from the first half (`public.go:30-44`). Equivalent to: split
into two halves, each is `LE`; `X = LE(raw[:size])`, `Y = LE(raw[size:])`. A
big-endian variant `NewPublicKeyBE` exists but is **not** what VKO callers
use. gost-engine serializes the same way (`BN_bn2lebinpad`,
`gost_ec_keyx.c:99-100`).

### D4. Agreement point serialized `LE(K_x) || LE(K_y)` before hashing

The hash input is `PublicKey.Raw()` = `RawLE()` (`vko.go:36`, `public.go:85`),
which pads `Y` then `X` big-endian, concatenates, and **reverses the whole
thing** (`public.go:65-72`). Net effect = `LE(X) || LE(Y)`, each
`pointSize`-wide. This matches RFC 7836 §3 (x first, y second, both LE) and
gost-engine `gost_ec_keyx.c:99-100`. **Getting the X/Y order or the
endianness wrong is the single most common VKO bug** — the parties will still
agree with each other if both are wrong the same way, but won't match the
reference KEK or the TLS peer.

### D5. KEK2012512 error strings are copy-paste wrong (cosmetic)

`KEK2012512` wraps its errors as `"...KEK2012256: %w"` (`vko2012.go:45,49`).
Harmless, but don't copy the label verbatim when reimplementing.

### D6. KEK2001 uses GOST R 34.11-94 with the CryptoPro S-box

The 2001 hash is **not** Streebog. It is GOST R 34.11-94 with
`SboxIdGostR341194CryptoProParamSet` (`vko2001.go:37`). Two further hazards:

- **Empty-input finalization divergence** (TODO.md, Disagreements). gogost's
  GOST R 34.11-94 `Sum` does 2 step calls; gost-engine's `finish_hash()`
  (`tmp/engine/gosthash.c:257-258`) does an extra zero-block step on
  empty input. **This does not affect VKO**: the hash input is always a
  non-empty `2*pointSize` buffer, where gogost and engine agree bit-for-bit.
  A reimplementer of GOST R 34.11-94 must still get the non-empty path right.
- **34.11-94 S-box row order** (TODO.md): gogost stores S-box rows reversed
  and compensates inside `step()`. If you reimplement GOST R 34.11-94, take
  the S-box and the compensating reversal as a matched pair (or take the
  engine's `Gost28147_TC26ParamSetZ`-style layout directly — see
  CLAUDE.md "read the S-box symbol out of the dylib").

### D7. Private key is reduced mod q, zero rejected

`NewPrivateKeyLE` reverses the LE bytes, rejects zero, and stores `d mod q`
(`private.go:32-46`). Reimplementers must reduce the scalar mod the subgroup
order and reject the all-zero key.

### D8. `Exp(0, …)` is an error

gogost's scalar multiply `Exp` errors on a zero degree (`curve.go:144-147`).
With a non-zero UKM and non-zero `d mod q` this never fires in practice, but a
reimplementer should handle the zero-scalar edge (identity point) deliberately
rather than crash.

## Test vectors

Existing in-repo vectors:

- **`internal/gost/primitives_test.go:170` `TestGost_VKO2012_Agreement`** —
  VKO2012_256 on `id-tc26-gost-3410-2012-512-paramSetA`. Both directions plus
  a fixed expected KEK. (Vectors copied from gogost `vko2012_test.go:25`.)
- **`third_party/gogost/gost3410/vko2001_test.go:26` `TestVKO2001`** —
  VKO2001 on `CurveIdGostR34102001TestParamSet`.
- **`third_party/gogost/gost3410/vko2012_test.go:71` `TestVKO2012512`** —
  the 512-bit KEK variant on the same paramSetA.
- gost-engine `tmp/engine/test/04-pkey.t:160` has a 'derive' subtest, but it
  only checks `sha256(DER(derived key))` — **not directly portable** as a raw
  KAT (TODO.md / `primitives_pkey_vectors_test.go:57` is skipped). Don't chase
  it.

### Inline KAT #1 — VKO GOST R 34.10-2001 (test paramset, cofactor 1)

Curve: `id-GostR3410-2001-TestParamSet` (`params.go:70`, RFC 4357 §11.4).
Hash: GOST R 34.11-94 CryptoPro. The curve parameters (big-endian hex, short
Weierstrass `y² = x³ + a·x + b mod p`, subgroup order `q`, base point
`(x, y)`, cofactor 1) — inlined here so KAT #1 is buildable without consulting
gogost:

```
p = 8000000000000000000000000000000000000000000000000000000000000431
a = 0000000000000000000000000000000000000000000000000000000000000007
b = 5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
q = 8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
x = 0000000000000000000000000000000000000000000000000000000000000002
y = 08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8
co = 1
```

Self-agreement vector (both private keys known, so you can verify symmetry and
the absolute KEK):

```
curve  = id-GostR3410-2001-TestParamSet
ukm    = 5172be25f852a233                         (8 bytes, little-endian int)
d_1    = 1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928  (LE)
d_2    = 5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473  (LE)
Q_1    = d_1 · P    (derive via PublicKey())
Q_2    = d_2 · P
KEK    = KEK2001(d_1, Q_2, ukm) = KEK2001(d_2, Q_1, ukm)
       = ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6
```

### Inline KAT #2 — VKO GOST R 34.10-2012, 256-bit KEK (full hex)

Curve: `id-tc26-gost-3410-2012-512-paramSetA` (cofactor 1, 64-byte
coordinates). Hash: Streebog-256. Both public keys given so it runs
immediately:

```
curve  = id-tc26-gost-3410-2012-512-paramSetA
ukm    = 1d80603c8544c727                         (8 bytes, little-endian int)
d_A    = c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8
         c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667   (64-byte LE)
Q_A    = aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5
         d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7
         914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38
         461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a   (128-byte LE X||Y)
d_B    = 48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b
         8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db
Q_B    = 192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e
         fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651
         04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b
         b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79

KEK256 = KEK2012256(d_A, Q_B, ukm) = KEK2012256(d_B, Q_A, ukm)
       = c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221

KEK512 = KEK2012512(d_A, Q_B, ukm)   (same inputs, Streebog-512)
       = 79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa
         7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf
```

## Re-implementation checklist

Each step is independently testable.

1. **Curve params.** Load the fixed paramsets you need:
   `id-GostR3410-2001-TestParamSet` and `id-tc26-gost-3410-2012-512-paramSetA`
   are enough for the two inline KATs. Field `P`, order `q`, cofactor `Co`,
   coefficients `A,B`, base point `(X,Y)`. Verify `Contains(X,Y)`. (Source for
   the test paramset bytes: `params.go:70-110`.)
2. **`bytes2big` / `pad` / `reverse` helpers** (`utils.go`). Test: reverse is
   its own inverse; `pad` left-zero-pads to fixed width.
3. **Little-endian key loaders.** `NewPrivateKeyLE`: reverse, `SetBytes`,
   reject zero, reduce mod q (`private.go:32-46`). `NewPublicKeyLE`: reverse
   whole buffer, `X=second half, Y=first half` (`public.go:30-44`). Test by
   round-tripping `Raw()`.
4. **`NewUKM`** — reverse then `SetBytes` (D1). Test: `1d80603c8544c727` →
   `0x27c744853c60801d`.
5. **EC scalar multiply `Exp(s, X, Y)`** — double-and-add over short
   Weierstrass `add` (`curve.go:108-161`). Test: `d·P == Q` against a known
   keypair; reject `s == 0`.
6. **Agreement point** (D2): `K1 = Exp(d, Q_x, Q_y)`; `u = (UKM·Co)`; if
   `u != 1`, `K = Exp(u, K1)` else `K = K1`. Keep UKM immutable. Test: both
   directions of the KAT yield the **same** point.
7. **Serialize `LE(K_x) || LE(K_y)`** (D3/D4), each `pointSize` wide. Test
   against the hash input length (`2*pointSize`).
8. **KEK2001** = GOST R 34.11-94 (CryptoPro S-box) of step 7 (D6). Verify
   against inline KAT #1 (`ee4618a0…`).
9. **KEK2012256 / KEK2012512** = Streebog-256 / -512 of step 7. Verify against
   inline KAT #2 (`c9a9a773…` / `79f002a9…`).
10. **Wire integration**: TLS UKM = first 8 bytes of `client_random`
    (`vkogost.go:17`; the raw `client_random[0:8]` rule is the legacy
    draft-chudov-cryptopro-cptls behavior, not RFC 9189's `Streebog(r_c|r_s)`
    UKM); the 2018/KEG path reverses a 16-byte UKM
    (`keg_gost.go:11-14`, `gost_ec_keyx.c:140-145`).

## Conformance & fuzz testing

This is scaffolding for a clean-room implementer: drop it next to your new
package (import alias `mynew`), point the placeholder calls at your exported
VKO functions, and run the commands below. The strategy is **differential
testing against two reference targets**: the raw gogost `gost3410` `KEK*`
methods (`third_party/gogost/gost3410/vko2001.go:29`, `vko2012.go:28,42`) and
the in-repo wrappers `internal/gost.VKO2001TestCurve` / `VKO2012_256` /
`VKO2012_512` (`internal/gost/primitives_gost.go:243,352,496`). VKO is fully
deterministic, so for the fuzz target we generate a random private-key pair
plus an 8-byte UKM on a fixed curve, assert **both parties derive the same
KEK** (symmetry, D2/step 6), and assert that KEK equals the reference's —
catching any X/Y-order or endianness slip (D4) the moment it diverges. There
is no CLI-oracle fallback here: the entire surface (`KEK2001`, `KEK2012256`,
`KEK2012512`) has a native gogost API, so every assertion is an in-process
`bytes.Equal`, never a subprocess.

### Table-driven KAT — pins the exact vectors from this doc

The rows reuse the inline KATs verbatim (KAT #1 `ee4618a0…`, KAT #2
`c9a9a773…` / `79f002a9…`). KAT #1 gives only `d_1`, `d_2` and derives the
peer point `Q = d·P`; we derive it once via gogost `PrivateKey.PublicKey()`
(`third_party/gogost/gost3410/private.go:91`) and feed the resulting LE bytes
to every implementation, so the clean-room impl is never trusted to derive its
own input.

```go
//go:build gost

package mynew_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go.stargrave.org/gogost/v7/gost3410"

	gost "go.bigb.es/tlsdialer/internal/gost" // in-repo wrappers (adjust module path)
	"github.com/.../mynew"              // clean-room impl under test
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// deriveQ returns the LE-encoded public point d·P on curve c (KAT #1 only
// gives the scalars). third_party/gogost/gost3410/private.go:91.
func deriveQ(t *testing.T, c *gost3410.Curve, dLE []byte) []byte {
	t.Helper()
	prv, err := gost3410.NewPrivateKey(c, dLE)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pub, err := prv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return pub.Raw()
}

func TestVKOConformance(t *testing.T) {
	// KAT #1 — VKO 2001, test paramset, cofactor 1 (doc lines 264-272).
	curve2001 := gost3410.CurveIdGostR34102001TestParamSet()
	d1 := mustHex(t, "1df129e43dab345b68f6a852f4162dc69f36b2f84717d08755cc5c44150bf928")
	d2 := mustHex(t, "5b9356c6474f913f1e83885ea0edd5df1a43fd9d799d219093241157ac9ed473")
	ukm2001 := mustHex(t, "5172be25f852a233")
	Q1 := deriveQ(t, curve2001, d1)
	Q2 := deriveQ(t, curve2001, d2)

	// KAT #2 — VKO 2012, id-tc26-gost-3410-2012-512-paramSetA (doc lines 281-302).
	dA := mustHex(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	QA := mustHex(t, "aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5"+
		"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"+
		"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38"+
		"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	dB := mustHex(t, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
		"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	QB := mustHex(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"+
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"+
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	ukm2012 := mustHex(t, "1d80603c8544c727")

	type variant int
	const (
		v2001 variant = iota
		v2012_256
		v2012_512
	)

	cases := []struct {
		name        string
		v           variant
		prv, peer   []byte
		ukm         []byte
		wantHex     string
	}{
		{"2001/A", v2001, d1, Q2, ukm2001, "ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6"},
		{"2001/B", v2001, d2, Q1, ukm2001, "ee4618a0dbb10cb31777b4b86a53d9e7ef6cb3e400101410f0c0f2af46c494a6"},
		{"2012_256/A", v2012_256, dA, QB, ukm2012, "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"},
		{"2012_256/B", v2012_256, dB, QA, ukm2012, "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221"},
		{"2012_512/A", v2012_512, dA, QB, ukm2012,
			"79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa" +
				"7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := mustHex(t, tc.wantHex)

			// reference 1: in-repo internal/gost wrappers.
			// reference 2: raw gogost gost3410 KEK*.
			var (
				got      []byte // clean-room impl
				refLocal []byte
				refGo    []byte
				err      error
			)
			switch tc.v {
			case v2001:
				got, err = mynew.VKO2001TestCurve(tc.prv, tc.peer, tc.ukm)
				if err != nil {
					t.Fatalf("mynew: %v", err)
				}
				refLocal, err = gost.VKO2001TestCurve(tc.prv, tc.peer, tc.ukm)
				if err != nil {
					t.Fatalf("gost: %v", err)
				}
				refGo = kekGo(t, curve2001, tc.prv, tc.peer, tc.ukm, v2001)
			case v2012_256:
				got, err = mynew.VKO2012_256(tc.prv, tc.peer, tc.ukm)
				if err != nil {
					t.Fatalf("mynew: %v", err)
				}
				refLocal, err = gost.VKO2012_256(tc.prv, tc.peer, tc.ukm)
				if err != nil {
					t.Fatalf("gost: %v", err)
				}
				refGo = kekGo(t, gost3410.CurveIdtc26gost341012512paramSetA(), tc.prv, tc.peer, tc.ukm, v2012_256)
			case v2012_512:
				got, err = mynew.VKO2012_512(tc.prv, tc.peer, tc.ukm)
				if err != nil {
					t.Fatalf("mynew: %v", err)
				}
				refLocal, err = gost.VKO2012_512(tc.prv, tc.peer, tc.ukm)
				if err != nil {
					t.Fatalf("gost: %v", err)
				}
				refGo = kekGo(t, gost3410.CurveIdtc26gost341012512paramSetA(), tc.prv, tc.peer, tc.ukm, v2012_512)
			}

			for label, ref := range map[string][]byte{"pinned": want, "internal/gost": refLocal, "gogost": refGo} {
				if !bytes.Equal(got, ref) {
					t.Fatalf("KEK mismatch vs %s:\n got = %x\n ref = %x", label, got, ref)
				}
			}
		})
	}
}
```

The single helper that drives both gogost references (and is reused by the
fuzz target) wraps the raw `KEK*` methods:

```go
// kekGo computes the reference KEK with raw gogost gost3410 — the same path
// internal/gost wraps. vko.go:23, vko2001.go:29, vko2012.go:28/42.
func kekGo(t *testing.T, c *gost3410.Curve, prvLE, pubLE, ukmRaw []byte, v variant) []byte {
	t.Helper()
	prv, err := gost3410.NewPrivateKey(c, prvLE)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pub, err := gost3410.NewPublicKey(c, pubLE)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	ukm := gost3410.NewUKM(ukmRaw)
	var kek []byte
	switch v {
	case v2001:
		kek, err = prv.KEK2001(pub, ukm)
	case v2012_256:
		kek, err = prv.KEK2012256(pub, ukm)
	case v2012_512:
		kek, err = prv.KEK2012512(pub, ukm)
	}
	if err != nil {
		t.Fatalf("KEK: %v", err)
	}
	return kek
}
```

### Fuzz harness — random key pair + 8-byte UKM, symmetry + reference

VKO has no plaintext to round-trip, so the randomized invariant is
**agreement symmetry plus reference equality**: derive both peers' public
points from two random scalars, then assert
`mynew(d_A,Q_B,ukm) == mynew(d_B,Q_A,ukm) == gogost == internal/gost`. We pin
the fuzz curve to `id-tc26-gost-3410-2012-512-paramSetA` (the `VKO2012_256`
default, `primitives_gost.go:352`) so a 64-byte scalar and 128-byte point are
the fixed-size arguments; the raw `[]byte` from the fuzzer is normalized by
slicing/zero-padding to those widths and forced non-zero (D7 rejects the
all-zero scalar). The corpus is seeded from the KAT scalars.

```go
func FuzzVKOConformance(f *testing.F) {
	f.Add(
		mustHexF(f, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
			"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"),
		mustHexF(f, "48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"+
			"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"),
		mustHexF(f, "1d80603c8544c727"),
	)

	curve := gost3410.CurveIdtc26gost341012512paramSetA()

	f.Fuzz(func(t *testing.T, rawA, rawB, rawUKM []byte) {
		dA := norm(rawA, 64) // 64-byte LE scalar, forced non-zero
		dB := norm(rawB, 64)
		ukm := norm(rawUKM, 8) // 8-byte LE UKM, forced non-zero

		// Derive each peer's public point with gogost (trusted input source).
		QA := deriveQF(t, curve, dA)
		QB := deriveQF(t, curve, dB)
		if QA == nil || QB == nil { // scalar landed on identity / out of range
			return
		}

		// clean-room: both directions.
		kAB, err := mynew.VKO2012_256(dA, QB, ukm)
		if err != nil {
			return // a rejected scalar is a valid outcome, not a mismatch
		}
		kBA, err := mynew.VKO2012_256(dB, QA, ukm)
		if err != nil {
			t.Fatalf("mynew asymmetric error: B->A failed but A->B did not")
		}
		if !bytes.Equal(kAB, kBA) {
			t.Fatalf("symmetry broken: A->B=%x  B->A=%x", kAB, kBA)
		}

		// reference equality (gogost + internal/gost), one direction is enough.
		if ref := kekGoF(t, curve, dA, QB, ukm, v2012_256); !bytes.Equal(kAB, ref) {
			t.Fatalf("KEK != gogost:\n got=%x\n ref=%x", kAB, ref)
		}
		if ref, err := gost.VKO2012_256(dA, QB, ukm); err == nil && !bytes.Equal(kAB, ref) {
			t.Fatalf("KEK != internal/gost:\n got=%x\n ref=%x", kAB, ref)
		}
	})
}

// norm slices or zero-extends b to n bytes (LE) and forces a non-zero low byte
// so NewPrivateKeyLE/NewUKM never see all-zero (D7/D1).
func norm(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	out[0] |= 0x01
	return out
}
```

`mustHexF`, `deriveQF`, and `kekGoF` are the `*testing.F` twins of the KAT
helpers above (identical bodies, `f.Fatalf` in place of `t.Fatalf`);
`deriveQF` returns `nil` instead of failing when `PublicKey()` errors, so the
fuzzer skips out-of-subgroup scalars rather than aborting.

### Run

```sh
go test -tags gost -run TestVKOConformance ./yourpkg/
go test -tags gost -fuzz=FuzzVKOConformance -fuzztime=30s ./yourpkg/
```

## References

- **RFC 4357 §5.2** — VKO GOST R 34.10-2001 key agreement.
  https://github.com/bigbes/gostcrypto/blob/master/vko/rfc/rfc4357.txt
- **RFC 7836 §3, §4.3** — VKO_GOSTR3410_2012_256/512, point serialization.
  https://github.com/bigbes/gostcrypto/blob/master/vko/rfc/rfc7836.txt
- **RFC 6986** — GOST R 34.11-2012 (Streebog), the 2012 KEK hash.
  https://github.com/bigbes/gostcrypto/blob/master/vko/rfc/rfc6986.txt
- **RFC 5831** — GOST R 34.11-94, the 2001 KEK hash.
  https://github.com/bigbes/gostcrypto/blob/master/vko/rfc/rfc5831.txt
- **RFC 9189** — GOST cipher suites for TLS 1.2. Note: its own UKM is
  `H[1..8]` / `INT(H[1..16])` of `Streebog(r_c|r_s)` (§8.3.1 / §8.3.2), and
  §4.1 is "Record Payload Protection". The raw `client_random[0:8]` UKM this
  repo uses comes from the legacy **draft-chudov-cryptopro-cptls** suites
  (0x0081 / 0xFF85), not RFC 9189.
- **GOST R 34.10-2012 / GOST R 34.10-2001** — the signature/curve standards.
- **GOST R 34.11-2012**, **GOST R 34.11-94** — the hash standards.

Source citations:

- gogost VKO: `third_party/gogost/gost3410/vko.go:23-37` (`KEK`),
  `vko2001.go:29-42` (`KEK2001`), `vko2012.go:28-52`
  (`KEK2012256`/`KEK2012512`), `ukm.go:23-29` (`NewUKM`),
  `public.go:30-87` (LE encode/decode + `Raw`), `private.go:32-46`,
  `curve.go:108-161` (point add/`Exp`), `params.go:70` (test paramset).
- repo wrappers: `internal/gost/primitives_gost.go:220-255, 352-370, 496-507`;
  `internal/gost/keg_gost.go:36-77`.
- TLS call sites: `tls/internal/ke/vkogost.go:126,158`,
  `tls/internal/ke/gost2018.go:190`.
- gost-engine ground truth: `tmp/engine/gost_ec_keyx.c:26-126`
  (`VKO_compute_key`), `:132-179` (`gost_keg`), `:65-78` (cofactor note),
  `:99-100` (LE coordinate serialization).
- divergence notes: `TODO.md` (34.11-94 empty-input finalization, S-box row
  order), `CLAUDE.md` (gogost gotchas, S-box dylib extraction).
