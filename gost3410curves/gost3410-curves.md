# GOST R 34.10 curve parameter sets (CryptoPro + TC26)

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

## 1. What it is and where the repo uses it

A **GOST R 34.10 curve parameter set** is the fixed tuple
`(p, a, b, q, x, y)` (plus an optional cofactor and twisted-Edwards
`(e, d)` pair) that defines one named elliptic curve over a prime field
`GF(p)`. GOST R 34.10-2001 and GOST R 34.10-2012 do **not** define a single
curve; instead an X.509 certificate, a key, or a TLS handshake names a
parameter set by **OID**, and every signing / verifying / VKO / KEG operation
must first resolve that OID to the concrete `(p, a, b, q, x, y)` constants.

This document is the clean-room spec for the **parameter-set tables and the
OID→curve resolution** only. The point arithmetic, signature, and key-exchange
algorithms that *consume* a resolved curve are separate primitives (see
`gost3410-sign.md`, `vko.md` when they exist). The contract here is narrow and
exact: given an OID, produce the right integers, in the right form
(Weierstrass vs. twisted Edwards), with the right cofactor.

Standards identity:
- **GOST R 34.10-2001** — superseded signature standard; its 256-bit curves
  (`1.2.643.2.2.35.x`) are still used by Tarantool-EE legacy `0x0081` suites.
- **GOST R 34.10-2012** — current standard (RFC 7091 describes the algorithm).
- Curve constants are specified by **RFC 4357 §11** (CryptoPro 2001 sets) and
  **RFC 7836 §5 / Appendix A** (TC26 2012 sets). `draft-deremin-rfc4491-bis`
  collects the full OID list and the 2012↔2001 aliasing.

### Where this repo uses it

Status: **gogost-backed.** Every curve in this repo is currently produced by
`go.stargrave.org/gogost/v7/gost3410` (vendored, GPL-3.0). The only resolution
point is `internal/gost.CurveByOID`, which is a pure OID→constructor switch.

Call sites (grepped):

| Caller | Site | Purpose |
|---|---|---|
| `x509gost/verify.go:196` | `gost.CurveByOID(parent.CurveOID)` | resolve the issuer cert's curve before `VerifyDigestOnCurve` |
| `tls/internal/handshake/kex_gost.go:27,62` | `gost.CurveByOID(gc.CurveOID)` | resolve the server cert curve for VKO / KEG key exchange |
| `tls/internal/ke/vkogost.go` | via `CurveByOID` | VKO 2001/2012 shared-secret derivation |
| `internal/gost/keg_gost.go:61,65` | `gost3410.NewPrivateKey/NewPublicKey(curve.inner, …)` | RFC 9367 KEG key exchange (256-bit tc26 curves) |

The opaque wrapper is `internal/gost/primitives_gost.go:32`
(`type Curve struct{ inner *gost3410.Curve }`). Public surface on it:
`Name()` (`exports_gost.go:125`) and `PointSize()` (`exports_gost.go:129`).
No caller outside `internal/gost` ever names `gogost`.

---

## 2. Specification

### 2.1 Curve equation forms

Two equation forms appear (RFC 7836 §5.1 / §5.2):

- **Short Weierstrass** (canonical, all 2001 sets and most 2012 sets):
  `y² = x³ + a·x + b (mod p)`
- **Twisted Edwards** (RFC 7836 §5.2; only `tc26-256-A`, `tc26-512-C`):
  `e·u² + v² = 1 + d·u²·v² (mod p)`

  A twisted-Edwards set still carries Weierstrass `(a,b,x,y)` — those are the
  *birationally equivalent* Weierstrass coordinates that all signing/VKO uses.
  The `(e,d)` pair plus the equivalent Edwards basepoint `(u,v)` is **extra**
  data; it is only needed if you implement the `XY2UV` / `UV2XY` coordinate
  maps (`third_party/gogost/gost3410/edwards.go`). For signature and VKO you
  can ignore `(e,d)` entirely and treat every curve as Weierstrass.

### 2.2 Parameters and their sizes

| Field | Meaning | 256-bit size | 512-bit size |
|---|---|---|---|
| `p` | field characteristic (prime) | 32 B | 64 B |
| `a` | Weierstrass coefficient | ≤ 32 B | ≤ 64 B |
| `b` | Weierstrass coefficient | ≤ 32 B | ≤ 64 B |
| `q` | order of the basepoint cyclic subgroup (prime) | 32 B | 64 B |
| `x`,`y` | basepoint affine coordinates | ≤ 32 B | ≤ 64 B |
| `co` | cofactor (`m = co·q`, `m` = full curve order) | small int | small int |
| `e`,`d` | twisted-Edwards coeffs (only A-256, C-512) | — | — |

`PointSize()` is derived purely from `p`: **32 if `p.BitLen() ≤ 256`, else
64** (`third_party/gogost/gost3410/utils.go:36`). It is *not* read from a
table — a reimplementation must compute it from `p`. All public keys,
private keys, and signature halves are `PointSize()` bytes each;
public keys are `2·PointSize()` (X‖Y), signatures `2·PointSize()` (s‖r).

### 2.3 The validity contract

`NewCurve` (`third_party/gogost/gost3410/curve.go:56`) **rejects** a parameter
set whose basepoint is not on the curve: it computes `Contains(x,y)` and
returns an error otherwise (`curve.go:66`). `Contains`
(`curve.go:82`) checks `y² ≡ x³ + a·x + b (mod p)` exactly. A reimplementation
SHOULD do the same self-check at construction; every table below passes it.

Cofactor defaulting: if `co == nil`, `Co` is set to **1**
(`curve.go:73-77`). For most sets `co = 1`; the twisted-Edwards sets
(`tc26-256-A`, `tc26-512-C`) and `CryptoPro-C`/`tc26-256-D` have `co = 4`.

### 2.4 OID → parameter-set table (the pasteable artifact)

This is exactly what `internal/gost/primitives_gost.go:53-77` resolves.
All hex below is **big-endian** (the natural integer notation). The byte
arrays in gogost are big-endian too; little-endianness only enters at the
key/signature *wire* layer (see §3.1), never in these constants.

#### CryptoPro 2001, 256-bit (RFC 4357 §11.2; aliased to tc26 2012 256-bit sets)

The 2001 CryptoPro sets are **identical curves** to three of the tc26 2012
256-bit sets — gogost literally aliases them
(`third_party/gogost/gost3410/params.go:614-631`):

| OID | Name | gogost constructor | identical to |
|---|---|---|---|
| `1.2.643.2.2.35.1` | CryptoPro-A | `CurveIdGostR34102001CryptoProAParamSet` | tc26-256-**B** |
| `1.2.643.2.2.35.2` | CryptoPro-B | `CurveIdGostR34102001CryptoProBParamSet` | tc26-256-**C** |
| `1.2.643.2.2.35.3` | CryptoPro-C | `CurveIdGostR34102001CryptoProCParamSet` | tc26-256-**D** |

(The XchA/XchB exchange sets `1.2.643.2.2.36.{0,1}` alias A and C again; the
repo does not register them in `CurveByOID`.)

**CryptoPro-A** (= tc26-256-B), `co = 1`, Weierstrass
(`params.go:173-219`; engine `tmp/engine/gost_params.c:28-35`):
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
a = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94
b = 00000000000000000000000000000000000000000000000000000000000000A6
q = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
x = 0000000000000000000000000000000000000000000000000000000000000001
y = 8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14
```

**CryptoPro-B** (= tc26-256-C), `co = 1`, Weierstrass
(`params.go:221-268`; engine `gost_params.c:40-47`):
```
p = 8000000000000000000000000000000000000000000000000000000000000C99
a = 8000000000000000000000000000000000000000000000000000000000000C96
b = 3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B
q = 800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F
x = 0000000000000000000000000000000000000000000000000000000000000001
y = 3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC
```

**CryptoPro-C** (= tc26-256-D), `co = 4`, Weierstrass
(`params.go:270-318`; engine `gost_params.c:52-59` — note engine lists
cofactor `1` here, see §3.5):
```
p = 9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B
a = 9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598
b = 000000000000000000000000000000000000000000000000000000000000805A
q = 9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9
x = 0000000000000000000000000000000000000000000000000000000000000000
y = 41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67
```

#### TC26 2012, 256-bit (RFC 7836 §5.2 / draft-deremin)

| OID | Name | gogost constructor | form | `co` |
|---|---|---|---|---|
| `1.2.643.7.1.2.1.1.1` | tc26-256-A | `CurveIdtc26gost341012256paramSetA` | twisted Edwards | 4 |
| `1.2.643.7.1.2.1.1.2` | tc26-256-B | `CurveIdtc26gost341012256paramSetB` | Weierstrass | 1 |
| `1.2.643.7.1.2.1.1.3` | tc26-256-C | `CurveIdtc26gost341012256paramSetC` | Weierstrass | 1 |
| `1.2.643.7.1.2.1.1.4` | tc26-256-D | `CurveIdtc26gost341012256paramSetD` | Weierstrass | 1* |

\* gogost passes `co = nil` for D (`params.go:309`), so it defaults to **1**,
even though D's full curve order is `4·q`. See §3.5 — this is a known cofactor
under-specification that does not affect sign/verify/VKO (none of those use
`Co`).

**tc26-256-A** (`co = 4`, twisted Edwards, `params.go:118-171`;
engine `gost_params.c:88-102`). Weierstrass coords used for crypto:
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
a = C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335
b = 295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513
q = 400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67
x = 91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28
y = 32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C
e = 1
d = 0605F6B7C183FA81578BC39CFAD518132B9DF62897009AF7E522C32D6DC7BFFB
```
(`tc26-256-B/C/D` are the CryptoPro-A/B/C tables above — same integers.)

#### TC26 2012, 512-bit (RFC 7836 §5.1 / Appendix A.1)

| OID | Name | gogost constructor | form | `co` |
|---|---|---|---|---|
| `1.2.643.7.1.2.1.2.1` | tc26-512-A | `CurveIdtc26gost341012512paramSetA` | Weierstrass | 1 |
| `1.2.643.7.1.2.1.2.2` | tc26-512-B | `CurveIdtc26gost341012512paramSetB` | Weierstrass | 1 |
| `1.2.643.7.1.2.1.2.3` | tc26-512-C | `CurveIdtc26gost34102012512paramSetC` | twisted Edwards | 4 |

**tc26-512-A** (`co = 1`, Weierstrass, `params.go:383-455`;
engine `gost_params.c:132-150`):
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
a = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4
b = E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265
    EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760
q = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275
x = 3
y = 7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921
    DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4
```

**tc26-512-B** (`co = 1`, Weierstrass, `params.go:456-528`;
engine `gost_params.c:152-170`):
```
p = 8000000000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000006F
a = 8000000000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000000000006C
b = 687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F
    3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116
q = 8000000000000000000000000000000000000000000000000000000000000001
    49A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD
x = 2
y = 1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335
    DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD
```

**tc26-512-C** (`co = 4`, twisted Edwards, `params.go:529-610`;
engine `gost_params.c:172-191` lists it Weierstrass with cofactor 4):
```
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7
a = DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645
    46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3
b = B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE0
    38CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1
q = 3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    C98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED
x = E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043A
    A27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148
y = F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9B
    E18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F
e = 1
d = 9E4F5D8C017D8D9F13A5CF3CDF5BFE4DAB402D54198E31EBDE28A0621050439C
    A6B39E0A515C06B304E2CE43E79E369E91A0CFC2BC2A22B4CA302DBB33EE7550
```
(Whitespace inside the 64-byte hex above is purely for line-wrapping;
concatenate to 128 hex chars = 64 bytes.)

Also defined but **not registered in `CurveByOID`** (test-only):
`id-GostR3410-2001-TestParamSet` (`1.2.643.2.2.35.0`, `params.go:70`) and
`id-tc26-gost-3410-12-512-paramSetTest` (`params.go:319`). The repo exposes
the 2001 test set via `GOST2001TestParamSetCurve` for vector round-trips only.

---

## 3. RFC ↔ implementation deltas

This is the section a reimplementer must internalize. The constants are easy;
the *contracts around them* are where parity breaks.

### 3.1 Endianness: constants are BE, the wire is LE

The parameter tables above are big-endian integers. But every value that
crosses a boundary — raw private key, raw public key, signature — is
**little-endian** in GOST. gogost stores `Curve` integers as `*big.Int`
(BE-natural) via `bytes2big` (`utils.go:22`), yet:

- `NewPublicKeyLE` reverses the input bytes before splitting into X‖Y
  (`public.go:30-44`): wire layout is `LE(X)‖LE(Y)`, and the reversal of the
  whole `2·PointSize` buffer swaps both the byte order *and* the X/Y order, so
  it reads back `Y = first half, X = second half` of the reversed buffer.
- `RawLE()` pads `Y` then `X` big-endian, concatenates `pad(Y)‖pad(X)`, then
  reverses the entire buffer (`public.go:65-72`).

Contract for a reimplementation: **the curve constants are NEVER reversed**;
only key/signature *serialization* is little-endian. Do not byte-swap `p,a,b,q,x,y`.

Note the matching wrapper docs: `internal/gost/keygen_gost.go:9-10` —
"privRaw: little-endian … pubRaw: little-endian (LE Y ‖ LE X)". The `Y‖X`
(not `X‖Y`) order on the wire is a direct consequence of the whole-buffer
reverse in `RawLE`.

### 3.2 PointSize is computed from `p`, not stored

`pointSize(p)` returns 64 iff `p.BitLen() > 256`, else 32
(`utils.go:36-41`). A naive reimplementation that keys point size off the OID
family would mis-size the test curves or any future set. Always derive it from
`p.BitLen()`. All 256-bit sets here have `p.BitLen()` exactly 256 (top byte
`0xFF` or `0x80`/`0x9B`); 512-bit sets have `p.BitLen()` 511–512.

### 3.3 Twisted-Edwards sets still verify/sign as Weierstrass

RFC 7836 §5.2 gives `tc26-256-A` and `tc26-512-C` in twisted-Edwards form
with `(e,d,u,v)`. gogost stores those **plus** the equivalent Weierstrass
`(a,b,x,y)` (`params.go:118-171`, `529-610`), and `IsEdwards()` is true only
because `E != nil` (`edwards.go:22-24`). Critically, *signature and VKO never
touch `E`/`D`*: `Exp`/`add`/`Contains` are pure Weierstrass
(`curve.go:82-161`). The Edwards data is only consumed by `XY2UV`/`UV2XY`
(`edwards.go:50,73`), which nothing in this repo's TLS path calls.

Reimplementation guidance: you may **omit `(e,d)` entirely** and store every
curve as Weierstrass `(p,a,b,q,x,y,co)`. The OID→curve switch then collapses
to one uniform shape. Only re-add Edwards if you implement RFC 7836 point
compression.

### 3.4 The 2001↔2012 256-bit aliasing is real, not coincidental

`CryptoPro-A/B/C` (`1.2.643.2.2.35.{1,2,3}`) and `tc26-256-{B,C,D}`
(`1.2.643.7.1.2.1.1.{2,3,4}`) are the **same six integers**. gogost makes the
2001 names thin aliases that just rename a 2012 curve
(`params.go:614-631`). The engine keeps two parallel tables but with identical
bytes (`gost_params.c:109` literally `R3410_2012_256_paramset =
R3410_2001_paramset`). A reimplementation can collapse both OIDs to one
constructor — but it MUST still accept *both* OID arcs, because certs and the
TLS handshake use whichever the issuer chose. `CurveByOID`
(`primitives_gost.go:55-68`) handles `35.x` and `1.1.x` separately for exactly
this reason.

### 3.5 Cofactor disagreements (gogost vs. engine vs. reality)

The cofactor `Co` is stored but **unused by any sign/verify/VKO/KEG path** in
this repo — gogost's `Exp` and `Contains` never reference `Co`. So the
following discrepancies are benign for the operations the repo performs, but a
reimplementer who later adds subgroup-membership checks (cofactor clearing)
must get them right:

- **CryptoPro-C / tc26-256-D**: true curve order is `4·q` (cofactor 4). gogost
  passes `co = nil` for tc26-256-D → defaults to **1** (`params.go:309`,
  `curve.go:73`). The engine table also writes cofactor `"1"` for CryptoPro-C
  (`gost_params.c:59`). Both are wrong against the standard's `4`, but
  harmless here.
- **tc26-256-A and tc26-512-C**: gogost passes `bigInt4`
  (`params.go:164`, `603`), matching the standard. The engine writes `"4"` for
  tc26-512-C (`gost_params.c:191`) and `"4"` for tc26-256-A
  (`gost_params.c:102`). Consistent.

Decision for a reimpl: store the **mathematically correct** cofactor (1 for
A/B 512 and 256-B/C; 4 for 256-A, 256-D, 512-C, and CryptoPro-C), and never
rely on gogost's `nil`-defaulted value for D.

### 3.6 Engine table field order is `{a,b,p,q,x,y,cofactor}` — do not copy positionally

`tmp/engine/gost_params.c` lists fields in the order
**a, b, p, q, x, y, cofactor** (struct `R3410_ec_params` at
`tmp/engine/gost_lcl.h:32-42`), whereas gogost's `NewCurve` signature is
`(p, q, a, b, x, y, e, d, co)` (`curve.go:56`). When cross-checking a value
against the engine, map by *label*, not by column position — `a` is the first
engine string but the third gogost argument. This trap has bitten vector
ports before; read the `/* a */`, `/* p */` comments in `gost_params.c`.

### 3.7 No S-box / meshing / finalization quirks here

This primitive is pure big-integer curve data. The three known
gogost↔engine divergences logged in `TODO.md` (S-box row order, R 34.11-94
empty-input finalization, CryptoPro key meshing) all belong to the symmetric /
hash primitives and **do not touch curve parameters**. The only curve-specific
under-specifications are the cofactors in §3.5. The S-box row-order divergence
is mentioned in `TODO.md:9` only as a *corrected wrong theory*; it is
irrelevant to GOST R 34.10 curves.

---

## 4. Test vectors

### 4.1 Self-check every table at construction (KAT #0)

The cheapest vector is the on-curve check itself. For each set, verify
`y² ≡ x³ + a·x + b (mod p)`. gogost runs this inside `NewCurve`
(`curve.go:66`→`Contains` `curve.go:82`); if your table is wrong by one byte,
this fails immediately. Run it for all ten registered sets.

### 4.2 Inline sign/verify KAT (runnable now)

From `internal/gost/primitives_test.go:83-104` (RFC 7091 §A.1 vector). Note
the curve: `R341012Sign`/`R341012Verify` hardcode the 2001 test parameter set
(`primitives_gost.go:189-202`, `gost3410.CurveIdGostR34102001TestParamSet`,
`id-GostR3410-2001-TestParamSet`), not a registered production OID — this KAT
exercises the sign/verify math, not OID resolution. The private key is given
big-endian here; the wrapper consumes it as LE bytes (§3.1):

```
curve   = id-GostR3410-2001-TestParamSet   (gogost test curve, not a registered OID)
prvRaw  = 7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28
digest  = 2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5
```
Procedure: `sig = R341012Sign(prvRaw, digest)` then
`R341012Verify(prvRaw, digest, sig)` MUST return true. Because GOST sign
uses a random nonce `k`, the signature is not fixed — verify the round-trip,
not a fixed `sig`.

To exercise the production tc26-256-A curve (OID 1.2.643.7.1.2.1.1.1)
specifically, use `curve_sign_sweep_test.go`'s `GOST2012-256-TC26-A` subtest
(`TestCurveSignVerify_AllCurves`, on `CurveIdtc26gost341012256paramSetA`); its
resolution from the OID is pinned by `TestCurveByOID_SupportedCurvesSanity`'s
`TC26-256-A` subtest (§4.3). A reimplementer's tc26-256-A table is correct iff
both of those pass.

### 4.3 Existing tests that pin curve resolution

- `internal/gost/curve_sign_sweep_test.go` — sign/verify sweep across the
  resolved curves; the canonical "does `CurveByOID` return a usable curve"
  test.
- `x509gost/verify_curve_coverage_test.go` — exercises `CurveByOID` for every
  supported parameter OID through real certificate verification.
- `x509gost/key_encoding_roundtrip_test.go` — LE key (un)marshal round-trip;
  pins the §3.1 endianness contract.
- `internal/gost/keg_gost_test.go` — RFC 9367 KEG on 256-bit tc26 curves.
- `internal/gost/keygen_gost_test.go` — `pubRaw = LE(Y)‖LE(X)` layout (§3.1).

### 4.4 Engine ground-truth tables

`tmp/engine/gost_params.c:14-105` (2001 + 256-bit) and `:111-194` (512-bit)
are the byte-for-byte parity target (Tarantool's upstream). Cross-check each
value against the gogost table by **label**, per §3.6.
`tmp/engine/test_params.c` and `tmp/engine/test_curves.c` run the engine's own
on-curve and order checks.

---

## 5. Re-implementation checklist

Each step is independently testable against a vector above.

1. **Define the curve struct** as Weierstrass `{p, a, b, q, x, y, co *big.Int}`
   (optionally `e,d` only if you need Edwards maps). All `*big.Int` are
   big-endian — never reverse them. *Test:* construct and dump.
2. **Hardcode the ten registered tables** from §2.4 (CryptoPro-A/B/C,
   tc26-256-A/B/C/D, tc26-512-A/B/C), big-endian. Collapse 2001↔2012 256-bit
   aliases to shared constants if you like, but keep both OID arcs. *Test:*
   §4.1 on-curve check `y²≡x³+ax+b (mod p)` passes for all.
3. **Implement `PointSize` from `p.BitLen()`** (32 if ≤256 else 64), not from
   the OID. *Test:* tc26-512-* report 64, others 32.
4. **Set cofactors correctly** (§3.5): 4 for tc26-256-A, tc26-256-D,
   tc26-512-C, CryptoPro-C; 1 otherwise. Do not inherit gogost's nil-default
   for D. *Test:* assert `co` per set.
5. **Write `CurveByOID`** mirroring `primitives_gost.go:53-77`: a switch over
   the ten OIDs returning the right table, error on unknown. *Test:* feed
   each OID from `x509gost/oids.go:64-100`, expect the matching name; feed a
   junk OID, expect an error.
6. **Wire (de)serialization**: `RawLE` = `reverse(pad(Y)‖pad(X))`, `NewPublicKeyLE`
   = reverse whole buffer then split (§3.1). Keep this strictly separate from
   the curve constants. *Test:* §4.3 `key_encoding_roundtrip_test.go` shape.
7. **End-to-end on-curve + sign/verify** on tc26-256-A with the §4.2 vector:
   resolve `1.2.643.7.1.2.1.1.1`, sign, verify true. *Test:* §4.2.
8. **Engine parity sweep**: diff every constant against
   `tmp/engine/gost_params.c` by label (§3.6). *Test:* byte-equality per field.

---

## Conformance & fuzz testing

When you replace the gogost-backed `CurveByOID` with a clean-room table, you
need a mechanical proof that your `(p,a,b,q,x,y)` integers and your OID switch
match the reference for **every** supported OID. For this primitive the
differential target is gogost's `gost3410.CurveId*` constructors (the same raw
curve params §2.4 was transcribed from): for each OID, compare your clean-room
curve's `P,A,B,Q,X,Y` `*big.Int`s field-by-field against gogost's, then assert
the base point is on your curve (`y²≡x³+ax+b mod p`, §4.1) and that its order
is `q` (i.e. `q·G = ∞`). There is no byte-stream to fuzz here — the curve is a
fixed table, so a table conformance test **over all ten OIDs** is the right
shape; the "fuzz" harness just randomizes *which* OID and re-runs the same
on-curve / order invariants. The sign/verify KAT (§4.2) round-trips through the
resolved curve, which transitively exercises `X,Y,Q` end-to-end.

These tests live in your clean-room package (import alias `mynew`). The
reference is imported directly — `gost3410` has a public Go API for curves, so
no CLI oracle is needed here (unlike OMAC / CTR-ACPKM / KEG / KExp15 / KeyWrap,
whose only ground truth is the gost-engine `openssl` command from CLAUDE.md).

### Table-driven conformance KAT

Seeded with the exact pinned hex from §2.4 (CryptoPro-A / tc26-256-A) and the
RFC 7091 sign/verify vector from §4.2. `mynew` is your clean-room package;
`gost3410` is the reference (`go.stargrave.org/gogost/v7/gost3410`).

```go
//go:build gost

package yourpkg_test

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"

	mynew "example.com/yourpkg"

	refg "go.stargrave.org/gogost/v7/gost3410"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// Pinned (p,a,b,q,x,y) from §2.4 — big-endian, never reversed (§3.1).
var curveKATs = []struct {
	name string
	oid  asn1.ObjectIdentifier
	p, a, b, q, x, y string
	pointSize int
}{
	{
		name: "CryptoPro-A", oid: asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1},
		p: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
		a: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
		b: "00000000000000000000000000000000000000000000000000000000000000A6",
		q: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
		x: "0000000000000000000000000000000000000000000000000000000000000001",
		y: "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
		pointSize: 32,
	},
	{
		name: "tc26-256-A", oid: asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1},
		p: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
		a: "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
		b: "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
		q: "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
		x: "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
		y: "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
		pointSize: 32,
	},
}

func beInt(t *testing.T, s string) *big.Int {
	return new(big.Int).SetBytes(hx(t, s))
}

func TestCurveConformance(t *testing.T) {
	for _, kat := range curveKATs {
		t.Run(kat.name, func(t *testing.T) {
			got, err := mynew.CurveByOID(kat.oid)
			if err != nil {
				t.Fatalf("clean-room CurveByOID(%v): %v", kat.oid, err)
			}
			ref, err := refg.CurveByOID(kat.oid) // see note below if unavailable
			if err != nil {
				t.Fatalf("reference CurveByOID(%v): %v", kat.oid, err)
			}

			// 1. Clean-room integers equal the pinned §2.4 constants.
			for _, f := range []struct {
				label string
				want  *big.Int
				gotI  *big.Int
				refI  *big.Int
			}{
				{"p", beInt(t, kat.p), got.P(), ref.P},
				{"a", beInt(t, kat.a), got.A(), ref.A},
				{"b", beInt(t, kat.b), got.B(), ref.B},
				{"q", beInt(t, kat.q), got.Q(), ref.Q},
				{"x", beInt(t, kat.x), got.X(), ref.X},
				{"y", beInt(t, kat.y), got.Y(), ref.Y},
			} {
				if f.gotI.Cmp(f.want) != 0 {
					t.Fatalf("%s: clean-room=%X want pinned=%X", f.label, f.gotI, f.want)
				}
				if f.gotI.Cmp(f.refI) != 0 { // differential: clean-room vs gogost
					t.Fatalf("%s: clean-room=%X reference=%X", f.label, f.gotI, f.refI)
				}
			}

			// 2. PointSize derived from p.BitLen() (§3.2), not the OID.
			if got.PointSize() != kat.pointSize {
				t.Fatalf("PointSize=%d want %d", got.PointSize(), kat.pointSize)
			}

			// 3. Base point on the clean-room curve (§4.1).
			if !mynew.OnCurve(got, got.X(), got.Y()) {
				t.Fatalf("base point off clean-room curve %s", kat.name)
			}
		})
	}
}

// RFC 7091 §A.1 sign/verify round-trip on tc26-256-A (§4.2). Nonce is random,
// so verify the round-trip, not a fixed signature.
func TestSignVerifyConformance(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}
	prvRaw := hx(t, "7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28")
	digest := hx(t, "2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5")

	curve, err := mynew.CurveByOID(oid)
	if err != nil {
		t.Fatalf("CurveByOID: %v", err)
	}
	sig, err := mynew.SignDigestOnCurve(curve, prvRaw, digest, rand.Reader)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pubRaw, err := mynew.PublicKeyRawFromPrivate(curve, prvRaw)
	if err != nil {
		t.Fatalf("PublicKeyRawFromPrivate: %v", err)
	}
	ok, err := mynew.VerifyDigestOnCurve(curve, pubRaw, digest, sig)
	if err != nil || !ok {
		t.Fatalf("Verify on %s: ok=%v err=%v", curve.Name(), ok, err)
	}
}
```

`mynew.CurveByOID` / `SignDigestOnCurve` / `PublicKeyRawFromPrivate` /
`VerifyDigestOnCurve` mirror the actual signatures in
`internal/gost/exports_gost.go:115,133,148` and
`internal/gost/primitives_gost.go:53` — `rand.Reader` (`crypto/rand`) is the
nonce source. `got.P()`/`got.A()`/… stand in for however your clean-room curve
exposes its integers; gogost's reference `Curve` exposes them as exported
`*big.Int` fields `P,A,B,Q,X,Y` (`third_party/gogost/gost3410/curve.go:31-47`).
`refg.CurveByOID` is shown for symmetry; gogost has no such helper, so in
practice dispatch the same OID switch as `CurveByOID`
(`primitives_gost.go:53-77`) to pick the matching `gost3410.CurveId*()`
constructor and read its fields.

### Fuzz harness

For a fixed table the fuzz target randomizes the OID selector and re-asserts
the invariants that must hold for *any* supported curve: clean-room integers
equal the reference, the base point is on-curve, and its order is `q`
(`q·G == ∞`). The corpus is seeded from the ten registered OIDs (here from
the KAT table). The random `[]byte` is normalized to an index into the OID set.

```go
//go:build gost

package yourpkg_test

import (
	"encoding/asn1"
	"math/big"
	"testing"

	mynew "example.com/yourpkg"

	refg "go.stargrave.org/gogost/v7/gost3410"
)

// referenceCurve dispatches the same OID switch as CurveByOID
// (primitives_gost.go:53-77), returning the gogost reference curve.
func referenceCurve(t *testing.T, oid asn1.ObjectIdentifier) *refg.Curve {
	t.Helper()
	switch {
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}):
		return refg.CurveIdGostR34102001CryptoProAParamSet()
	case oid.Equal(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}):
		return refg.CurveIdtc26gost341012256paramSetA()
	// … remaining nine arcs, one per CurveByOID case …
	}
	t.Fatalf("no reference curve for %v", oid)
	return nil
}

// All ten OIDs CurveByOID accepts (primitives_gost.go:55-74,
// x509gost/oids.go:64-100).
var allCurveOIDs = []asn1.ObjectIdentifier{
	{1, 2, 643, 2, 2, 35, 1}, {1, 2, 643, 2, 2, 35, 2}, {1, 2, 643, 2, 2, 35, 3},
	{1, 2, 643, 7, 1, 2, 1, 1, 1}, {1, 2, 643, 7, 1, 2, 1, 1, 2},
	{1, 2, 643, 7, 1, 2, 1, 1, 3}, {1, 2, 643, 7, 1, 2, 1, 1, 4},
	{1, 2, 643, 7, 1, 2, 1, 2, 1}, {1, 2, 643, 7, 1, 2, 1, 2, 2},
	{1, 2, 643, 7, 1, 2, 1, 2, 3},
}

func FuzzCurveConformance(f *testing.F) {
	for i := range allCurveOIDs {
		f.Add(byte(i)) // seed corpus from each OID index
	}
	f.Fuzz(func(t *testing.T, sel byte) {
		oid := allCurveOIDs[int(sel)%len(allCurveOIDs)] // normalize to fixed arg

		got, err := mynew.CurveByOID(oid)
		if err != nil {
			t.Fatalf("clean-room CurveByOID(%v): %v", oid, err)
		}
		ref := referenceCurve(t, oid) // OID switch over gost3410.CurveId*()

		for _, f := range []struct {
			label      string
			gotI, refI *big.Int
		}{
			{"p", got.P(), ref.P}, {"a", got.A(), ref.A}, {"b", got.B(), ref.B},
			{"q", got.Q(), ref.Q}, {"x", got.X(), ref.X}, {"y", got.Y(), ref.Y},
		} {
			if f.gotI.Cmp(f.refI) != 0 {
				t.Fatalf("%s on %s: clean-room=%X reference=%X", f.label, oid, f.gotI, f.refI)
			}
		}

		// Invariants for any curve: base point on-curve and of order q.
		if !mynew.OnCurve(got, got.X(), got.Y()) {
			t.Fatalf("base point off curve for %v", oid)
		}
		if !mynew.ScalarBaseMult(got, got.Q()).IsInfinity() { // q·G == ∞
			t.Fatalf("base point order != q for %v", oid)
		}
	})
}
```

`referenceCurve` is the same OID-switch as `CurveByOID`
(`primitives_gost.go:53-77`) returning the gogost `*gost3410.Curve` for the
arc, so its exported `P,A,B,Q,X,Y` fields are the differential target.
`mynew.ScalarBaseMult`/`IsInfinity` stand in for your clean-room point
arithmetic (`Exp`/`add` in `third_party/gogost/gost3410/curve.go:98-161`); if
you have not built point arithmetic yet, drop the order check and keep the
field-equality + on-curve assertions — both already catch any transcription
error in §2.4.

### Run commands

```sh
go test -tags gost -run TestCurveConformance ./yourpkg/
go test -tags gost -fuzz=FuzzCurveConformance -fuzztime=30s ./yourpkg/
```

`go test` writes to the build cache outside the sandbox allow-list — run these
with `dangerouslyDisableSandbox: true` (see CLAUDE.md, "Running a single test").

---

## 6. References

RFCs (cite section, not just number):
- **RFC 4357** — "Additional Cryptographic Algorithms for GOST 28147-89, GOST
  R 34.11-94, GOST R 34.10-94, and GOST R 34.10-2001."
  §11.2 / §11.4 = CryptoPro 2001 256-bit parameter sets; §10.8 = OID arcs.
  https://github.com/bigbes/gostcrypto/blob/master/gost3410curves/rfc/rfc4357.txt
- **RFC 7836** — "Guidelines on the Cryptographic Algorithms to Accompany the
  Usage of Standards GOST R 34.10-2012 and GOST R 34.11-2012."
  §5.1 (Weierstrass form), §5.2 (twisted Edwards), Appendix A = the 256/512
  TC26 parameter sets. https://github.com/bigbes/gostcrypto/blob/master/gost3410curves/rfc/rfc7836.txt
- **RFC 7091** — GOST R 34.10-2012 algorithm; §A.1/§A.2 hold the sign/verify
  KAT used in §4.2. https://github.com/bigbes/gostcrypto/blob/master/gost3410curves/rfc/rfc7091.txt
- **draft-deremin-rfc4491-bis** — consolidated OID list and the 2012↔2001
  256-bit curve aliasing.
  https://datatracker.ietf.org/doc/draft-deremin-rfc4491-bis/

GOST standards: GOST R 34.10-2001 (curves `1.2.643.2.2.35.x`),
GOST R 34.10-2012 (TC26 curves `1.2.643.7.1.2.1.{1,2}.x`),
GOST R 34.11-2012 (Streebog, the digest these signatures consume).

Key source citations (`file:line`):
- gogost curve type + on-curve check: `third_party/gogost/gost3410/curve.go:31,56,66,82,98`
- gogost parameter tables: `third_party/gogost/gost3410/params.go:21-694`
  (CryptoPro aliases at `:614-631`; 256-A `:118`; 256-B `:173`; 256-C `:222`;
  256-D `:271`; 512-A `:384`; 512-B `:457`; 512-C `:530`)
- gogost LE key (un)marshal: `third_party/gogost/gost3410/public.go:30,65`
- gogost PointSize: `third_party/gogost/gost3410/utils.go:36`
- gogost Edwards maps: `third_party/gogost/gost3410/edwards.go:22,50,73`
- repo OID→curve switch: `internal/gost/primitives_gost.go:53`
- repo opaque wrapper + accessors: `internal/gost/primitives_gost.go:32`,
  `internal/gost/exports_gost.go:125,129`
- repo curve OIDs: `x509gost/oids.go:64-100`
- repo call sites: `x509gost/verify.go:196`,
  `tls/internal/handshake/kex_gost.go:27,62`
- engine ground-truth tables: `tmp/engine/gost_params.c:14-194`;
  struct field order `tmp/engine/gost_lcl.h:32-42`
- divergence log: `TODO.md:9` (S-box row-order note — irrelevant to curves)
</content>
</invoke>
