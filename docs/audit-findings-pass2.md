# Audit findings — pass 2 (independent re-review, machine-generated)

Generated from the 2026-06-10 second-pass per-algorithm review workflow: 21 independent
reviewers (Fable; one per package, plus the root facade and `internal/alias` as their own
units), each finding then adversarially re-verified by a separate Opus verifier. This is an
**independent second pass**, complementary to `audit-findings.md` (the canonical 82-finding
audit). Its findings do **not** overlap with that file — they were surfaced by a different
reviewer cohort with a deliberately skeptical (refute-by-default) verification gate.

Raised: 12 correctness findings. **Confirmed: 9. Refuted by verifiers: 3** (listed at the end
with full dismissal reasoning — off-limits for remediation). Uncertain: 0.

Headline: **no confirmed finding produces wrong cryptographic output on a real or standard
input.** The primitive math is sound. The confirmed issues are an X.509 path-validation policy
gap (the one MEDIUM), facade contract gaps that erase a subpackage's error signal, a benign
internal nonce-encoding convention mismatch, a hardening gap on caller-supplied curves, and a
doc/test-naming defect. Finding IDs (`R2-…`) are stable; use them in commits and the
remediation plan. The `R2-` prefix and distinct package tags avoid collision with
`audit-findings.md`.

---

## Severity-ordered remediation queue

| ID | Sev | Package | One-line |
|---|---|---|---|
| `R2-X509-01` | **medium** | x509gost | GOST chain path skips RFC 5280 pathLen / critical-extension / name-constraint checks |
| `R2-X509-02` | low | x509gost | `leafSatisfiesKeyUsages` ignores `anyExtendedKeyUsage` asserted by the leaf (false-reject) |
| `R2-X509-03` | low | x509gost | leaf byte-identical to a `GOSTRoots` entry must be self-signed or the whole search aborts |
| `R2-SIGN-01` | low | gost3410sign | facade serializes the nonce LE but `SignDigest` reads it BE — effective nonce is reversed (benign) |
| `R2-FACA-01` | low | facade | `PublicKeyRawFromPrivate` hardcodes `nil` error, returns `(nil, nil)` for a degenerate key |
| `R2-FACA-02` | low | facade | `GenerateEphemeralKey` zero-scalar check runs before `mod q`; `LE(q)` input → all-zero key, diverges from gogost |
| `R2-VKO-01` | low | vko | `cofactor()` clamps any cofactor ≠4 to 1 → wrong KEK on a hand-built h∈{2,8} curve (unreachable via registered curves) |
| `R2-CURVE-01` | low | gost3410curves | clean-room guide still tells implementers to set cofactor 4 for CryptoPro-C / tc26-256-D (impossible; code is correct) |
| `R2-IMIT-01` | low | gost28147imit | `TestIMIT_TC26Z_1024B_Meshing` is named/documented as exercising `mesh()` but never does |

---

## Coverage matrix — KAT and fuzz presence per unit

Every algorithm package ships Known-Answer-Tests against authoritative vectors. The only unit
with no KAT is `internal/alias` (a slice-overlap helper — KAT is N/A). Six units have no fuzz
target despite having natural `[]byte`-in entry points.

| Unit | KAT | Fuzz | Highest-value coverage gap (full list in workflow output) |
|---|:---:|:---:|---|
| streebog | ✓ | ✓ | no in-package HMAC-Streebog (RFC 7836) KAT; `add512` full-512-bit carry-wrap untested |
| kuznyechik | ✓ | **✗** | `gf()` field-multiply has no direct unit test; fused-table vs slow-path equivalence unasserted |
| magma | ✓ | **✗** | over-size `dst/src` buffers and partial overlap untested |
| gost28147 | ✓ | ✓ | only one CryptoPro-A KAT (rest TC26-Z) |
| gost28147cnt | ✓ | ✓ | end-around-carry edge (IV near 0xFFFFFFFF upper LE word) has no targeted KAT |
| gost28147imit | ✓ | ✓ | **no test runs `mesh()` under a non-CryptoPro-A S-box** — see `R2-IMIT-01` |
| gostr341194 | ✓ | ✓ | `Reset()` reuse and `Sum(prefix)` append semantics untested |
| ctracpkm | ✓ | **✗** | full counter-block wraparound and empty-`src` no-op untested |
| omac | ✓ | ✓ | Magma K2 / partial-final-block path; panic paths (bad tagSize) untested |
| mgm | ✓ | ✓ | `Open` in-place aliasing and early-reject branches untested |
| kexp15 | ✓ | ✓ | no vector with `len(S) != 32` (OMAC block-aligned final-block path); no long-input test |
| keywrap | ✓ | ✓ | no engine-pinned CryptoPro-A KAT; exported `Diversify` happy path never called |
| kdftree | ✓ | ✓ | `r≥2` (counter > 255, 3-byte `[L]_b`) paths only checked vs an in-test oracle, not external |
| tlstree | ✓ | **✗** | **RFC 9189 Appendix A.1.1 official vectors not pinned**; intermediate K1/K2 unasserted |
| keg | ✓ | **✗** | zero-UKM vector sourced from gogost reference, not an external standard; error identities unasserted |
| vko | ✓ | ✓ | `KEK2012512` never run on a cofactor-4 curve; `u ≡ 0 mod h·q` error branch unhit |
| gost3410curves | ✓ | ✓ | static k·G KATs only for tc26-256-A / tc26-512-A; group laws only on tc26-256-A |
| gost3410sign | ✓ | ✓ | `r==0` / `s==0` nil paths and `C==∞` rejection untested |
| x509gost | ✓ | ✓ | no externally-signed GOST R 34.10-2001 fixture; `errMixedChain` and max-depth bound untested |
| internal/alias | **✗** | **✗** | helper — KAT N/A; same-start different-length and adjacent-subslice boundary cases untested |
| facade | ✓ | ✓ | `NewGOST28147_CNT` keystream KAT, `NewCTRACPKM` nonzero-section ACPKM KAT, fixed-nonce sign KAT all absent |

**No fuzz target:** `kuznyechik`, `magma`, `ctracpkm`, `tlstree`, `keg`, `internal/alias`.
The first four expose obvious fuzz candidates (block/stream `[]byte`-in APIs, the TLSTREE
derivation). **No KAT:** `internal/alias` only (N/A).

---

## x509gost

**Reviewer summary:** The GOST-leaf verification path is fully self-contained in `verify.go`
and does not delegate to `crypto/x509.Verify` (only the non-GOST branch does). It is correct on
the checks it performs (DN match, validity, IsCA, KeyUsageCertSign, GOST signature) but enforces
a strictly smaller check set than the stdlib path reached through the same `Certificate.Verify`
entry point. Three confirmed gaps below; two further claims (`PubKeyRaw` aliasing, the
`GOSTAlgorithm` iota constants) were refuted.

### [R2-X509-01] GOST chain path skips mandatory RFC 5280 path-validation checks (pathLen, critical extensions, name constraints)

- **Location:** `x509gost/verify.go:207-341`
- **Category:** correctness/policy · **Severity:** medium · **Confidence:** 90

**Finding:** The GOST chain builder enforces exactly five checks (DN match, validity window,
IsCA/BasicConstraintsValid, KeyUsageCertSign, GOST signature) and no more. It never consults
`pathLenConstraint` (`Stdlib.MaxPathLen`), unrecognized critical extensions
(`Stdlib.UnhandledCriticalExtensions`), or name-constraint fields. `ParseCertificate`
(`parse.go:168`) records but does not reject unknown critical extensions — rejection in stdlib
happens only during `Verify`, which the GOST path bypasses. So a GOST leaf gets strictly weaker
validation than a non-GOST leaf through the same API. Concrete consequences: (1) a sub-CA with
`pathLenConstraint=0` can still issue further intermediates (depth bounded only by
`maxGOSTChainDepth=8`); (2) a cert with an unrecognized critical extension verifies, violating
RFC 5280 §4.2's MUST-reject; (3) name constraints on an intermediate are ignored, letting a
domain-constrained CA issue out-of-scope leaves. The package's "permissive-when-unset" posture
(`verify.go:205-206`) only justifies tolerating *absent* extensions, not ignoring *present*
constraint data.

**Verifier confirmation (Opus):** Confirmed. `signerOf` (verify.go:327-341) consults only
`subjectMatchesIssuer`, the validity window, `issuerIsCA`, and `verifyGOSTSignature`;
`issuerIsCA` (verify.go:207-217) checks only `IsCA` and `KeyUsageCertSign`, no `MaxPathLen`. A
grep over `x509gost/*.go` for `MaxPathLen|UnhandledCriticalExtensions|NameConstraints|
PermittedDNS|ExcludedDNS|pathLen` returns zero matches in source (only in the bundled
`rfc/rfc5280.txt`). Ground truth — `$GOROOT/src/crypto/x509/verify.go:444` rejects
`UnhandledCriticalExtensions`; `:500-502` enforce `MaxPathLen`; `checkNameConstraints` handles
name constraints — exactly the checks the GOST path omits. Existing tests
(`verify_paths_test.go`) cover only IsCA/keyCertSign/EKU/validity, so the gap is untested. Not
one of the three logged TODO.md divergences; not a byte-order artifact; the `Verify` doc comment
does not disclose the skip. Severity medium is well-calibrated: exploitation needs a multi-tier
GOST PKI where a trusted root issues constrained intermediates, but within that model it
bypasses RFC 5280 MUST-level checks.

### [R2-X509-02] leafSatisfiesKeyUsages ignores anyExtendedKeyUsage asserted by the leaf

- **Location:** `x509gost/verify.go:189-199`
- **Category:** correctness/interop · **Severity:** low · **Confidence:** 85

**Finding:** The loop only inspects the *requested* side for Any (`want == ExtKeyUsageAny`) and
otherwise tests `slices.Contains(leaf.ExtKeyUsage, want)`. It never checks whether the *leaf's
own* EKU set contains `ExtKeyUsageAny`. Trace for `leaf.ExtKeyUsage=[Any]`,
`requested=[ServerAuth]`: the leaf-empty guard (line 185) is not taken; in the loop
`want=ServerAuth`, `want==Any` is false, `slices.Contains([Any],ServerAuth)` is false → returns
false → `errLeafEKUMismatch`. `crypto/x509` populates `ExtKeyUsage` with `ExtKeyUsageAny` when
the `anyExtendedKeyUsage` OID (2.5.29.37.0) is present, so the path is reachable with a real cert.

**Verifier confirmation (Opus):** Confirmed and reachable. Contradicts stdlib
`checkChainForKeyUsage` (`$GOROOT/src/crypto/x509/verify.go:1003-1008`), which does the
opposite — `for _, usage := range cert.ExtKeyUsage { if usage == ExtKeyUsageAny { continue
NextCert } }` — and RFC 5280 §4.2.1.12 (Any means "any purpose"). The package's own comment
(verify.go:158-160) states the GOST path "must do the same" as stdlib but fails this case.
Impact is **false-rejection only, never false-acceptance**, so no security weakening. Leaves
carrying Any are uncommon. No test covers the leaf-Any case
(`verify_paths_test.go:341 TestVerify_GOST_KeyUsages` uses only specific-EKU leaves). Low
severity correct.

### [R2-X509-03] Leaf found in GOSTRoots must be validly self-signed or verification aborts

- **Location:** `x509gost/verify.go:233-247`
- **Category:** robustness · **Severity:** low · **Confidence:** 80

**Finding:** `buildGOSTChain` first scans `gostRoots` for a byte-identical match of the leaf
(`certEqual`, raw-DER identity). On a match it runs `verifyGOSTSignature(leaf, leaf)` and on
failure does `return nil, err` (line 242) — it does **not** fall through to the recursive chain
search. So pool membership of a byte-identical entry short-circuits the whole search. For a cert
that is not validly self-signed (a cross-signed GOST CA whose signature was made by a different
key), this aborts even when a valid chain `[leaf, R2]` exists via another root R2 that actually
signed it.

**Verifier confirmation (Opus):** Confirmed. `verifyGOSTSignature(leaf, leaf)` verifies the
leaf with its *own* key (`gost.VerifyDigestOnCurve(curve, parent.PubKeyRaw, …)` at verify.go:411
with `parent==leaf`). Diverges from stdlib, which trusts a pool member with **no** signature
check (`crypto/x509/verify.go:596-598`, membership via raw-byte identity
`cert_pool.go:176`), matching RFC 5280's trust-anchor model (anchors trusted by provision, not
by self-signature). **Over-rejection only** — never accepts an invalid chain. Trigger is an
atypical deployment (a non-self-signed CA placed directly in `GOSTRoots` while also being the
leaf). The common self-signed-root case works (`TestVerify_GOST_SelfSigned_Happy`). Low
severity correct.

---

## gost3410sign

### [R2-SIGN-01] Facade serializes the nonce LE but SignDigest reads it BE — effective nonce is the byte-reversal of the draw

- **Location:** `exports.go:183` (facade `signDigestOnCurve`); contract at `gost3410sign/gost3410sign.go:46`
- **Category:** correctness-convention · **Severity:** low · **Confidence:** 90

**Finding:** `signDigestOnCurve` draws `k` uniformly in `[0,q)` via `rand.Int(rnd, q)`, then
serializes it with `big2leFixed` = **little-endian** (exports.go:183). But `gost3410sign.
SignDigest` reads its `k` argument **big-endian** (`kk := new(big.Int).SetBytes(k)`, no
reverse, gost3410sign.go:75) — and its doc contract says so explicitly ("k: the per-signature
nonce, read big-endian"). This BE contract is independently pinned by `TestKAT_SignDeterministic`
(GOST Appendix-A nonce passed in BE hex reproduces the standard r/s). So the integer nonce
actually used by the facade is `reverse(k) mod q`, not `k`.

**Verifier confirmation (Opus):** Real and reproduced (`big2leFixed(0x0102…08,32)` then
`SetBytes` → `0x0807…01` `≠` input). **Benign**, so severity stays low: (a) signatures stay
valid — `SignDigest` uses the same `kk` for both `C=kk·P` and `s=r·d+kk·e`, and `kk==0` is
caught and retried; both test suites green. (b) No RFC 7091 §6.1 violation: the effective nonce
still satisfies `0<k<q`. (c) No exploitable bias — the LE-write/BE-read round-trip is a byte
permutation (bijection) preserving full entropy, then reduced mod q; not an ECDSA-style biased-
nonce condition. The `prv` handling at gost3410sign.go:58 *does* reverse, confirming `k` is
intentionally BE while the facade hands it LE. Not in TODO.md. Fix is trivial (serialize `k`
big-endian, or document the deliberate reversal and fix the misleading `big2leFixed` comment).

---

## facade (exports.go / modes.go / primitives.go)

### [R2-FACA-01] PublicKeyRawFromPrivate returns (nil, nil) for a degenerate private key

- **Location:** `exports.go:164` (also `exports.go:241` `PublicKeyRawFromPrivate2001Test`)
- **Category:** contract · **Severity:** low · **Confidence:** 92

**Finding:** `gost3410sign.PublicKeyRaw` returns `nil` when the LE private key reduces to zero
mod q (gost3410sign.go:200-202) or on `IsInfinity`. Both facade wrappers call it as
`gost3410sign.PublicKeyRaw(...), nil` — hardcoding a `nil` error and erasing the subpackage's
only failure signal. A caller checking `err != nil` is misled into trusting a zero-length
public key.

**Verifier confirmation (Opus):** Confirmed empirically —
`PublicKeyRawFromPrivate(GOST2001TestParamSetCurve(), make([]byte,32))` returns `pub=[] len=0
err=<nil>` (same for the 2001Test variant). Genuine contract gap: the facade signature is
`([]byte, error)` and its doc mentions no nil-on-degenerate convention; GOST R 34.10-2012 §5.2
requires `0 < d < q`. Not a logged divergence. Low severity — a degenerate/zero key never
arises from valid GOST material, and no in-repo caller feeds untrusted key material. Fix:
return a non-nil error when `PublicKeyRaw` yields `nil`.

### [R2-FACA-02] GenerateEphemeralKey zero-scalar check happens before mod-q reduction

- **Location:** `modes.go:291-299`
- **Category:** contract/parity · **Severity:** low · **Confidence:** 80

**Finding:** The zero check (`d.Sign() == 0`) runs on the **pre-reduction** value; `d.Mod(d, q)`
runs after. If the random bytes encode exactly `q` in little-endian (`raw = LE(q)`), then
`d == q != 0` so the check passes, `d.Mod(q,q)` yields 0, and the function returns an all-zero
private key with `pub=nil` and `err=nil` (`PublicKeyRaw` returns nil for the zero key, and
`GenerateEphemeralKey` does not check `pub`).

**Verifier confirmation (Opus):** Reproduced with `raw=LE(q)` on `GOST2001TestParamSetCurve`:
gostcrypto returns `err=nil`, priv = 32 zero bytes, pub len 0. The **gogost-backed compat
facade returns an error** ("gogost/gost3410: zero degree value", `curve.go:145-147`) on the
identical input — so the two backends are **not byte-for-byte equivalent** here. Genuine
contract violation: the doc promises `pubRaw` is `2×PointSize` bytes, and the zero test belongs
*after* `mod q`. Not a logged divergence. Low severity — trigger requires `rnd` to emit exactly
`LE(q)` (≈2⁻²⁵⁶, and `rnd` is crypto/rand in production). `FuzzGenerateEphemeralKey` would catch
it via the `len(pub) != 2*ps` assertion, but its corpus seeds (`0x00…`, `0xFF…`) never equal
`LE(q)`. Fix: keep read/reduce order, add a post-mod zero check (or check `pub==nil`) — preserves
pinned-seed parity.

---

## vko

### [R2-VKO-01] cofactor() silently treats any cofactor other than 4 as 1, producing a wrong KEK on non-registry curves

- **Location:** `vko/vko.go:137-143`
- **Category:** robustness · **Severity:** low · **Confidence:** 65

**Finding:** `cofactor()` returns 4 only when `c.Cofactor==4`, and 1 for every other value (0, 2,
8). `agreementRaw` then computes `u = UKM*cof mod (cof*q)` and `K = u*K1`. The cofactor value
materially changes the agreement point (empirically, on tc26-256-A the raw point with cof=4
differs from cof=1). RFC 7836 §4.3 requires the multiplier `m/q` to be the true cofactor `h`,
and since `gcd(h,q)=1` this is non-trivial — so a hand-built curve with a genuine cofactor of 2
or 8, clamped to 1, yields a silently wrong KEK (wrong output, not an error).

**Verifier confirmation (Opus):** Mechanism confirmed by direct computation (cof=4
`c11c4fdd…` vs cof=1 `2fd326cf…`). Held at **low** by two bounding facts: (1) Unreachable
through `CurveByOID` and every package constructor — all 7 registered GOST curves have
`Cofactor ∈ {1,4}` (curves.go); no standardized GOST/CryptoPro/TC26 paramset has cofactor 2 or
8, so an h=2 GOST curve is hypothetical. It fires only for a caller-supplied curve passed to the
exported `KEK2001`/`KEK2012256`/`KEK2012512`. (2) The reference is no better — gost-engine's
`gost_ec_point_mul` (`gost_ec_sign.c:531`) falls back to plain `EC_POINT_mul` with no cofactor
clearing for unregistered curves; the clean-room is byte-for-byte parity-correct for every curve
that has a reference answer. A real hardening gap (an unsupported-cofactor curve should be
*rejected*, not silently clamped), but no correctness impact for any real GOST curve.

---

## gost3410curves

### [R2-CURVE-01] Stale guide instruction: §3.5 / checklist step 4 demand cofactor 4 for CryptoPro-C / tc26-256-D (mathematically impossible; code is correct)

- **Location:** `gost3410curves/gost3410-curves.md:144` (also `:324-336`, `:430-432`)
- **Category:** doc-drift · **Severity:** low · **Confidence:** 95

**Finding:** The shipped code is correct and the clean-room *guide* is wrong. `curves.go:161-171`
defines CryptoPro-C with `Cofactor: 1` (tc26-256-D aliases it), with a comment explaining that
the stored Q is the full group order so the cofactor is 1, and that cofactor 4 is impossible
(4·Q exceeds the Hasse bound). But the guide at the cited lines instructs implementers to "set
cofactors correctly … 4 for tc26-256-A, tc26-256-D, … CryptoPro-C." A future implementer
"fixing" the code to match the guide would corrupt VKO on those curves (see `R2-VKO-01`:
`vko.go` reads `c.Cofactor`).

**Verifier confirmation (Opus):** Code correct, guide wrong — confirmed by independent
computation: for CryptoPro-C, `q` (256-bit) lies inside the Hasse interval (so `#E = q`,
cofactor 1) while `4q` (258-bit) lies outside it; reconstructed the curve, confirmed G is
on-curve, and computed `q·G = ∞` by full double-and-add (proving `q` is the order of G, `h=1`).
Ground truth agrees: gost-engine v3.0.3 `gost_params.c:52-59` stores cofactor "1" for
`NID_id_GostR3410_2001_CryptoPro_C_ParamSet`; gogost defaults to 1. The regression hazard is
**concrete** (the reviewer's "no path reads Cofactor" was itself inaccurate — `vko.go:137-143`
does). Doc-only defect, low severity. Fix: correct `gost3410-curves.md` lines 144, 324-336,
430-431 to say cofactor 1 for CryptoPro-C / tc26-256-D.

---

## gost28147imit

### [R2-IMIT-01] TestIMIT_TC26Z_1024B_Meshing never executes mesh(); tc26-Z key meshing is asserted-covered but actually untested

- **Location:** `gost28147imit/imit_test.go:230`
- **Category:** test-gap/doc · **Severity:** low · **Confidence:** 95

**Finding:** `mesh()` fires only when `count==1024`, checked *before* a block (imit.go:163-171),
mirroring engine `gost_crypt.c:1518-1520`. A 1024-byte message is 128 blocks, but the loop
defers the trailing 1–8 bytes (`for len(msg)-i > blockSize`, strict `>8`, imit.go:180), so 127
blocks run in the loop and the 128th in finalization; `count` advances 0,8,…,1016, so before the
final block `count==1016 ≠ 1024` and `mesh()` is never invoked for a 1024-byte input. Yet
`TestIMIT_TC26Z_1024B_Meshing` (named `_Meshing`) and its comment claim it is "the only tc26-Z +
meshing coverage point … catches bugs in `mesh()`'s cipher re-keying when the S-box is not
CryptoPro-A", and guide V4 repeats it. Both claims are false: this test never enters `mesh()`,
and no other test exercises `mesh()` under tc26-Z (the only multi-mesh test uses CryptoPro-A; the
other tc26-Z case is 8 bytes).

**Verifier confirmation (Opus):** Factual core confirmed; **not** the logged TODO.md
"CryptoPro key meshing" divergence (that note is about implementing meshing at all vs gogost,
not test coverage). The guide is internally contradictory — V1 states the 1024-byte boundary
correctly ("does not trigger a mesh"), V4 contradicts it. The implementation itself is correct:
`mesh()` (imit.go:129-141) builds the re-keying cipher with `c.sbox` generically, so there is no
actual CryptoPro-A hardcode — a hypothetical hardcode regression would simply go uncaught,
contradicting the stated assurance. Low severity — no incorrect output, a coverage/doc gap. Fix:
pin a >1024-byte tc26-Z vector and correct the test comment + guide V4.

---

## Dismissed (do NOT act on these)

### DISMISSED: [R2-MGM-D1] gfMul is not constant-time (branch on secret-derived accumulator MSB)

- **Location:** `mgm/mgm.go:287-326` · **Category:** side-channel · **Severity claimed:** low

**Original claim:** `gfMul` branches on secret-derived data — `overflow := z[0]&msbMask != 0`
with a conditional field-constant XOR (mgm.go:301-314), where `z` derives from the secret hash
subkey `H_i = E_K(Z_i)` (the sole secret operand; `auth()` at mgm.go:388-389).

**Why dismissed:** Accurate observation, not a bug. (1) No incorrect output and no standard
violation — RFC 9058 Appendix A KATs and the gogost differential parity both pass; the math is
correct. (2) It matches the reference: gogost `mul64.go:49-52` makes the identical secret-MSB
branch (`if mul.x.Bit(Mul64MaxBit) == 1`), built on non-constant-time `math/big`. The clean-room
is no worse (fixed-width). (3) The package documents exactly one constant-time property — the
tag comparison (`mgm-aead.md:248`) — and that *is* implemented constant-time; no CT claim exists
for `gfMul`. (4) Not one of the three logged divergences. A real, low-exploitability micro-arch
observation, but not a defect in correctness, conformance, or any documented guarantee.

### DISMISSED: [R2-X509-D1] PubKeyRaw aliases the caller's DER buffer in the OCTET STRING branch

- **Location:** `x509gost/parse.go:370-386` · **Category:** memory-safety · **Severity claimed:** low

**Original claim:** The OCTET STRING branch returns a slice aliasing `der`, so later mutation of
the DER buffer could corrupt the parsed key.

**Why dismissed:** The central premise — "encoding/asn1 does not copy `[]byte` contents" — is
false for the decode path used here. The branch unmarshals into a plain `[]byte` (`var inner
[]byte; asn1.Unmarshal(bits, &inner)`, parse.go:368-372), which takes the `reflect.Slice`/Uint8
path that **allocates a fresh slice and copies** (`asn1.go:989-994`:
`reflect.MakeSlice(...)`+`reflect.Copy(...)`). Verified empirically: after unmarshal, wiping the
source buffer left `inner` unchanged. The raw-bytes *fallback* branch (which slices a sub-slice
of `der`) defensively copies (`rawCopy`), so both branches return non-aliasing buffers — the
contract is consistent, no corruption hazard. No code change needed.

### DISMISSED: [R2-X509-D2] GOSTAlgorithm constants are 2/3/4, not the 1/2/3 the `iota + 1` idiom intends

- **Location:** `x509gost/parse.go:27-37` · **Category:** maintainability · **Severity claimed:** low

**Original claim:** Because `pubKeyCoords = 2` occupies index 0 of the const block,
`AlgoR341001 = iota + 1` evaluates at index 1 → 2, so the algorithm tags are 2/3/4 not the
intended 1/2/3.

**Why dismissed:** Accurate but not a correctness bug. These are internal Go enum tags, not
on-wire identifiers (the GOST OIDs are the wire identifiers, handled separately and correctly).
Every use is symbolic (switch/case, `String()`, named-constant equality); the zero value still
means "undefined". The two `int(a)` sites are diagnostic-only fall-throughs reached only for
*unrecognized* values, so 2/3/4 is never serialized for valid inputs. `pubKeyCoords=2` is used
correctly at `parse.go:253`. A grep across all four workspace modules found zero cross-module or
numeric consumers. A valid low-value maintainability nit (move `pubKeyCoords` out of the block or
use an explicit `= 1`), not an active defect.

---

*Methodology: 21 Fable reviewers (one per package + facade + internal/alias), each reading every
source file in full against the GOST standard and the colocated `*.md` guides, with the three
logged TODO.md known-divergences and the intentional LE/BE wire-format flip excluded by
construction. Each correctness finding was then re-verified by an independent Opus agent with a
refute-by-default stance, cross-checking `tmp/engine/` ground truth, gogost, and existing KATs.
Confirmed only on demonstrable wrong output or standard violation.*
