# Experiment: constant-time `ScalarMult` (clean-room)

Branch `exp/ct-scalarmult`. Goal: replace the variable-time `big.Int`
double-and-add (`SECURITY.md`, "option C") with a constant-time implementation,
clean-room and zero-dependency (no `filippo.io/bigmod`).

## Thesis

A side-channel-safe `ScalarMult` needs constant-time arithmetic at every layer:

1. **Field** — fixed-limb Montgomery arithmetic over GF(p). No `math/big` on the
   hot path (its `Mul`/`Mod`/`ModInverse` are operand-dependent). Inversion by
   Fermat `a^(p-2)` (exponent is the *public* prime, so square-and-multiply
   branching on its bits leaks nothing about the secret base).
2. **Point** — complete short-Weierstrass formulas (Renes–Costello–Batina 2016)
   in projective coords, so `add`/`double` need no secret-dependent special-case
   branches for identity / equal points.
3. **Scalar** — Montgomery ladder: one add + one double per bit with a
   constant-time conditional swap, iterating the **full** bit length of the
   group order regardless of the scalar's leading zeros.

## Scope / increments

- [x] **F1** 256-bit Montgomery field (4 limbs), validated vs `big.Int` (random
      differential: add/sub/mul/sqr/inv/round-trip Mont). `ctfield.go`.
- [x] **P1** projective complete add/double (add/dbl-2015-rcb), validated vs the
      existing affine `Add`/`Double` incl. identity / P+(−P) edges. `ctpoint.go`.
- [x] **S1** ladder `ScalarMultCT`, validated **bit-for-bit** vs `ScalarMult`
      over random scalars on all four 256-bit curves. `ctscalar.go`.
- [x] **H1** harness: benchmark + timing-leak demonstration. `ctbench_test.go`.
- [x] **W1** side-by-side wiring: `ctCurve` memoised on `Curve` (`sync.Once`);
      `ScalarMult` (big.Int reference) and `ScalarMultCT` (constant-time) coexist
      as plain methods, caller picks. Wider-than-256-bit falls back to the
      reference path (documented).
- [x] **W2** configurable wiring: `Curve.ConstantTime` flag + `ScalarMultSecret`
      selector; the secret-scalar sites (signing nonce, private key in
      `gost3410sign`/`vko`) route through it. Default off → behaviour unchanged;
      parity gate still green. `TestConstantTime_MatchesReference` pins CT==ref.
- [x] **V2** differential fuzz `FuzzScalarMult_CTvsRef`: `ScalarMultCT` == the
      parity-verified `ScalarMult` for any scalar, across a=−3 and cofactor-4
      curves.
- [x] **F2/P2/S2** 512-bit (8-limb) path — `ctfield8.go` / `ctpoint8.go` /
      `ctscalar8.go`, a parallel of the 4-limb stack (compact loop-based CIOS;
      512-bit is rare so the flat-unroll is reserved for the hot 256-bit path).
      `ScalarMultCT` dispatches by width (≤256 → 4-limb, 257–512 → 8-limb). The
      256-bit fast path is untouched (still ~196 µs). Validated: `ctfield8`
      differential vs `big.Int`; `FuzzScalarMult_CTvsRef` now spans 5 curves
      incl. tc26-512-A/C. Wider-than-512 still falls back to the reference.
- [x] **V3** `ctgrind` instruction-level check (`ctgrind.sh`, `.github/workflows/
      ctgrind.yml`): control fires (1522 errors), **CT path 0 errors**. Fixed the
      `scalarToLimbs` residual with `scalarBytesToLimbs` (fixed-width byte decode,
      no `big.Int` on the secret path); same for the 8-limb path.
- [ ] later: route the signer/VKO secret through the bytes core end-to-end (the
      `mod q` reduction on the secret is still `big.Int`); optional 8-limb
      flat-unroll if 512-bit perf matters.

## Results (Apple M-class, `go test -bench`)

| scalar | `big.Int` ScalarMult | CT ladder |
|---|---|---|
| 2-bit (k=3)    | 2.08 µs | 470 µs |
| ~256-bit (k≈Q) | 778 µs  | 470 µs |
| **leak ratio large/small** | **373×** | **1.00×** |
| full-width throughput (`ns/op`) | 901 µs | **531 µs** |

So the constant-time ladder is not only flat against the scalar, it is **~1.7×
faster** than the `big.Int` double-and-add at full width — fixed-limb Montgomery
+ one final inversion (vs a `math/big` `ModInverse` per step) and zero allocs.

### Perf pass (profile-driven)

Profiling showed `mul` at ~48% and the per-op conditional reduction + add/sub at
~28%. Two profile-targeted changes, each validated against the oracle:

| step | `ScalarMult_CT` ns/op | note |
|---|---|---|
| baseline (ladder)        | ~524 µs | add+double every bit |
| + fixed-window (w=4)     | ~350 µs | 256 doublings + ~78 adds vs 256+256; CT table scan |
| + flattened CIOS `mul`   | ~286 µs | 4-limb accumulator in registers, no array/bounds checks |
| + flattened `add`/`sub`  | ~194 µs | masked conditional reduce in register locals; `add` 25%→3.5% |

Net **524 → 194 µs (~2.7×)**, now **~4.7× faster than `big.Int`**. The profile is
now `mul`/`mulAddCarry` at ~84% cum, and `mulAddCarry` is already `MULQ`/`ADCQ`
via `math/bits` — i.e. **the pure-Go floor for generic Montgomery**.

Remaining levers, honestly bounded:

- **dedicated Montgomery squaring** (3 squarings per doubling): ~5–10%. Modest;
  hand-written squaring is error-prone, gated by the oracle if attempted.
- ~~lazy / incomplete reduction~~ **not viable here**: the GOST 256-bit primes
  are within a few hundred of 2²⁵⁶ (e.g. CryptoPro-A `p = 2²⁵⁶ − 617`), so an
  unreduced `a+b < 2p` overflows 4 limbs. Staying in `[4]uint64` *forces* the
  conditional reduce after every add — the 5-limb alternative costs more in
  `mul` than it saves. So `condSubP` is essentially irreducible for these primes.
- **assembly / curve-specific reduction** → approach `nistec` (~40–50 µs). This
  is the only ~2× lever left, and it is per-arch work; out of scope for the
  experiment. Generic Montgomery in pure Go bottoms out around here.

### Tried and rejected: `a = −3` specialization

CryptoPro-A/B/C have `a ≡ −3` (tc26-256-A does not), which normally lets `a·X`
become `−(X+X+X)`. Implemented and measured: **break-even (~194→191 µs, noise)**,
so reverted. Reason: for a *4-limb* field a Montgomery `mul` is only ~2–3× a
modular `add`, so trading one `mul` for two adds + a negate doesn't win (and the
`add`/`sub` methods aren't always inlined). The `a=−3` trick pays off only when
`mul ≫ add` — i.e. with an asm-optimized `mul` or a larger field. Worth
revisiting *together with* an assembly `mul`, not before.

## Constant-time status (honest)

The timing-ratio test (`373× → 1.00×`) is a **smoke test, not a proof** — it
catches gross bit-length leaks only. It even *missed* the `feFromBig` leak below.

Audited as data-oblivious (by construction): all field ops (fixed `ctLimbs`
loops, branch-free, `bits.Mul64/Add64/Sub64` = single CT instructions on
amd64/arm64); the fixed-window scalar mult (fixed iteration counts, `selectWindow`
scans all 16 entries with a masked select); `inv` (branches on the **public**
exponent `p−2`, never the secret operand — the reason Fermat replaces
`ModInverse`).

Issues found:

- **`feFromBig` scalar decode leaked magnitude** — its loop length is
  `len(k.Bits())`, the secret scalar's word count. FIXED: `scalarMult` now uses
  `scalarToLimbs` (fixed-iteration decode via a 32-byte buffer). **Residual:**
  `big.Int.FillBytes` itself iterates k's words, so a *fully* CT entry point must
  take the scalar as fixed-width bytes (gost3410sign already holds them).
- **`toAffine` branches on `Z == 0`** (identity). Not reachable for a valid
  `k ∈ [1, Q−1]` on a prime-order subgroup, but it is a value-dependent branch;
  documented precondition.

### dudect run (with positive control)

`TestDudect_CTvsBigInt` runs a dudect-style timing test (two fixed scalars, same
bit length, Hamming weight 2 vs ~255) over 40 000 interleaved samples per impl,
max-cropped Welch t. The positive control is the integrity check: the SAME
detector is run against the variable-time `big.Int` `ScalarMult`.

```
dudect max|t|:  big.Int = 764.7   CT = 0.7    (|t| > 4.5 ⇒ leak detected)
```

- `big.Int` → **764.7**: detector correctly flags the known-leaky impl.
- CT fixed-window → **0.7**: no detectable HW-dependent timing, well below 4.5.

What this **does** establish: for the secret-scalar data-dependent-branch leak
class, on this machine, the CT path is not distinguishable while the bad path is.

What it **does NOT** establish: it is falsification, not proof — one leak class,
one machine, mean-timing only; no microarchitectural channels.

### ctgrind run (instruction-level taint, with positive control)

`gost3410curves/ctgrind.sh` (build tag `ctgrind`, cgo, Linux+valgrind only — runs
on a remote Arch box, not darwin/arm64). It poisons the secret scalar's bytes
with `VALGRIND_MAKE_MEM_UNDEFINED`; memcheck then flags any branch/address that
depends on it. The Go runtime trips memcheck, so per mode it runs twice: a
no-poison run captures runtime noise as name-based suppressions, then a poison
run surfaces only poison-induced reports (`asyncpreemptoff=1`, `GOMAXPROCS=1`,
GC off keep the runtime quiet/deterministic). Result:

```
[ref] ERROR SUMMARY: 1522 errors  frames: (*Curve).ScalarMult, math/big.(*Int).Bit
[ct]  ERROR SUMMARY: 0 errors      frames: <none>
```

- **ref (positive control)** flags the variable-time path at `if k.Bit(i)==1` —
  detector proven live.
- **ct** — **zero reports.** The field/window/formula core was already
  branch-free; the one earlier residual was `scalarToLimbs` → `big.Int.FillBytes`
  branching on the scalar's words (memcheck at nat.go). Fixed: the secret now
  decodes through `scalarBytesToLimbs` — a fixed-width big-endian byte decode with
  no value- or length-dependent branch — so no `big.Int` touches the secret on
  the CT path. Result released before serialising.

So at the instruction level, on x86-64, the constant-time path has **no**
secret-dependent branch or memory access. This is wired into CI
(`.github/workflows/ctgrind.yml`).

ctgrind only certifies the *executed* paths, so the check is driven by a **Go
fuzz test, in-process** (`FuzzScalarMultCTLeak`): the constant-time function runs
in the test process — so Go's fuzzer sees its coverage and can mutate toward new
paths — and the fuzz body reads `VALGRIND_COUNT_ERRORS` before/after a poisoned
call. A rise means that input drove a secret-dependent branch/access, so
`t.Fatal` fails it and the fuzzer records the input as a crasher in
`testdata/fuzz/`. Without valgrind the client request returns 0, so the same test
is a harmless no-op (and still gives coverage).

The Go runtime trips memcheck, so a no-poison **calibration** pass
(`CTG_CALIBRATE=1`) captures runtime noise as suppressions; `COUNT_ERRORS` then
counts only poison-induced errors. A variable-time **positive control**
(`TestScalarMultCTLeak_Control`) must still be flagged, run in its own process
(a poisoned control contaminates a shared one via reused memory). `ctgrind.sh`
runs `-test.run` (replay the seed corpus + recorded crashers); active
coverage-guided exploration is `valgrind --trace-children=yes <bin> -test.fuzz`.
Same harness for Kuznyechik (`kuznyechik/ctgrind.sh`, `FuzzKuzCTLeak`). Caveats unchanged: it checks executed paths on
one arch (coverage-bound, not an all-inputs proof; Go can change codegen — hence
CI pinned to the toolchain). A true *proof* still needs formal methods
(Jasmin/ct-verif), i.e. a different implementation.

## Lint status (deferred)

The `add/dbl-2015-rcb` bodies are a dense verbatim formula sequence; `wsl_v5`
wants a blank line between every `t0 = …` / `t1 = …` line, which would shred the
line-for-line correspondence with the published listing (a correctness feature).
Graduating this to a PR needs a `//nolint:wsl_v5,mnd` decision on the formula
functions (and `paralleltest`/`testpackage` exceptions on the in-package tests,
which need unexported access). Not done on the experiment branch.

## Validation principle

The existing `big.Int` `ScalarMult` is **correct** (matches gogost/gost-engine
bit-for-bit per the parity suite). So it is the perfect oracle: every CT layer
is diffed against the `big.Int` equivalent over random inputs. The CT code never
needs its own KATs — equality with the trusted impl is the test.

## Status

F1–H1 complete and green for the 256-bit curves. Constant-time `ScalarMultCT`
matches `ScalarMult` bit-for-bit and closes the documented timing channel; it is
not yet wired into `gost3410sign`/`vko`/`keg` (next increment).
