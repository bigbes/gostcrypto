# Plan: assembly / codegen for the constant-time field

Forward-looking design doc (not yet implemented). Companion to
[EXPERIMENT-ct.md](EXPERIMENT-ct.md), which got the constant-time `ScalarMultCT`
to **~194 µs** in pure Go and proved it leak-free (ctgrind). This doc is about
the next lever: making the field multiply fast via assembly, either hand-written
or generated from a language that compiles to asm.

## Where the time goes (so: what to optimize)

Profile of a 256-bit `scalarMult`:

- `mul` (4-limb CIOS Montgomery multiply): **~84%**.
- everything else (add/sub/`condSubP`, point formulas, window select): ~16%.

So the **only** function worth assembling is the Montgomery multiply (plus a
dedicated squaring). Nothing else moves the needle enough to justify per-arch asm
maintenance.

**Key property:** our Montgomery mul is *generic* — the modulus and `n0` are
runtime arguments, not baked-in constants. So **one 4-limb routine + one 8-limb
routine cover every GOST prime** (CryptoPro-A/B/C, tc26-256, tc26-512). No
per-prime code. The price is no fast reduction — but the GOST primes have no
special form (unlike P-256's pseudo-Mersenne), so we never had that anyway. This
is the structural reason we can't reach `nistec`'s ~40 µs; the realistic floor
here is ~70 µs.

## Prerequisite (both approaches): pointer-based in-place field ops

Today the field ops are value-in/value-out (`func (f) mul(a, b fe) fe`). Asm and
generated code want pointers (`func feMul(z, x, y *fe)`) to avoid copying 32/64-
byte arrays across the call boundary (Go won't inline a `.s` function, so each
mul is a CALL). This refactor:

- is required before any asm,
- also speeds the *pure-Go* path (no array copies),
- is validated with **zero behaviour change** by the existing `big.Int`
  differential test (`TestCTField_AddSubMulInv`).

Do this first, in pure Go, and lock it in.

---

## Approach A — hand-written Go assembly (Plan 9)

Go has **no inline assembly**. You write whole functions in Plan 9 syntax in
per-arch `.s` files, with a body-less `//go:noescape` Go stub and a pure-Go
fallback.

### Layout

```
ctfield_generic.go    // build !amd64 || purego — the current flat CIOS (fallback)
ctfield_amd64.go      // //go:noescape stubs + CPUID feature gate
ctfield_amd64.s       // feMul/feSqr via MULX + ADCX/ADOX (BMI2+ADX)
ctfield_arm64.go      // stubs
ctfield_arm64.s       // feMul/feSqr via MUL/UMULH + ADCS
```

### amd64 core

4-limb Montgomery CIOS using **MULX** (flag-free multiply) with **two
independent carry chains** via **ADCX** (carry) and **ADOX** (overflow). The dual
chains are the whole win — ~2× over the single-carry Go CIOS. Modulus and `n0`
loaded from the `*ctField`.

### Zero-dependency feature detection

`x/sys/cpu` is a third-party dep (gostcrypto is zero-dep), so detect ADX/BMI2
with a ~10-line **CPUID** asm helper at init; fall back to the generic path when
absent. (ADX is ~all x86-64 since 2015, but fall back honestly.)

### arm64

`MUL`/`UMULH` + `ADCS` carry chain. This is what speeds Apple-silicon / ARM-server
benchmarks; amd64 asm does nothing for them.

### Pros / cons

- Fast, ships now, one generic routine per limb-count.
- **Unaudited per-arch**; must be re-checked with ctgrind on each arch. amd64
  ctgrind is already wired; **arm64 valgrind is unreliable**, so arm64 CT would
  lean on dudect + manual audit.
- Two `.s` files to maintain, kept honest by the differential test.

---

## Approach B — write the algorithm in a language that compiles to asm

Instead of hand-writing (and hand-auditing) asm, write the field in a language
whose compiler emits asm — and, for the verified options, a machine-checked
proof of correctness *and* constant-time.

### B1. fiat-crypto (recommended of the generated options)

Feed each GOST prime to **fiat-crypto**; it emits field arithmetic that is
**Coq-proven correct and constant-time**. Output is C or asm.

- **Per-prime** generation (≈6 primes) rather than one generic routine — more
  generated code, but it's generated, not hand-written.
- Bridge into pure-Go: fiat emits C → compile with clang → transcribe to Go Plan 9
  asm with **`c2goasm`/`asm2plan9s`** (the Minio approach), or wrap via cgo
  (breaks `CGO_ENABLED=0`).
- This is the principled answer for a clean-room security lib: proofs instead of
  trust.

### B2. Jasmin (+ EasyCrypt)

Write the field/ladder in **Jasmin** (high-level assembly), prove
functional-correctness + constant-time (+ optionally Spectre-v1) in EasyCrypt;
the verified compiler emits asm. This is how `libjade` ships. Strongest
guarantees; largest effort; a new language and proof toolchain. No existing
libjade primitive for GOST's generic primes — written from scratch.

### B3. Plain C → asm → Go (no proofs, just speed)

Write the CIOS in C, `clang -O3 -march=...` to asm, transcribe to Go Plan 9 with
`c2goasm`. Faster to write than Plan 9 by hand, decent codegen, but no
correctness/CT proof and still per-arch.

### The proof boundary (B1/B2 caveat)

The proof covers the generated **asm**. The moment you transcribe it to Go's Plan
9 dialect (`c2goasm`) or wrap it in cgo, you step **outside** the verified chain —
so you must **re-run ctgrind on the final Go-linked binary** to confirm the
bridge preserved the property. Go also can't *consume* the proof, only the asm.
And cgo would break the pure-Go / `CGO_ENABLED=0` contract.

---

## Validation (unchanged, already in place)

Whatever `feMul` resolves to — generic Go, hand asm, or generated — is checked by:

- `TestCTField_AddSubMulInv` (differential vs `big.Int`) — the correctness oracle.
- `FuzzScalarMult_CTvsRef` — CT == reference for any scalar.
- in-process ctgrind (`FuzzScalarMultCTLeak`) — no secret-dependent branch/access.

Add: a `purego`-tagged CI leg so the generic fallback stays covered, and a
per-arch ctgrind run.

## Expected payoff

| step | est. `ScalarMult_CT` |
|---|---|
| today (pure-Go flat CIOS) | ~194 µs |
| + asm `feMul` (amd64 ADX) | ~100 µs |
| + `a = −3` (now worth it: `mul ≫ add`) + dedicated `feSqr` | ~70 µs |
| `nistec` P-256 (for reference; needs fast reduction we can't use) | ~40 µs |

Note: `a = −3` was [rejected as break-even in pure Go](EXPERIMENT-ct.md) precisely
because a 4-limb `mul` is only ~2–3× an add there. Once `mul` is asm-fast, the
balance flips and it should be re-tried.

## Recommendation

1. **Pointer-refactor the field ops** (pure Go, no behaviour change) — do this
   regardless of path.
2. Then choose:
   - **Ship-now:** hand-written amd64 ADX `feMul`/`feSqr` + generic fallback,
     ctgrind-verified; arm64 next.
   - **Principled:** evaluate **fiat-crypto** generated fields (proven CT +
     correct), bridged via `c2goasm`, re-verified with ctgrind.
3. Re-try `a = −3` and dedicated squaring after `mul` is fast.

## Out of scope: Kuznyechik

Asm does **not** help the constant-time cipher — its full-table scan is
memory-bound, not arithmetic-bound. The speed lever there is **bitslicing / SIMD**
(multiple blocks in vector registers, S-box as a Boolean circuit), a separate and
larger effort. Tracked elsewhere.
