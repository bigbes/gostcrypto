# EXPERIMENT — SIMD batch encrypt (`Cipher.EncryptBlocks`)

A constant-time, byte-sliced Kuznyechik that encrypts **32 blocks in parallel**
with Go 1.26's experimental SIMD intrinsics (`simd/archsimd`, AVX2). It is the
bulk engine behind `Cipher.EncryptBlocks` and exists to accelerate parallel
modes (CTR-style keystream generation) **without** the cache-timing leak of the
table cipher.

It is **off in every default build**. The implementation
(`simd_amd64.go`) is gated `//go:build goexperiment.simd && amd64`; every other
build compiles the `simd_stub.go` fallback, where `EncryptBlocks` is just
successive `Encrypt` calls. `go.mod` stays at `go 1.24` — the tagged file only
needs to compile when the experiment is on.

## Why bother

For a *parallel* mode the win is real and somewhat counter-intuitive: the
batched **constant-time** SIMD cipher is *faster* than the **non-constant-time**
fused-table scalar cipher.

| path (32-block batch, AMD Ryzen 7 3700X) | ns/block | constant-time |
|---|---:|:---:|
| SIMD `EncryptBlocks` (this) | **~188** | ✅ |
| fused-table `Encrypt` (the hot scalar path) | ~247 | ❌ |
| SWAR constant-time `NewCipherCT` | ~4000 | ✅ |

So `EncryptBlocks` is ~1.3× the table cipher and ~20× the existing CT path,
while leaking nothing. The batching is the whole trick — single-block latency
would be far worse, so this only helps CTR-like callers that can hand over many
blocks at once.

## Design (byte-sliced, data-oblivious)

32 blocks are transposed into 16 *byte-sliced* registers: register `i` holds
byte `i` of all 32 blocks (a `Uint8x32`). The transforms then act on whole
registers with no secret-dependent addressing:

- **S (π)** — a generic 256-entry `VPSHUFB` lookup. `VPSHUFB` indexes 16 entries
  per 128-bit lane, so π is split into 16 sub-tables keyed by the high nibble;
  for each high-nibble value the low nibble is shuffled and the result blended
  into the lanes whose high nibble matches.
- **L** — the GF(2⁸)-linear transform as a 16×16 matrix multiply-accumulate
  (`simdMatM[j][i] = l(eᵢ)[j]`); each multiply by a constant is two `VPSHUFB`
  (low/high-nibble product tables) XORed.

Both are data-oblivious → constant-time **by construction**, not by careful
balancing.

## `archsimd` gotcha (load-bearing)

`archsimd`'s **right shift is not lowered to hardware on Go 1.26**:
`Uint16x16.ShiftAllRight` (and the 32/64-bit widths) runs ~50× slower than a
real `VPSRLW` — it tanked the L layer until replaced. A **left** shift is fine.

The high nibble (`x>>4`) needed for the GF high-nibble index is therefore taken
with **`VPMULHUW`**: `MulHigh(x, 0x1000)` divides each 16-bit lane by 16, landing
both bytes' high nibbles in place (`simdHi4`); a mask clears the rest. `VPSHUFB`,
`And`/`Xor` and the AVX2-emulated `Merge` blend are all fast (~20–25 GB/s).

`GOAMD64` (v1 vs v3) makes no difference — `archsimd` does its own runtime AVX2
dispatch. `go tool objdump` on the 1.26 toolchain can't decode the new SIMD
opcodes, so trust the benchmarks, not the disassembly.

## Correctness

`EncryptBlocks` produces output **identical to successive `Encrypt` calls**,
proven at three levels:

- `TestEncryptBlocks_MatchesEncrypt` (portable, default build) — equals
  per-block `Encrypt` for both `NewCipher`/`NewCipherCT` across block counts that
  straddle the 32-block boundary; also exercises the fallback.
- `TestSimd_KAT` — the RFC 7801 §A.1 vector through the SIMD path.
- `FuzzEncryptBlocks_vs_Table` — random key + input, SIMD ≡ table cipher
  byte-for-byte (the same oracle relationship `NewCipherCT` is held to).

## Constant-time status

FALSIFICATION, not proof — same stance as `EXPERIMENT-ct.md`.
`TestSimdDudect_vsTable` (`-tags dudect`) runs a dudect timing sweep with the
**table cipher as a positive control** (its 64 KB tables exceed L1, so it must be
flagged). Pinned to a core (`taskset -c`): SIMD `|t|≈1`, control `|t|≈2000`. The
test asserts a *ratio* (SIMD far below the control) rather than an absolute
`|t|<4.5`, because each ~µs encrypt on a shared, unpinned runner has a noise
floor of `|t|~4–6` even when constant-time. ctgrind under valgrind (instruction-
level proof) is the natural next step and is left as follow-up.

## Build & test

```sh
# default build excludes all of this (stub fallback):
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test ./kuznyechik/

# experimental SIMD path (amd64 + AVX2):
GOEXPERIMENT=simd CGO_ENABLED=0 go test ./kuznyechik/ -run 'Simd|EncryptBlocks'
GOEXPERIMENT=simd CGO_ENABLED=0 go test ./kuznyechik/ -run x -fuzz FuzzEncryptBlocks_vs_Table -fuzztime 30s
GOEXPERIMENT=simd CGO_ENABLED=0 go test -tags dudect -run TestSimdDudect ./kuznyechik/   # pin: taskset -c N
```

## Status / not done

- Experimental: needs `GOEXPERIMENT=simd`, **amd64 only**, AVX2 at runtime.
- Not wired into `ctracpkm` CTR yet — that streaming loop still calls
  `Encrypt` one block at a time; batching it (respecting ACPKM section
  boundaries) is the follow-up that lets gostls suite `0xC100` use this.
- AVX-512 (64-block batches, wider `Uint8x64`) untested — the dev box is AVX2.
- Decrypt has no SIMD path (CTR needs only encrypt).
