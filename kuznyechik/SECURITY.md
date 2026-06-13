# Security: Kuznyechik is not constant-time

`kuznyechik` is a software block cipher that **leaks the key and plaintext
through timing and cache behaviour**. Two sources:

- **Secret-indexed S-box lookups.** The forward/inverse rounds and the
  table-driven `S∘L` / `L⁻¹` paths index the fused lookup tables (and `pi` /
  `piInv`) by secret state bytes. Table access patterns depend on secret data,
  so cache-timing side channels are present. This is identical to the
  table-driven AES implementations shipped everywhere and matches the
  gogost / gost-engine references.
- The slow `gf()` generator (used only at `init()` to build the tables and to
  document the math) additionally branches on a secret bit, but it never runs
  on the hot path with attacker-influenced secrets.

## Why this is accepted here

This matches the GOST software-implementation norm: gogost and gost-engine are
also table-driven and not constant-time. For a reference / interop TLS record
cipher (gostls suite 0xC100, KUZNYECHIK-CTR-OMAC) this is the accepted state and
is documented here per the module convention (see
`../gost3410curves/SECURITY.md`).

The table-driven performance rewrite keeps exactly the same cache-channel
profile as the prior bit-loop implementation: it replaces the per-bit GF
multiply with secret-indexed table lookups, neither adding nor removing a
side channel.

## What a constant-time implementation would need

A bitsliced Kuznyechik (no secret-indexed memory access, no secret-dependent
branches) is the standard remedy, at a substantial throughput and complexity
cost. The fastest production CT path is bitsliced; if Kuznyechik must protect
high-value traffic against a local cache-timing adversary at speed, use a
hardware implementation or a vetted bitsliced one.

## Experimental constant-time path: `NewCipherCT`

`NewCipherCT(key)` returns a cipher whose `Encrypt`/`Decrypt` and key schedule
are constant-time. It splits each round into its nonlinear and linear halves and
removes the secret-dependent address from both:

- **S-box** (the only nonlinear step) — a **SWAR full scan** of `pi`/`piInv`: for
  each *public* table index it tests all 16 secret bytes at once (two `uint64`
  lanes) with a borrow-safe byte-zero compare and ORs in the broadcast table
  value. Every entry is read at a public index, so the access pattern is
  independent of the secret.
- **L / L⁻¹** (linear) — *not a table lookup at all*. Because `L` is
  GF(2)-linear, `L(x)` is the XOR of precomputed per-bit columns selected by
  `x`'s bits with a branch-free `internal/ct.Mask`. Decrypt's `L⁻¹` therefore
  needs no S-box and no scan.

It uses only the 256-byte `pi`/`piInv` and 2 KiB of per-bit `L` columns — never
the 64 KiB fused `encTable`/`lInvTable`. No bitslicing, so it is ~36× slower than
the table path (≈111 ns → ≈4 µs/block) — far better than a naive 256-entry full
scan, suitable when leak-freedom matters more than throughput. A bitsliced core
(see above) would be faster still and remains the production endgame.

Validation: byte-for-byte equal to the table cipher (`FuzzCT_vs_Table`, the
parity-verified oracle); `ctgrind.sh` confirms it instruction-level clean under
valgrind while the table path's secret-indexed loads are flagged (positive
control). Shares the masking primitives with the constant-time EC scalar
multiply via `internal/ct`. See `../gost3410curves/EXPERIMENT-ct.md` for the
methodology.
