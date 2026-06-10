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
cost. It is out of scope for this reference module; if Kuznyechik must protect
high-value traffic against a local cache-timing adversary, use a hardware
implementation or a vetted bitsliced one.
