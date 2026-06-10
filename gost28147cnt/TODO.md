# TODO — gost28147cnt

- **[RESOLVED — GOST-10]** S-box passed twice with no consistency check.
  `NewCNT` previously accepted both a `*gost28147.Cipher` (S-box baked in)
  and a separate `sbox` argument, creating a silent mismatch trap at the
  1024-byte meshing boundary. Resolved by: adding `SBox()` accessor to
  `*gost28147.Cipher` (L0) and changing `NewCNT` to read the S-box via
  `c.SBox()`, dropping the redundant parameter entirely.
