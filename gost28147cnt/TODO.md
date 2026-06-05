# TODO — gost28147cnt

- **S-box passed twice with no consistency check** (`cnt.go` `NewCNT`;
  carried from the clean-room code review). `NewCNT` takes both a
  `*gost28147.Cipher` (S-box already baked in) and a separate `sbox`
  argument, used only to rebuild the cipher at the 1024-byte CryptoPro mesh
  boundary. A mismatched pair silently switches S-box mid-stream after the
  first meshing. Fix: expose the S-box from `*gost28147.Cipher` and drop the
  redundant parameter, or at minimum document the must-match invariant on
  `NewCNT`.
