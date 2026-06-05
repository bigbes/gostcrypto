# TODO — gost-engine v3.0.3 vector-porting status

Open per-package items live next to the code:

- `gost3410sign/TODO.md` — 512-bit sign/verify vector unported
- `gost28147cnt/TODO.md` — S-box passed twice in `NewCNT`, no consistency check

TLS-layer concerns formerly tracked here moved to `../gostls/TODO.md`.

## Known divergences (gogost vs gost-engine) — check before claiming a bug

- **S-box row order**: gogost stores S-box rows in reverse order and applies a
  compensating `blockReverse` inside `step()`; net cipher output agrees with
  the engine. When extracting S-boxes, read them out of the engine dylib, not
  gogost source.
- **R 34.11-94 empty-input finalization**: the engine's `finish_hash()`
  (tmp/engine/gosthash.c:257-258) runs an extra `hash_step(H, zero_block)`
  when `fin_len == 0`; gogost omits it. Our clean-room `gostr341194` matches
  the engine (`3f25bc1f…`), not gogost (`981e5f3c…`). Non-empty inputs agree
  bit-for-bit. Details: `gostr341194/gostr341194.md` §D1.
- **CryptoPro key meshing in 28147 IMIT**: the engine's `mac_block_mesh`
  (tmp/engine/gost_crypt.c:1510-1524) re-keys every 1024 bytes (RFC 4357
  §2.3.2); gogost's raw `gost28147.MAC` omits it. Our `gost28147imit`
  implements meshing. Details: `gost28147imit/gost28147-imit.md`.

## Skipped — out of scope (not used by Tarantool TLS suites)

- CFB / CBC modes (test/03-encrypt.t:149/197, tcl_tests/enc.try:49/59) — not
  implemented in this module.
- ACPKM master-key MAC vectors (test/02-mac.t:55) and all other ACPKM-section
  tests in test/ and tcl_tests/.
- Engine/provider registration tests (test/00-engine.t, test/00-provider.t) —
  infrastructure only, no KAT.
