# TODO — gost3410sign

- **tmp/engine/test/04-pkey.t:265 — R 34.10-2012-512 sign/verify vector
  unported.** The original "wrapper only exposes 256-bit" blocker is gone:
  512-bit curves exist (`gost3410curves` Tc26 512 A/B/C) and
  `SignDigest`/`VerifyDigest` are curve-agnostic. Only the vector port
  remains.
- 04-pkey.t:45 (key print/parse) closed as won't-port: no signature data in
  the subtest; its only extractable assertion (private→public derivation) is
  covered by `vko.TestKAT_Engine04PkeyDerive`.
