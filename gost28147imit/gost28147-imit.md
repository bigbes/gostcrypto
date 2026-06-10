# GOST 28147-89 IMIT MAC + CryptoPro key meshing

## What this is

The **IMIT** (имитовставка / "imitovstavka", an authentication tag) is the
keyed message-authentication code defined inside GOST 28147-89 and
republished as **RFC 5830 §8**. It is a CBC-MAC built on the GOST 28147-89
block cipher, but with a *16-round* transform per block instead of the
cipher's 32 rounds. On top of the raw RFC 5830 IMIT, deployments that
process more than 1024 bytes under one key (TLS application records, file
MACs) apply **CryptoPro key meshing** (RFC 4357 §2.3.2): every 1024 bytes
of processed full blocks the key is re-derived. TLS truncates the 8-byte
IMIT to **4 bytes** (RFC 9189 §4.2).

*Intended implementer: a Sonnet-class coding agent — every constant, S-box, parameter table, and edge case is inlined so this primitive can be built without consulting gogost or external specs.*

This document specifies the MAC layer **only**. It depends on the GOST
28147-89 block primitive — the key schedule, S-boxes, little-endian
octet↔word packing, the round function `f`, and especially the **16-round
`SeqMAC` schedule** — which are specified in the sibling document
[`gost28147-cipher.md`](../gost28147/gost28147-cipher.md). Do not re-derive the
S-boxes here; §8 of that document has the CryptoPro-A and tc26-Z byte
tables verbatim, and §7 there specifies the 16-round schedule. This
document references them and concentrates on the MAC chaining, finalization,
and key-meshing logic layered on top.

**Standards identity**

- IMIT MAC: **GOST 28147-89** §"выработка имитовставки", republished as
  **RFC 5830 §8** ("Generation of an Imitovstavka (MAC)").
- CryptoPro key meshing: **RFC 4357 §2.3.2** ("Key Meshing Algorithm").
- TLS 4-byte truncation and framing: **RFC 9189 §4.2** (GOST cipher suites
  for TLS 1.2); the older draft-chudov-cryptopro-cptls for 0x0081.
- Block-cipher core it sits on: GOST 28147-89 / RFC 5830 §5–§7,
  see [`gost28147-cipher.md`](../gost28147/gost28147-cipher.md).

**Repo status: clean-room implementation.** This package (`github.com/bigbes/gostcrypto/gost28147imit`) is a BSD-2-Clause, pure-Go, zero-dependency clean-room implementation — no gogost and no GPL anywhere in the module graph. The 16-round per-block transform, the chaining, the finalization order, and the CryptoPro key meshing are all implemented natively in `gost28147imit/imit.go` without consulting gogost source. The module never had a gogost dependency; the Repo-status section above was historical scaffolding from the pre-split monorepo and has been removed.

**Where the module uses it (call sites within this module)**

- `gostcrypto/modes.go` — `GOST28147_IMIT(key, msg)` (one-shot 4-byte tag
  with meshing), and `GOST28147Cipher.SeqMACBlock` (the facade wrapper over
  `gost28147imit.SeqMACBlock`).
- `gostcrypto/exports.go` — `NewGOST28147Cipher` constructs the opaque cipher
  handle used by gostls; `SeqMACBlock` is called on that handle by the TLS
  record driver.

**Where the upstream TLS module uses it (call sites in `../gostls`)**

- `gostls/internal/record/protection_gost.go` — `gostIMIT`: a *streaming* MAC
  whose state persists across records, replicating OpenSSL's EVP digest-sign
  semantics (finalize-on-copy, deferred last block, meshing). Serves TLS suites
  **0x0081** (`GOST2001-GOST89-GOST89`, CryptoPro-A S-box) and **0xFF85**
  (`GOST2012-GOST8912-GOST8912`, tc26-Z S-box).
- Non-zero-IV IMIT for `GOST_KEY_TRANSPORT` key wrap is **not** handled by
  this package; that code is in `gostcrypto/keywrap/keywrap.go` (`imit4`)
  which implements its own 16-round step because it needs the UKM as the
  initial state (guide D8). See `keywrap.go` and guide §D8.

**Parity tests** (correctness gate) live in
`../gostcrypto-compat/parity/gost28147imit/gost28147imit_parity_test.go` —
the `TestDiff_InternalGostOracle` and `FuzzDiff_InternalGostOracle` tests
diff the clean-room `IMIT` against the gogost-backed oracle for all message
lengths including the meshing boundary. Run with:

```sh
( cd ../gostcrypto-compat && go test ./parity/gost28147imit/ )
```

**Dimensions (constants)**

| Quantity              | Value                       | Source |
|-----------------------|-----------------------------|--------|
| Block size            | 8 bytes (64 bit)            | RFC 5830 §6 / `gost28147imit/imit.go:blockSize` |
| Key size              | 32 bytes (256 bit)          | RFC 5830 §6 / `imit.go:keySize` |
| Rounds per MAC block  | 16 (`SeqMAC`)               | RFC 5830 §8; `tmp/engine/gost89.c:657-672` |
| Full IMIT tag         | 1–8 bytes                   | RFC 5830 §8 |
| TLS tag (truncated)   | 4 bytes                     | RFC 9189 §4.2; `imit.go:tlsTagLen` |
| Key-meshing period    | 1024 processed bytes        | `tmp/engine/gost_crypt.c:1519`; RFC 4357 §2.3.2 |
| Meshing constant      | 32 bytes (see §2.3)         | `tmp/engine/gost89.c:240-245`; `imit.go:cryptoProKeyMeshingKey` |


## Specification

### 1. The per-block transform (16-round `SeqMAC`)

IMIT runs the GOST 28147-89 encryption step but **stops after 16 rounds**
(two forward subkey passes `X[0..7]`, no reverse pass), versus the cipher's
32 rounds. The schedule is:

```
SeqMAC = [0,1,2,3,4,5,6,7,  0,1,2,3,4,5,6,7]
```

Engine source: two unrolled 8-round groups in `mac_block`
(`tmp/engine/gost89.c:657-672`) — applies `key[0..7]` then `key[0..7]`
again, 16 rounds total, never the reverse pass. RFC 5830 §8 states the
imitovstavka uses the first 16 cycles of the basic encryption step.

The 16-round transform is **not reachable through any public cipher
encrypt/decrypt API** (those are hardwired to 32 rounds), which is exactly
why this package surfaces it as `SeqMACBlock`
(`gost28147imit/imit.go:SeqMACBlock`) and the facade at
`gostcrypto/exports.go:GOST28147Cipher.SeqMACBlock`. A reimplementer
must implement the 16-round `xcrypt(SeqMAC, n1, n2)` directly over the
round function from [`gost28147-cipher.md`](../gost28147/gost28147-cipher.md) §2–§3.

**Octet ordering inside the MAC block (subtle — differs from the cipher).**
The engine's `mac_block` (`tmp/engine/gost89.c:644-684`) reads the 8-byte
state buffer into `(n1, n2)` little-endian as
`n1 = buf[0..3]`, `n2 = buf[4..7]`, runs 16 rounds, then writes back
`buf[0..3] = n1`, `buf[4..7] = n2` — i.e. **natural** order, no half-swap.
The 32-round cipher, by contrast, writes its output halves *swapped*
(see [`gost28147-cipher.md`](../gost28147/gost28147-cipher.md) §6 / D2). gogost
reproduces this asymmetry through its argument ordering: `mac.go:76` reads
`m.n1, m.n2 = block2nvs(m.prev)` and `mac.go:78` writes
`nvs2block(m.n2, m.n1, m.prev)`, and because gogost's `nvs2block(a, b, ...)`
puts its **first** argument into bytes 4–7 (`cipher.go:91-99`), the net
effect of `nvs2block(n2, n1, ...)` is `buf[0..3]=n1, buf[4..7]=n2` — the
same natural order the engine uses. **A reimplementer who reuses the
cipher's swapped pack/unpack verbatim inside the MAC will produce wrong
tags.** Implement the MAC block as: XOR plaintext into the 8-byte state,
read `(n1=lo, n2=hi)` LE, 16 rounds, write back `(lo=n1, hi=n2)` LE.

### 2. IMIT chaining (CBC-MAC)

RFC 5830 §8: maintain an 8-byte running state `S` (the "buffer"),
initialized to the IV (all zeros for the raw MAC; the UKM for key
transport, RFC 4357). For each 8-byte plaintext block `P`:

```
S ← MACBLOCK( S XOR P )      # MACBLOCK = the 16-round transform of §1
```

The tag is the leading `s` bytes of `S` after the last block (`s ≤ 8`; TLS
uses `s = 4`). Engine: `mac_block` does the `buffer[i] ^= block[i]` XOR then
the 16 rounds in place (`gost89.c:648-650`, `657-684`). gogost: `mac.go:70-82`.

### 2.1 Final / partial-block padding (RFC 5830 §8 + engine `gost_imit_final`)

Three padding rules, all from `tmp/engine/gost_crypt.c:1559-1580`
(`gost_imit_final`) and the one-shot `gost_mac` (`gost89.c:702-722`):

1. **Full blocks** are processed as in §2.
2. **A trailing partial block (1–7 bytes)** is **zero-padded to 8 bytes**
   and processed as one more MAC block (`gost89.c:710-714`;
   `gost_crypt.c:1571-1577`).
3. **The trailing zero-block rule (lengths 1–8 inclusive).** If the whole
   message fits in `count == 0` (no full block processed before the final
   one, i.e. total length ≤ 8 bytes), the engine appends one **all-zero
   8-byte block AFTER** the (zero-padded) data block. The data block is
   processed first; the all-zero block last. `gost_crypt.c:1566-1570`:
   ```c
   if (c->count == 0 && c->bytes_left) {
       unsigned char buffer[8]; memset(buffer, 0, 8);
       gost_imit_update(ctx, buffer, 8);
   }
   ```
   Trace this carefully: when `count == 0` and `bytes_left ∈ [1..8]`, the
   `gost_imit_update(zeros, 8)` call first **flushes the pending data
   partial** (the loop at `gost_crypt.c:1535-1545` fills `partial_block`'s
   tail with zero bytes up to 8 and calls `mac_block_mesh` on the
   zero-padded *data* block), then buffers 8 *zero* bytes back into
   `partial_block`. The subsequent `if (c->bytes_left)` at
   `gost_crypt.c:1571-1577` processes that **all-zero block last**. So the
   order is **data block, THEN zero block** — not the reverse. This fires
   for exactly-8-byte input too: 8 bytes leave `count == 0, bytes_left == 8`,
   so the data block is one full block and the trailing all-zero block is
   still appended.

   The one-shot `gost_mac` (`gost89.c:716-719`) expresses the same thing:
   after the data loop, `if (i == 8) { memset(buf2,0,8); mac_block(buf2); }`
   appends the all-zero block, and `i == 8` holds for a single-full-block
   (8-byte) message too.
   **Net rule: any message of length 1–8 bytes gets one extra TRAILING
   all-zero block, processed after the (zero-padded) data block.** A message
   of length ≥ 9 (at least one full block followed by more) does NOT get the
   trailing zero block.

   > **Repo conformance.** `gost28147imit/imit.go` (`imit()`) and
   > `gostls/internal/record/protection_gost.go` (`gostIMIT`) implement
   > exactly this order — the (zero-padded) data block first, then the
   > trailing all-zero block — so they **match gost-engine for inputs ≤ 8
   > bytes**. Concretely: 5-byte `"12345"` → `77a62d81`; 8-byte `"12345670"`
   > → `ac2b5ad6` (see V3). These values are pinned by
   > `TestIMIT_GuideVectors/V3_*` in `gost28147imit/imit_test.go`.

### 2.2 Worked example of the padding rule

Order is **left to right** — the leftmost block is fed first.

| Message length | Blocks fed to MACBLOCK (in order) |
|----------------|-----------------------------------|
| 0 bytes        | (none — engine returns IV-derived state; not used in TLS) |
| 1–7 bytes      | `P‖0-pad`, then `00000000_00000000`  (data first, trailing zero block, rule 3) |
| 8 bytes        | `P`, then `00000000_00000000`  (one full block, then trailing zero block, rule 3) |
| 9–15 bytes     | `P0` (full), then `P1‖0-pad`  (no trailing zero block) |
| 16 bytes       | `P0`, `P1`  (no trailing zero block) |

The trailing all-zero block fires for total length 1–8 (`count == 0` at
finalization). It does NOT fire once a full block has been processed ahead
of the final one (length ≥ 9).

### 2.3 CryptoPro key meshing (RFC 4357 §2.3.2)

After every **1024 bytes of processed full blocks**, before processing the
next block, re-derive the key. The derivation **ECB-decrypts the 32-byte
meshing constant `C` with the current key**, four 8-byte blocks, and the
result becomes the new key:

```
newKey[0..7]   = GOST_ECB_Decrypt(currentKey, C[0..7])
newKey[8..15]  = GOST_ECB_Decrypt(currentKey, C[8..15])
newKey[16..23] = GOST_ECB_Decrypt(currentKey, C[16..23])
newKey[24..31] = GOST_ECB_Decrypt(currentKey, C[24..31])
currentKey     = newKey
```

`GOST_ECB_Decrypt` here is the **32-round** cipher decrypt (`gost_dec`),
NOT the 16-round MAC step. Engine: `cryptopro_key_meshing`
(`tmp/engine/gost89.c:750-766`) — `gost_dec(ctx, CryptoProKeyMeshingKey,
newkey, 4)` then `gost_key(ctx, newkey)`. For the IMIT/MAC path the IV is
**not** re-encrypted (engine passes `iv = NULL` from `mac_block_mesh`,
`gost_crypt.c:1513-1520`) — the running MAC state buffer is preserved
unchanged across the mesh. This module implements it in
`gost28147imit/imit.go:macCipher.mesh()`, and gostls mirrors the same logic
in `gostls/internal/record/protection_gost.go:meshKey()`.

The 32-byte meshing constant `C` (`gost28147imit/imit.go:cryptoProKeyMeshingKey`;
engine `tmp/engine/gost89.c:240-245`, byte-for-byte identical):

```
69 00 72 22 64 C9 04 23 8D 3A DB 96 46 E9 2A C4
18 FE AC 94 00 ED 07 12 C0 86 DC C2 EF 4C A9 2B
```

Meshing applies to **both** the CryptoPro-A S-box (0x0081) and the tc26-Z
S-box (0xFF85) — `key_meshing=1` in `gost_imit_init` for both
(`gost_crypt.c:1494-1502`). The S-box only changes which cipher the ECB
decrypt uses; the constant and 1024-byte period are the same.

### 2.4 The meshing counter and its wrap

The engine tracks `count` = bytes of *full blocks* processed, advanced by 8
per block, and wrapped modulo 1024 after each block. The mesh fires when
`count == 1024` (checked **before** processing the block):

```
mac_block_mesh(c, data):
    if key_meshing and count == 1024:  cryptopro_key_meshing(ctx, NULL)
    mac_block(ctx, buffer, data)            # XOR + 16 rounds
    count = count % 1024 + 8                 # advance, wraps to 8 not 0
```

Source: `tmp/engine/gost_crypt.c:1510-1524`. **The wrap is `count % 1024 +
8`, not `count = 0`** — so after a mesh at `count==1024`, the counter
becomes `1024 % 1024 + 8 = 8`, and the next mesh is again 1024 bytes
(128 blocks) later. This module mirrors this in `imit.go`'s `process` closure
(`count = count%meshPeriod + blockSize`), and gostls mirrors it in
`protection_gost.go`'s `Write`/`processBlockMesh`.


## RFC ↔ implementation deltas

This is the section a reimplementer must internalize. Every entry cites the
RFC and the source line.

### D1. 16-round `SeqMAC`, not the 32-round cipher (RFC 5830 §8)

IMIT is 16 rounds (engine two-pass `mac_block`, `gost89.c:657-672`); the
cipher is 32 (`SeqEncrypt`). Using the 32-round schedule for the MAC silently
produces a plausible-looking but wrong 8-byte value. The 16-round step is
otherwise unreachable through the public cipher API, hence
`gost28147imit.SeqMACBlock` (this package) and the facade wrapper
`GOST28147Cipher.SeqMACBlock` (`gostcrypto/exports.go`). The key-meshing ECB
*decrypt* in §2.3, by contrast, **does** use the 32-round schedule.

### D2. MAC octet ordering is "natural"; the cipher's is swapped

The cipher writes output halves swapped (`cipher.go:91-99`,
[`gost28147-cipher.md`](../gost28147/gost28147-cipher.md) D2); the MAC block writes
them **natural** (`buf[0..3]=n1`, `buf[4..7]=n2`). gogost achieves this with
`block2nvs(iv)→(n2,n1)` at `mac.go:49`, `block2nvs(prev)→(n1,n2)` at
`mac.go:76`, and `nvs2block(n2,n1,...)` at `mac.go:78`. Engine `mac_block`
makes it explicit (`gost89.c:651-654` read, `676-683` write). Reusing the
cipher's swapped pack/unpack inside the MAC yields wrong tags.

### D3. Finalize-on-copy: `Finalize`/`Sum` must NOT mutate the running MAC

OpenSSL `EVP_DigestSignFinal` copies the MD context
(`EVP_MD_CTX_copy_ex`), finalizes the copy, and frees it — the original is
left writable, holding the state from the last `Update`. With
`TLS1_STREAM_MAC` the persistent context is carried across records, so the
next record's MAC continues from where the previous one left off
(seq-number-free chaining). Source: `crypto/evp/m_sigver.c` (per CLAUDE.md);
engine `gost_imit_final` finalizes from `c->buffer`/`c->bytes_left` without
clearing them.

A correct streaming MAC's `Finalize` must **snapshot** `(prev, buf,
bufLen, count)`, run the zero-prefix + zero-pad logic on the snapshot, and
return the tag, leaving the receiver untouched. gostls implements this in
`gostls/internal/record/protection_gost.go:gostIMIT.Finalize`.

**Corollary — gogost `MAC.Sum` is destructive.** `gost28147.MAC.Sum`
reassigns internal state — violating the `hash.Hash` contract. **Never call
`Sum` on a gogost MAC you intend to `Write` to again.** This is the single
biggest trap when trying to use gogost's MAC for streaming TLS; gostls
drives the MAC block-by-block through `SeqMACBlock` and keeps its own
`prev`/`buf` rather than calling gogost's `Write`/`Sum`. (CLAUDE.md,
"gogost/v7 library gotchas".)

### D4. Deferred last block: `while (bytes > 8)`, strictly greater (engine `gost_imit_update`)

`gost_imit_update` processes full blocks with `while (bytes > 8)` —
**strictly greater than 8**, not `>= 8` — buffering the trailing 1–8 bytes,
*including a full 8-byte block*, into `partial_block`. So `bufLen == 8` is a
**valid intermediate state**: a complete block can sit unprocessed until the
next `Update` or `Final`. Source: `tmp/engine/gost_crypt.c:1547-1554`:

```c
while (bytes > 8) { mac_block_mesh(c, p); p += 8; bytes -= 8; }
if (bytes > 0) memcpy(c->partial_block, p, bytes);
c->bytes_left = bytes;
```

Why it matters: using `>= 8` would process that trailing block one
`Update`-call earlier, shifting the `count` and therefore the **key-meshing
boundary** by one block. On records that cross a 1024-byte boundary this
silently corrupts the tag. gostls replicates the strict `> 8` and the
"defer a full buffered block unless more data follows" rule in
`gostls/internal/record/protection_gost.go:gostIMIT.Write` (note the
explicit `for len(data)-i > gostBlockSize` loop).

The one-shot `gostcrypto.GOST28147_IMIT` (`gostcrypto/modes.go`)
doesn't stream, so it processes all full blocks eagerly and handles the
remainder — but it reproduces the *same observable result* because for a
one-shot call the deferred-block distinction only changes *when*, not
*whether*, each block is processed. The streaming `gostIMIT` is the one
that must honor the `> 8` rule precisely.

### D5. Trailing zero block for short messages, lengths 1–8 (engine `gost_imit_final`)

If `count == 0` (no full block processed ahead of the final one — i.e. the
whole message is ≤ 8 bytes) and a partial remains, the engine appends one
all-zero block **after** the (zero-padded) data block, not before it. The
`gost_imit_final` (`gost_crypt.c:1566-1577`) trace is: the
`gost_imit_update(zeros, 8)` at `:1566-1570` first flushes the pending data
partial (processing the zero-padded *data* block), then the `if
(c->bytes_left)` at `:1571-1577` processes the buffered all-zero block last.
The one-shot `gost_mac` matches with `if (i == 8) { mac_block(zeros) }`
(`gost89.c:716-719`), which also fires for exactly-8-byte input. See §2.1
rule 3 and the §2.2 table.

**`gost28147imit/imit.go` and `gostls/internal/record/protection_gost.go`
implement this engine order** — the (zero-padded) data block first, then the
trailing all-zero block — so they **match gost-engine for every input ≤ 8
bytes** (e.g. 5-byte `"12345"` → `77a62d81`; 8-byte `"12345670"` → `ac2b5ad6`;
V3). These values are pinned by `TestIMIT_GuideVectors/V3_*` in
`gost28147imit/imit_test.go`.

### D6. CryptoPro key meshing every 1024 bytes (RFC 4357 §2.3.2)

gogost's raw `gost28147.MAC` omits meshing entirely; this package adds it
(`gost28147imit/imit.go:macCipher.mesh()`). ECB-**decrypt** the constant `C`
(§2.3) with the current key to get the new key; do NOT re-encrypt the MAC
state (iv=NULL). Counter wraps `count%1024+8` (§2.4). This is the divergence
documented in `TODO.md` — the raw gogost MAC matches the engine up to 1024
bytes and diverges after. Manifests first on large application-data records,
never during the handshake.

### D7. TLS framing and 4-byte truncation are the Protector's job, not the MAC's

The MAC primitive takes a key and an opaque byte string. The TLS MAC input
— `seq_num(8) ‖ type(1) ‖ version(2) ‖ length(2) ‖ plaintext` (RFC 5246
§6.2.3.1 / RFC 9189) — is assembled by the record-layer Protector
(`gostls/internal/record/protection_gost.go`), not by `gost28147imit.IMIT`.
The 8-byte IMIT is then truncated to its leading **4 bytes** (RFC 9189 §4.2;
`gost28147imit/imit.go:tlsTagLen = 4`). A reimplementer should keep the MAC
generic (return up to 8 bytes) and truncate at the call site. Note that
`get_mac` (`tmp/engine/gost89.c:686-696`) takes a *bit* length and masks the
final byte — for byte-aligned sizes like 32 bits this is a plain 4-byte prefix.

### D8. Key-transport IMIT uses a non-zero IV (UKM), and no meshing

In `KeyWrapCryptoPro` (`gostcrypto/keywrap/keywrap.go:imit4`) the IMIT over
the 32-byte session key is computed with **iv = ukm** (8 bytes), not zeros.
The wrapped data is exactly 32 bytes (< 1024) so meshing never fires. This
path is implemented inline in `keywrap.imit4` rather than using
`gost28147imit.IMIT` because it needs the UKM as the initial chaining state
— this package's `IMIT` always uses a zero IV. RFC 4357 §6.3 (CryptoPro KEK
wrap). The `imit()` internal function in this package formerly accepted an
arbitrary IV parameter for this use case; it was removed because keywrap
never called it (it had its own inline implementation), making the parameter
dead code.


## Test vectors

All tags below are 4-byte TLS-truncated IMIT, IV = all zeros. **V1, V2, and
V3 are engine-validated**: cross-checked against gost-engine v3.0.3
`test/02-mac.t`. All are pinned by `gost28147imit/imit_test.go`.

### V1. Engine-sourced, 1024 bytes, no meshing (CryptoPro-A)

```
S-box:       CryptoPro-A (1.2.643.2.2.31.1)
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
                   = 30313233343536373839616263646566 30313233343536373839616263646566
message:           "12345670" repeated 128 times  (exactly 1024 bytes, ASCII)
IMIT-4 tag:        2ee8d13d
full IMIT-8 tag:   2ee8d13dff7f037d
```

Source: `tmp/engine/test/02-mac.t:158-173`. Pinned by
`TestIMIT_GuideVectors/V1_1024B_no_mesh`. 1024 bytes sits exactly at the
meshing boundary but does **not** trigger a mesh (the check is `count ==
1024` *before* a block, and the last block advances `count` to 1024 *after*
finalizing) — so this is the largest input still equal to the meshing-free MAC.

### V2. Engine-sourced, >1024 bytes, meshing exercised (CryptoPro-A)

```
S-box:       CryptoPro-A
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
message:           ("12345670" repeated 8 times, then a "\n" byte) repeated 4096 times
                   = 4096 * 65 = 266240 bytes
IMIT-4 tag:        5efab81f
```

Source: `tmp/engine/test/02-mac.t:181-187`. Pinned by
`TestIMIT_GuideVectors/V2_266240B_mesh`. This input crosses the 1024-byte
boundary 260 times, so an implementation that omits key meshing (D6) or
wraps the counter wrong (D4/§2.4) will NOT produce `5efab81f`.

### V3. Short single- and double-block tags (CryptoPro-A; exercise §2.1)

Key is the V1 key, `"0123456789abcdef0123456789abcdef"` (32B ASCII).
**KAT target = the engine value** (computed with the V5 CLI oracle,
`openssl dgst -engine gost -mac gost-mac -macopt hexkey:…`):

```
msg "12345"             (5 bytes, partial)          -> 77a62d81
msg "12345670"          (8 bytes, one full block)   -> ac2b5ad6
msg "1234567012345670"  (16 bytes, two full blocks) -> 7862d83a
```

The 5-byte and 8-byte rows exercise the engine's *trailing* all-zero block
(§2.1 rule 3, D5); the 16-byte case (two full blocks) does not. Pinned by
`TestIMIT_GuideVectors/V3_*`.

### V4. tc26-Z, 1024 bytes (engine gost-mac-12)

```
S-box:       tc26-Z (id-tc26-gost-28147-param-Z)
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
message:           "12345670" repeated 128 times  (1024 bytes)
IMIT-4 tag:        be4453ec
full IMIT-8 tag:   be4453ec1ec327be
```

Source: `tmp/engine/test/02-mac.t:190-194` (gost-mac-12, testdata.dat).
Pinned by `TestIMIT_TC26Z_1024B_Meshing` in `gost28147imit/imit_test.go`.
This is the primary tc26-Z + meshing coverage point: a regression in
`macCipher.mesh()` that hardcodes CryptoPro-A for the ECB-decrypt step would
only be caught here.

### V5. SeqMACBlock step-1 raw chaining state

```
key  (32B, ASCII): "0123456789abcdef0123456789abcdef"
block:             "12345670"
CryptoPro-A state: 832e9da41b6e6d6b   (guide §checklist step 1)
tc26-Z state:      611451608741d776   (computed 2026-06-10)
```

The state returned by `SeqMACBlock` is the *raw* 16-round chaining state
before finalization. It differs from the finalized IMIT of `"12345670"`
(`ac2b5ad6…`) because finalization for an 8-byte input appends a trailing
all-zero block (§2.1 rule 3). Pinned by `TestSeqMACBlock_GuideStep1KAT`.

### V6. gost-engine CLI oracle (cross-check any new vector)

Per CLAUDE.md, compute the engine's reference IMIT for arbitrary input:

```sh
OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
/opt/homebrew/opt/openssl@3/bin/openssl dgst -engine gost \
  -mac gost-mac -macopt hexkey:<32B-hex> /path/to/input.bin
# tc26-Z: use -mac gost-mac-12 instead
```

Note `-macopt hexkey:` hex-decodes the key; `-macopt key:` takes raw ASCII
bytes (the V1/V2 keys above are ASCII strings, so their hex form is the
ASCII bytes of the digits).


## Re-implementation checklist

Each step is independently testable against a vector above. Steps 1–3
assume the GOST 28147-89 block core from
[`gost28147-cipher.md`](../gost28147/gost28147-cipher.md) (key schedule, S-boxes,
round function `f`, LE pack/unpack) already exists and passes its own V1.

1. **16-round MAC block step `macBlock(state8, block8) -> state8`.** XOR
   `block` into `state`; read `(n1=state[0..3], n2=state[4..7])` LE; run
   `xcrypt(SeqMAC=[0..7,0..7], n1, n2)` (16 rounds, round function from the
   cipher doc); write back `state[0..3]=n1, state[4..7]=n2` LE (**natural
   order, D2**). Test: feed the one block `"12345670"` into `macBlock` with
   a zero IV and read the raw 8-byte state (no finalization, no trailing
   zero block yet) — it must equal `832e9da41b6e6d6b`, prefix `832e9da4`.
   (This is the raw chaining state, NOT the finalized 8-byte IMIT of
   `"12345670"`, which appends a trailing zero block and is `ac2b5ad6…` —
   see V3. The two differ precisely because of the §2.1 rule-3 zero block.)

2. **CBC-MAC chaining (no padding, no meshing yet).** State starts at the
   IV (zeros). For each full 8-byte block, `state = macBlock(state, P)`.
   Test: V3 16-byte case → `7862d83a`. Test: V1 1024-byte case → `2ee8d13d`
   (128 whole blocks, no partials).

3. **Truncation.** Return leading `s` bytes (`s=4` for TLS). Test: V1
   size-8 (`2ee8d13dff7f037d`) vs size-4 (`2ee8d13d`).

4. **Partial-block padding + trailing zero block (§2.1, D5).** If a trailing
   1–7 bytes remain, zero-pad to 8 and process. If `count == 0` at
   finalization (total length ≤ 8), process the (zero-padded) data block
   FIRST, then append one all-zero block. Test against V3 engine values:
   5-byte `"12345"` → `77a62d81`, 8-byte `"12345670"` → `ac2b5ad6` (pinned by
   `TestIMIT_GuideVectors/V3_*`).

5. **Key meshing (§2.3, §2.4, D6).** Add a `count` counter advanced by 8 per
   full block and wrapped `count = count%1024 + 8`. Before processing a
   block, if `count == 1024`, derive `newKey[i*8..] =
   GOST_ECB_Decrypt(currentKey, C[i*8..])` for `i=0..3` with the §2.3
   constant `C`, rebuild the cipher, keep the MAC state buffer unchanged.
   Test: V2 (266240 bytes) → `5efab81f`.

6. **Streaming `Write`/`Finalize` with deferred last block (D4).** Buffer
   trailing 1–8 bytes; only process a buffered full block when more data
   follows (strict `> 8`). `Finalize` snapshots `(state, buf, bufLen,
   count)`, runs steps 4 on the snapshot, returns the tag, and leaves the
   receiver writable (**finalize-on-copy, D3**). Test: `Finalize`, then
   `Write` more, then `Finalize` again — the second tag must equal a
   one-shot MAC over the concatenated input. Test against the live
   Tarantool-EE ping (V4) for the full record-layer integration.

7. **Non-zero IV path for key transport (D8).** This package only exposes a
   zero-IV IMIT. The non-zero-IV case (UKM-seeded key-transport IMIT) is
   handled by `gostcrypto/keywrap/keywrap.go:imit4` — see §D8.

8. **tc26-Z parity.** Repeat steps 1–6 with the tc26-Z S-box (0xFF85);
   meshing constant and period are unchanged (§2.3). Cross-check with V5
   using `-mac gost-mac-12` / the tc26-Z paramset.


## Conformance & fuzz testing

The implementation is proved correct by differential testing against the
gogost-backed oracle. The parity tests live in
`../gostcrypto-compat/parity/gost28147imit/`:

- `TestDiff_InternalGostOracle` — 200 random keys × many lengths (including all
  lengths 1–16 and meshing-crossing sizes up to 12345) — diffs the clean-room
  `IMIT` against `gostcryptocompat.GOST28147_IMIT` (the gogost-backed reference).
- `FuzzDiff_InternalGostOracle` — same comparison under the fuzzer.

Run:

```sh
( cd ../gostcrypto-compat && go test ./parity/gost28147imit/ )
( cd ../gostcrypto-compat && go test -fuzz=FuzzDiff_InternalGostOracle -fuzztime=30s ./parity/gost28147imit/ )
```

The unit tests in this package (`gost28147imit/imit_test.go`,
`gost28147imit/guard_test.go`) pin:

- `TestIMIT_GuideVectors` — V1, V2, V3 vectors (CryptoPro-A, various lengths)
- `TestIMIT_EngineTclVectors` — ported `tmp/engine/tcl_tests/mac.try` vectors
- `TestIMIT_TC26Z_1024B_Meshing` — tc26-Z + meshing (V4)
- `TestSeqMACBlock_GuideStep1KAT` — raw chaining state for one block (V5)
- `TestSeqMACBlock_StreamingMatchesIMIT` — streaming SeqMACBlock driver agrees
  with one-shot IMIT
- `TestSeqMACBlock_RejectsBadKeyLen`, `TestSeqMACBlock_RejectsBadBlockLen` —
  validation panics
- `TestIMIT_RejectsEmpty` — empty-message panic

Run:

```sh
CGO_ENABLED=0 go test ./gost28147imit/
```


## References

**RFCs**

- RFC 5830 — *GOST 28147-89: Encryption, Decryption, and Message
  Authentication Code (MAC) Algorithms.* §8 IMIT generation (16-round MAC),
  §5–§7 the block cipher it builds on.
  https://github.com/bigbes/gostcrypto/blob/master/gost28147imit/rfc/rfc5830.txt
- RFC 4357 — *Additional Cryptographic Algorithms for Use with GOST
  28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94
  Algorithms.* §2.3.2 CryptoPro key meshing; §6.3 CryptoPro KEK wrap (the
  non-zero-IV IMIT use). https://github.com/bigbes/gostcrypto/blob/master/gost28147imit/rfc/rfc4357.txt
- RFC 9189 — *GOST Cipher Suites for TLS 1.2.* §4.2 IMIT-4 MAC truncation
  and the GOST-CNT record MAC. https://github.com/bigbes/gostcrypto/blob/master/gost28147imit/rfc/rfc9189.txt
- RFC 5246 — *TLS 1.2.* §6.2.3.1 the per-record MAC input framing
  (`seq ‖ type ‖ version ‖ length ‖ fragment`) the Protector assembles.

**Standards**

- GOST 28147-89 — Russian Federal Standard, block cipher + IMIT MAC (the
  normative source republished as RFC 5830).

**Sibling document**

- [`gost28147-cipher.md`](../gost28147/gost28147-cipher.md) — the GOST 28147-89 block
  core: key schedule, S-box byte tables (CryptoPro-A §8, tc26-Z §8), round
  function `f`, LE octet↔word packing, 32-round encrypt/decrypt, and the
  16-round `SeqMAC` schedule (§7). The IMIT MAC here depends on all of it.

**Key source citations**

- `gost28147imit/imit.go` — clean-room implementation in this package:
  `cryptoProKeyMeshingKey` constant, `macCipher`, `macBlock`, `mesh`, `imit`,
  `SeqMACBlock`, `IMIT`.
- `gostcrypto/exports.go` — `GOST28147Cipher.SeqMACBlock` facade wrapper.
- `gostcrypto/modes.go` — `GOST28147_IMIT` facade entry point.
- `gostls/internal/record/protection_gost.go` — `gostIMIT` streaming driver:
  `macBlockEncrypt`, `meshKey`, `Write` (deferred last block), `Finalize`
  (finalize-on-copy).
- `gostcrypto/keywrap/keywrap.go:imit4` — non-zero-IV IMIT for key transport.
- `tmp/engine/gost89.c:240-245` — `CryptoProKeyMeshingKey` constant;
  `:644-684` `mac_block` (16-round, natural ordering); `:686-696` `get_mac`
  (bit-length truncation); `:750-766` `cryptopro_key_meshing`.
- `tmp/engine/gost_crypt.c:1510-1524` — `mac_block_mesh` (1024-byte mesh +
  counter wrap); `:1526-1557` `gost_imit_update` (deferred last block,
  strict `> 8`); `:1559-1580` `gost_imit_final` (zero-prefix + zero-pad).
- `tmp/engine/test/02-mac.t` — engine KAT vectors (V1, V2, V4).
- `tmp/engine/tcl_tests/mac.try` — tcl-driven engine vectors.
- `../gostcrypto-compat/parity/gost28147imit/` — parity tests (gogost oracle
  differential + fuzz).
- `TODO.md` — known divergences: key-meshing (resolved), empty-message behavior
  (divergence; see imit.go comment at IMIT/empty check).
- `CLAUDE.md` — "GOST IMIT MAC — EVP streaming semantics" (D3/D4/D6 ground
  truth) and "gogost/v7 library gotchas" (destructive `Sum`).
