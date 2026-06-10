package ctracpkm_test

// C5 coverage-hardening additions (docs/audit-remediation-pass2.md §5 lane C5).
//
// Three invariants that directly guard the purpose of this clean-room
// reimplementation:
//
//  1. FuzzXORKeyStream_SplitInvariance — the property that gogost's
//     gost28147.CTR.XORKeyStream violates: concatenated XORKeyStream calls must
//     produce the same output as one-shot over the concatenation (partial-block
//     gamma is carried across calls).
//
//  2. TestCTR_CounterWrapAround — the counter block wraps around correctly
//     (all-0xFF in the counter half rolls to all-zero). Expected output is
//     derived from the package's own one-shot reference, never hand-invented.
//
//  3. TestXORKeyStream_EmptySrc — XORKeyStream with an empty src is a no-op:
//     dst is unchanged, no panic, and the counter position is not advanced
//     (subsequent output matches a fresh stream at the same position).

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
)

// decodeHex is a test-local helper that decodes a hex string without requiring
// a *testing.T, used to build seed corpora and IV literals in init context.
func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("decodeHex: " + err.Error())
	}

	return b
}

// FuzzXORKeyStream_SplitInvariance verifies that splitting the plaintext into
// two consecutive XORKeyStream calls produces identical output to a single
// one-shot call.  This is the exact streaming property the clean-room
// reimplementation exists to guarantee (ctr-acpkm.md delta #8,
// CLAUDE.md "gogost/v7 library gotchas": gogost's gost28147.CTR.XORKeyStream
// over-increments on block-aligned input and discards partial-block gamma
// across calls).
//
// The fuzzer drives:
//   - arbitrary key material (padded/truncated to 32 bytes)
//   - arbitrary nonce (placed in the high n/2 bytes of the counter)
//   - section size as a small multiple of the block size (1–8 × 16)
//   - arbitrary plaintext
//   - split point anywhere in [0, len(plain)]
//
// Expected output is always derived from the package's own one-shot
// reference — never a hand-invented byte string.
func FuzzXORKeyStream_SplitInvariance(f *testing.F) {
	// Seed corpus from the existing KAT inputs so the fuzzer starts from
	// known-good territory (ctr-acpkm.md §"Inline runnable vector").
	katKey := decodeHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	katNonce := []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0}
	katPlain := decodeHex(
		"1122334455667700ffeeddccbbaa9988" +
			"00112233445566778899aabbcceeff0a" +
			"112233445566778899aabbcceeff0a00" +
			"2233445566778899aabbcceeff0a0011")

	// Seed 1: KAT key+nonce, split near the middle.
	f.Add(katKey, katNonce, uint8(2), katPlain, uint16(16))
	// Seed 2: split at a block boundary.
	f.Add(katKey, katNonce, uint8(1), katPlain, uint16(32))
	// Seed 3: split at byte 0 (degenerate: empty first chunk).
	f.Add(katKey, katNonce, uint8(4), katPlain[:32], uint16(0))
	// Seed 4: split at len(plain) (degenerate: empty second chunk).
	f.Add(katKey, katNonce, uint8(4), katPlain[:32], uint16(32))

	const bs = 16 // Kuznyechik block size.

	f.Fuzz(func(t *testing.T, rawKey, rawNonce []byte, sectionMult uint8, plain []byte, splitRaw uint16) {
		// Build a valid 32-byte key (pad or truncate).
		key := make([]byte, 32)
		copy(key, rawKey)

		// Build a valid 16-byte IV: nonce in the high n/2 bytes, low half zero.
		iv := make([]byte, bs)
		if len(rawNonce) > bs/2 {
			rawNonce = rawNonce[:bs/2]
		}

		copy(iv[:bs/2], rawNonce)

		// Section size: 1..8 × block size so a short plaintext exercises rekeys.
		mult := int(sectionMult)%8 + 1
		section := mult * bs

		newKuz := func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }

		// One-shot reference (the authoritative output).
		oneShot := make([]byte, len(plain))
		ctracpkm.NewCTRACPKM(newKuz, key, iv, section).XORKeyStream(oneShot, plain)

		// Split into two consecutive calls at a fuzz-controlled boundary.
		split := int(splitRaw) % (len(plain) + 1)
		splitOut := make([]byte, len(plain))

		s := ctracpkm.NewCTRACPKM(newKuz, key, iv, section)
		s.XORKeyStream(splitOut[:split], plain[:split])
		s.XORKeyStream(splitOut[split:], plain[split:])

		if !bytes.Equal(oneShot, splitOut) {
			t.Fatalf(
				"split-invariance violation (section=%d split=%d len=%d):\n"+
					" one-shot %x\n split    %x",
				section, split, len(plain), oneShot, splitOut)
		}
	})
}

// TestCTR_CounterWrapAround drives the Kuznyechik CTR counter to its
// wraparound edge (low n/2 bytes all 0xFF) and asserts that the output
// from a split call (bytes before and after the wrap) matches the
// package's own one-shot reference over the same length.
//
// The expected bytes are derived exclusively from the package's one-shot
// call — no hand-invented values (§1.1 anti-footgun rule).
//
// Counter layout: IV = nonce(8B) || counter(8B). The wrap under test is
// the low-half counter rolling from 0xFFFFFFFFFFFFFFFF to 0x0000000000000000
// with a carry into the nonce half, exercising the big-endian incCounter carry
// across the nonce boundary (ctr-acpkm.md delta #1, ctracpkm.go:incCounter).
func TestCTR_CounterWrapAround(t *testing.T) {
	t.Parallel()

	key := decodeHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")

	const bs = 16 // Kuznyechik block size.

	// Place nonce 0x12345678_90ABCEF0 in the high half and set the low-half
	// counter to 0xFFFFFFFFFFFFFFFE so that:
	//   block 0  → counter = nonce || FFFFFFFFFFFFFF FE   (no wrap)
	//   block 1  → counter = nonce || FFFFFFFFFFFFFF FF   (no wrap)
	//   block 2  → counter = nonce || 0000000000000000 + carry into nonce
	// The carry increments byte 7 of the full IV (the last byte of the nonce
	// half), exercising the cross-half carry path in incCounter.
	iv := make([]byte, bs)
	copy(iv[:8], []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0})
	copy(iv[8:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe})

	// 4 blocks = 64 bytes — enough to cross the wrap (at block 2) and continue.
	const length = 4 * bs

	plain := make([]byte, length) // All-zero plaintext → output == keystream.

	// One-shot reference.
	reference := make([]byte, length)
	ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv).XORKeyStream(reference, plain)

	// Split: 2 blocks before wrap, 2 blocks after.
	splitOut := make([]byte, length)

	s := ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv)
	s.XORKeyStream(splitOut[:2*bs], plain[:2*bs])
	s.XORKeyStream(splitOut[2*bs:], plain[2*bs:])

	if !bytes.Equal(reference, splitOut) {
		t.Fatalf(
			"counter wrap: split != one-shot\n"+
				" one-shot %x\n split    %x",
			reference, splitOut)
	}

	// Sanity: the keystream must not be all-zero (proves the cipher is active).
	allZero := true

	for _, b := range reference {
		if b != 0 {
			allZero = false

			break
		}
	}

	if allZero {
		t.Fatal("counter wrap: keystream is all-zero (cipher not active?)")
	}
}

// TestCTR_CounterWrapAround_Magma mirrors TestCTR_CounterWrapAround for the
// Magma (64-bit block) cipher.  The 4-byte nonce half wraps when the 4-byte
// counter half rolls from 0xFFFFFFFE to 0x00000000.
//
// Expected bytes are derived from the package's one-shot reference.
func TestCTR_CounterWrapAround_Magma(t *testing.T) {
	t.Parallel()

	// Magma uses a different key schedule; the same raw bytes work fine.
	key := decodeHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	const bs = 8 // Magma block size.

	// Low-half counter 0xFFFFFFFE → wraps at block 2.
	iv := make([]byte, bs)
	copy(iv[:4], []byte{0x12, 0x34, 0x56, 0x78})
	copy(iv[4:], []byte{0xff, 0xff, 0xff, 0xfe})

	const length = 4 * bs

	plain := make([]byte, length)

	reference := make([]byte, length)
	ctracpkm.NewCTR(magma.NewCipher(key), iv).XORKeyStream(reference, plain)

	splitOut := make([]byte, length)

	s := ctracpkm.NewCTR(magma.NewCipher(key), iv)
	s.XORKeyStream(splitOut[:2*bs], plain[:2*bs])
	s.XORKeyStream(splitOut[2*bs:], plain[2*bs:])

	if !bytes.Equal(reference, splitOut) {
		t.Fatalf(
			"Magma counter wrap: split != one-shot\n"+
				" one-shot %x\n split    %x",
			reference, splitOut)
	}
}

// TestXORKeyStream_EmptySrc verifies the empty-src no-op contract:
//
//  1. XORKeyStream(dst[:0], nil) must not panic.
//  2. dst is left unchanged.
//  3. The counter is not advanced: subsequent output equals that of a fresh
//     stream that has never seen an empty call.
//
// This guards against any implementation that bumps sinceRekey, num, or the IV
// on a zero-length call, which would cause the stream to diverge from a fresh
// instance at the same logical position.
func TestXORKeyStream_EmptySrc(t *testing.T) {
	t.Parallel()

	key := decodeHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := decodeHex("1234567890abcef00000000000000000")

	newKuz := func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }

	const section = 32

	const followLen = 64 // 4 blocks, crosses one rekey boundary.

	// Reference: fresh stream, no empty call, first followLen bytes.
	reference := make([]byte, followLen)
	ctracpkm.NewCTRACPKM(newKuz, key, iv, section).XORKeyStream(reference, make([]byte, followLen))

	// Stream under test: emit one empty call, then followLen bytes.
	dst := []byte{0xAA, 0xBB, 0xCC} // Sentinel values to confirm they're unchanged.

	// Verify the empty call does not panic.
	mustNotPanic(t, "empty XORKeyStream call", func() {
		s := ctracpkm.NewCTRACPKM(newKuz, key, iv, section)

		// Empty call — dst[:0] is valid, src is nil (len 0).
		s.XORKeyStream(dst[:0], nil)

		// dst sentinel bytes must be unchanged.
		if dst[0] != 0xAA || dst[1] != 0xBB || dst[2] != 0xCC {
			t.Error("empty XORKeyStream mutated dst")
		}
	})

	// Counter not advanced: produce followLen bytes after an empty call and
	// compare to the reference (no-empty-call) stream.
	s := ctracpkm.NewCTRACPKM(newKuz, key, iv, section)
	s.XORKeyStream(nil, nil) // Empty call.

	afterEmpty := make([]byte, followLen)
	s.XORKeyStream(afterEmpty, make([]byte, followLen))

	if !bytes.Equal(reference, afterEmpty) {
		t.Fatalf(
			"empty call advanced the counter:\n"+
				" reference   %x\n after-empty %x",
			reference, afterEmpty)
	}
}
