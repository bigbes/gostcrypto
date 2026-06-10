package kdftree_test

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/kdftree"
	"github.com/bigbes/gostcrypto/streebog"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// KAT-1: gost-engine etalon, R=1, 64-byte output.
// kdftree2012-256.md §"KAT-1" (tmp/engine/test_keyexpimp.c:78-97,164-165).
func TestKDFTree256_KAT1_64B(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")
	want := mustHex(t,
		"22B6837845C6BEF65EA71672B265831086D3C76AEBE6DAE91CAD51D83F79D16B"+
			"074C9330599D7F8D712FCA54392F4DDDE93751206B3584C8F43F9E6DC51531F9")

	got := kdftree.KDFTree256(key, label, seed, 1, 64)
	if len(got) != 64 {
		t.Fatalf("len = %d, want 64", len(got))
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("KAT-1 mismatch:\n got  %x\n want %x", got, want)
	}
}

// KAT-1 trace check: the two iterations individually (guide §"Trace of the two
// HMAC iterations"). iter1 = K(1) (first 32B), iter2 = K(2) (next 32B).
func TestKDFTree256_KAT1_PerIteration(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")
	iter1 := mustHex(t, "22B6837845C6BEF65EA71672B265831086D3C76AEBE6DAE91CAD51D83F79D16B")
	iter2 := mustHex(t, "074C9330599D7F8D712FCA54392F4DDDE93751206B3584C8F43F9E6DC51531F9")

	got := kdftree.KDFTree256(key, label, seed, 1, 64)
	if !bytes.Equal(got[:32], iter1) {
		t.Fatalf("iter1 mismatch:\n got  %x\n want %x", got[:32], iter1)
	}

	if !bytes.Equal(got[32:], iter2) {
		t.Fatalf("iter2 mismatch:\n got  %x\n want %x", got[32:], iter2)
	}
}

// KAT-2: same inputs, 32-byte single-block output (L_b = 0x01 0x00).
// Source: RFC 7836 Appendix B, example 9 (rfc7836.txt:1499-1526), which is the
// single-block KDF_GOSTR3411_2012_256 = KDFTree256 with R=1, L=256.
// The HMAC message is: 01|26bdb878|00|af21434145656378|0100
// Expected output: a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9
func TestKDFTree256_KAT2_32B(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")
	// RFC 7836 Appendix B example 9 (rfc7836.txt:1499-1526):
	// KDF_GOSTR3411_2012_256(K_in, label, seed) = HMAC(K, 01|label|00|seed|0100)
	want := mustHex(t, "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")

	got := kdftree.KDFTree256(key, label, seed, 1, 32)
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("KAT-2 mismatch:\n got  %x\n want %x", got, want)
	}

	// Determinism.
	got2 := kdftree.KDFTree256(key, label, seed, 1, 32)
	if !bytes.Equal(got, got2) {
		t.Fatalf("non-deterministic 32B output")
	}

	// The 32B single-block output uses L_b=0x0100, so it must NOT equal the
	// first 32B of the 64B (L_b=0x0200) output. This guards against a bug
	// where L_b is computed per-block instead of from total length.
	got64 := kdftree.KDFTree256(key, label, seed, 1, 64)
	if bytes.Equal(got, got64[:32]) {
		t.Fatalf("32B output equals first 32B of 64B output — L_b not derived from total length")
	}
}

// Length-encoding edge: outLen not a multiple of 32 truncates correctly and L_b
// is derived from the byte length (RFC 7836 §4.4: L = outLen*8, ceil blocks).
//
// Content is pinned via an independent in-test HMAC oracle (KDFT-32): each
// block K(i) is assembled from scratch as hmac(key, [i]_b||label||0x00||seed||[L]_b)
// with [L]_b = encodeMinBE(outLen*8). This is independent of the package's own
// counterBytes and encodeNoLeadingZeros helpers.
func TestKDFTree256_Truncation(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")

	got := kdftree.KDFTree256(key, label, seed, 1, 40) // spans 2 blocks, truncated to 40.
	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}

	// Content check via independent oracle (KDFT-32): manual HMAC with L=320 bits
	// (outLen=40 → L_b = 0x01 0x40, which is 2 bytes with no leading zeros).
	// L_b for 320 bits = 0x140 = two bytes 0x01, 0x40.
	lRepr40 := []byte{0x01, 0x40} // 320 bits big-endian, no leading zeros
	k1 := oracleHMAC(key, []byte{0x01}, label, seed, lRepr40)
	k2 := oracleHMAC(key, []byte{0x02}, label, seed, lRepr40)
	wantOracle := append(k1, k2...)[:40]

	if !bytes.Equal(got, wantOracle) {
		t.Fatalf("Truncation content mismatch (outLen=40):\n got   %x\n oracle %x", got, wantOracle)
	}

	// Sub-32-byte case: outLen=16 → L = 128 bits → L_b = 0x80 (1 byte, single-block strip).
	// This exercises the encodeNoLeadingZeros single-byte branch (delta D2).
	got16 := kdftree.KDFTree256(key, label, seed, 1, 16)
	if len(got16) != 16 {
		t.Fatalf("len(got16) = %d, want 16", len(got16))
	}

	lRepr16 := []byte{0x80} // 128 bits = 0x80 (1 byte; no leading zeros)
	k1_16 := oracleHMAC(key, []byte{0x01}, label, seed, lRepr16)
	wantOracle16 := k1_16[:16]

	if !bytes.Equal(got16, wantOracle16) {
		t.Fatalf("Truncation content mismatch (outLen=16, 1-byte L_b):\n got    %x\n oracle %x", got16, wantOracle16)
	}
}

// TestKDFTree256_LBinding asserts that different total output lengths produce
// different output bytes even for the same inputs and same iteration count —
// [L]_b is part of every iteration's HMAC message (KDFT-32).
// Specifically: KDFTree256(..., 17) must NOT be a prefix of KDFTree256(..., 64).
func TestKDFTree256_LBinding(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")

	got17 := kdftree.KDFTree256(key, label, seed, 1, 17)
	got64 := kdftree.KDFTree256(key, label, seed, 1, 64)

	if bytes.Equal(got17, got64[:17]) {
		t.Fatalf("KDFTree256(..., 17) is a prefix of KDFTree256(..., 64) — [L]_b omitted or ignored")
	}
}

// TestKDFTree256_CounterWidth pins the counter-width parameter r=2..4 by
// cross-checking against an in-test manual HMAC oracle (KDFT-31).
//
// For each r in 2..4, the oracle builds the per-iteration HMAC message by
// hand: [i]_b is the low r bytes of i, big-endian (for i=1: 00..0001 r bytes).
// This is independent of the package's counterBytes helper, so a bug taking
// the HIGH r bytes (the delta D3 mistake) would surface here.
func TestKDFTree256_CounterWidth(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")

	// L=512 bits (outLen=64) → [L]_b = 0x02 0x00 (2 bytes, no leading zeros).
	lRepr64 := []byte{0x02, 0x00}

	for r := 2; r <= 4; r++ {
		r := r
		t.Run(func() string {
			switch r {
			case 2:
				return "r=2"
			case 3:
				return "r=3"
			default:
				return "r=4"
			}
		}(), func(t *testing.T) {
			t.Parallel()

			got := kdftree.KDFTree256(key, label, seed, r, 64)
			if len(got) != 64 {
				t.Fatalf("len = %d, want 64", len(got))
			}

			// Build counter bytes [i]_b: low r bytes of i, big-endian.
			// i=1: 00..0001 (r bytes), i=2: 00..0002 (r bytes).
			counter1 := make([]byte, r)
			counter1[r-1] = 0x01
			counter2 := make([]byte, r)
			counter2[r-1] = 0x02

			k1 := oracleHMAC(key, counter1, label, seed, lRepr64)
			k2 := oracleHMAC(key, counter2, label, seed, lRepr64)
			want := append(k1, k2...)

			if !bytes.Equal(got, want) {
				t.Fatalf("r=%d mismatch:\n got  %x\n want %x", r, got, want)
			}
		})
	}
}

// TestKDFTree256_CounterOverflowPanic pins the boundary of the r-byte counter
// overflow panic (KDFT-32): outLen=8160 (r=1 max) must succeed; 8161 must panic.
func TestKDFTree256_CounterOverflowPanic(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	label := []byte("level1")
	seed := make([]byte, 8)

	// 8160 = 32 * 255: the maximum for r=1 (counter fits in one byte, max value 255).
	got := kdftree.KDFTree256(key, label, seed, 1, 8160)
	if len(got) != 8160 {
		t.Fatalf("outLen=8160: len = %d, want 8160", len(got))
	}

	// 8161 exceeds 32 * 255: must panic.
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for outLen=8161 with r=1")
		}
	}()

	kdftree.KDFTree256(key, label, seed, 1, 8161)
}

// oracleHMAC assembles one iteration's HMAC message as:
// counterBytes || label || 0x00 || seed || lRepr
// and computes HMAC-Streebog256(key, message). This is used as an independent
// oracle in the counter-width and truncation content tests.
func oracleHMAC(key, counterBytes, label, seed, lRepr []byte) []byte {
	h := hmac.New(streebog.New256, key)
	h.Write(counterBytes)
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(seed)
	h.Write(lRepr)

	return h.Sum(nil)
}

func TestKDFTree256_PanicsOnBadArgs(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "00")
	cases := []struct {
		name      string
		r, outLen int
	}{
		{"r=0", 0, 32},
		{"r=5", 5, 32},
		{"outLen=0", 1, 0},
		{"outLen=-1", 1, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Fatalf("expected panic for %s", tc.name)
				}
			}()

			kdftree.KDFTree256(key, nil, nil, tc.r, tc.outLen)
		})
	}
}
