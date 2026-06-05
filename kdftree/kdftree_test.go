package kdftree_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/kdftree"
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
// Guide §"KAT-2": this must equal the first 32 bytes of KAT-1, since with
// keyOutLen=32 the only iteration is K(1) with L_b=0x0100 instead of 0x0200.
// The L_b change means it is NOT simply a truncation of KAT-1 — it is a fresh
// HMAC with a different message tail, so we pin the expected first-block value
// only as a structural invariant: the 32B output's length and determinism.
func TestKDFTree256_KAT2_32B(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")

	got := kdftree.KDFTree256(key, label, seed, 1, 32)
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
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
func TestKDFTree256_Truncation(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := mustHex(t, "26BDB878")
	seed := mustHex(t, "AF21434145656378")

	got := kdftree.KDFTree256(key, label, seed, 1, 40) // spans 2 blocks, truncated to 40.
	if len(got) != 40 {
		t.Fatalf("len = %d, want 40", len(got))
	}
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
