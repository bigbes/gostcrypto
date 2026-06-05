package keg_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/keg"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// Pinned vector from keg.md §"Complete runnable vector"
// (TC26 256-bit ParamSet A, OID 1.2.643.7.1.2.1.1.1). KEG is pair-symmetric:
// KEG(B_pub, A_priv, ukm) == KEG(A_pub, B_priv, ukm).
const (
	privAHex = "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d"
	pubAHex  = "a53d0c904d0c13835c5ebd3e35414e5182f3a9320f91ccec177b284eb407af2c" +
		"6b819ec462ebf933dabba24fb3c741ebe498faf2b8f4eaa21b091d6ab52cd3c4"
	privBHex = "bf4a0b1fe9eaa93529ec31ebc4eef2d92c198f970d9e3a523105db2156dfc607"
	pubBHex  = "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888" +
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602"
	ukmHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	wantHex = "bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900" +
		"39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b"
)

func TestKEG2012_256_KAT(t *testing.T) {
	t.Parallel()

	want := mustHex(t, wantHex)
	ukm := mustHex(t, ukmHex)

	cases := []struct {
		name      string
		pub, priv string
	}{
		{"privA_pubB", pubBHex, privAHex},
		{"privB_pubA", pubAHex, privBHex}, // symmetric: same expkeys
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pub := mustHex(t, tc.pub)
			priv := mustHex(t, tc.priv)

			got, err := keg.KEG2012_256(nil, pub, priv, ukm)
			if err != nil {
				t.Fatalf("KEG2012_256: %v", err)
			}

			if !bytes.Equal(got[:], want) {
				t.Fatalf("KEG mismatch:\n got %x\nwant %x", got[:], want)
			}

			// Documented output split.
			macKey, cipherKey := got[:32], got[32:]
			if !bytes.Equal(macKey, want[:32]) {
				t.Errorf("MAC key (expkeys[0:32]) wrong:\n got %x\nwant %x", macKey, want[:32])
			}

			if !bytes.Equal(cipherKey, want[32:]) {
				t.Errorf("cipher key (expkeys[32:64]) wrong:\n got %x\nwant %x", cipherKey, want[32:])
			}
		})
	}
}

// TestKEG2012_256_Symmetry asserts the pair-symmetry property directly
// (keg.md §"Conformance" / test_derive.c:338-364).
func TestKEG2012_256_Symmetry(t *testing.T) {
	t.Parallel()

	ukm := mustHex(t, ukmHex)

	ab, err := keg.KEG2012_256(nil, mustHex(t, pubBHex), mustHex(t, privAHex), ukm)
	if err != nil {
		t.Fatalf("KEG A→B: %v", err)
	}

	ba, err := keg.KEG2012_256(nil, mustHex(t, pubAHex), mustHex(t, privBHex), ukm)
	if err != nil {
		t.Fatalf("KEG B→A: %v", err)
	}

	if ab != ba {
		t.Fatalf("KEG not pair-symmetric:\n A→B %x\n B→A %x", ab[:], ba[:])
	}
}

// TestKEG2012_256_UKMAdjust exercises the all-zero UKM special case
// (keg.md §"Step 1": real_ukm = 00…00 01). We can only black-box it via the
// public API; assert it runs and is deterministic, distinct from the non-zero
// path, and still pair-symmetric.
func TestKEG2012_256_ZeroUKM(t *testing.T) {
	t.Parallel()

	zeroUKM := make([]byte, 32) // first 16 bytes zero → real_ukm = 00…00 01.
	pubB := mustHex(t, pubBHex)
	privA := mustHex(t, privAHex)
	pubA := mustHex(t, pubAHex)
	privB := mustHex(t, privBHex)

	ab, err := keg.KEG2012_256(nil, pubB, privA, zeroUKM)
	if err != nil {
		t.Fatalf("KEG zero-UKM A→B: %v", err)
	}

	ba, err := keg.KEG2012_256(nil, pubA, privB, zeroUKM)
	if err != nil {
		t.Fatalf("KEG zero-UKM B→A: %v", err)
	}

	if ab != ba {
		t.Fatalf("zero-UKM KEG not symmetric:\n A→B %x\n B→A %x", ab[:], ba[:])
	}

	// Must differ from the non-zero-UKM result (proves real_ukm changed).
	nonZero, err := keg.KEG2012_256(nil, pubB, privA, mustHex(t, ukmHex))
	if err != nil {
		t.Fatalf("KEG non-zero: %v", err)
	}

	if ab == nonZero {
		t.Fatal("zero-UKM produced same output as non-zero UKM; adjust path suspect")
	}
}

func TestKEG2012_256_ShortUKM(t *testing.T) {
	t.Parallel()

	if _, err := keg.KEG2012_256(nil, mustHex(t, pubBHex), mustHex(t, privAHex), make([]byte, 23)); err == nil {
		t.Fatal("expected error for ukm_source shorter than 24 bytes")
	}
}
