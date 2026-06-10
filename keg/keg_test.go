package keg_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bigbes/gostcrypto/gost3410curves"
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

// TestKEG2012_256_UKMLen pins the exact-32-byte ukm_source contract (KEG-35):
// the spec (keg.md §Sizes) fixes ukm_source at 32 bytes (= a Streebog-256
// digest), and the downstream KExp15 IV is read from ukm_source[24:24+ivLen],
// so any other length is malformed. Earlier the package accepted any length
// >= 24 and silently ignored extra bytes; now 23..31 and 33 all error.
func TestKEG2012_256_UKMLen(t *testing.T) {
	t.Parallel()

	pub := mustHex(t, pubBHex)
	priv := mustHex(t, privAHex)

	for _, n := range []int{0, 16, 23, 24, 31, 33, 64} {
		if _, err := keg.KEG2012_256(nil, pub, priv, make([]byte, n)); err == nil {
			t.Errorf("ukm_source length %d: expected error, got nil", n)
		}
	}

	// Exactly 32 succeeds.
	if _, err := keg.KEG2012_256(nil, pub, priv, mustHex(t, ukmHex)); err != nil {
		t.Errorf("32-byte ukm_source: unexpected error %v", err)
	}
}

// zeroUKMWantHex is KEG2012_256(privA, pubB, ukm=32×0x00) on TC26 256-bit
// ParamSet A. The all-zero first 16 bytes trigger the real_ukm = 00…00 01
// special case (keg.go:setting realUKM[15]=1, engine ground truth
// tmp/engine/gost_ec_keyx.c:140-142). Pinning the exact output bytes catches a
// byte-position slip (realUKM[0]=1 instead of realUKM[15]=1) that pair-symmetry
// and "differs from non-zero" alone would miss (KEG-36).
//
// Source: the gogost-backed reference gostcryptocompat.KEG2012_256 (the de-facto
// spec this module matches), computed on 2026-06-10 with privAHex/pubBHex and a
// 32-byte zero ukm_source on curve OID 1.2.643.7.1.2.1.1.1.
const zeroUKMWantHex = "1f28179da81185e6019a6bc43568b9d8be3788111c50dff78b2a04259f8ecc73" +
	"ddc39fe3d635dc2ffd7071286d4d074421307548b847dbb88039b94015382a6e"

// TestKEG2012_256_ZeroUKM_KAT pins the zero-UKM special-case output bytes
// (KEG-36), not just its round-trip properties.
func TestKEG2012_256_ZeroUKM_KAT(t *testing.T) {
	t.Parallel()

	want := mustHex(t, zeroUKMWantHex)
	zeroUKM := make([]byte, 32)

	got, err := keg.KEG2012_256(nil, mustHex(t, pubBHex), mustHex(t, privAHex), zeroUKM)
	if err != nil {
		t.Fatalf("KEG2012_256 zero-UKM: %v", err)
	}

	if !bytes.Equal(got[:], want) {
		t.Fatalf("zero-UKM KAT mismatch:\n got %x\nwant %x", got[:], want)
	}
}

// TestKEG2012_256_BadKeys pins keg's pass-through error contract for malformed
// key material (KEG-37): wrong-length / off-curve public key, wrong-length /
// zero private key. Each must return an error (not panic, not output); the
// errors originate in the vko sibling and propagate unchanged.
func TestKEG2012_256_BadKeys(t *testing.T) {
	t.Parallel()

	goodPub := mustHex(t, pubBHex)
	goodPriv := mustHex(t, privAHex)
	ukm := mustHex(t, ukmHex)

	// An off-curve public key: flip one byte of a valid key so the point no
	// longer satisfies the curve equation.
	offCurvePub := append([]byte(nil), goodPub...)
	offCurvePub[0] ^= 0xff

	cases := []struct {
		name string
		pub  []byte
		priv []byte
	}{
		{"short_pub_63", goodPub[:63], goodPriv},
		{"long_pub_65", append(append([]byte(nil), goodPub...), 0x00), goodPriv},
		{"off_curve_pub", offCurvePub, goodPriv},
		{"short_priv_31", goodPub, goodPriv[:31]},
		{"long_priv_33", goodPub, append(append([]byte(nil), goodPriv...), 0x00)},
		{"zero_priv", goodPub, make([]byte, 32)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := keg.KEG2012_256(nil, tc.pub, tc.priv, ukm); err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

// pubRawLE generates the LE(X)‖LE(Y) raw public key for the scalar privLE on the
// given 256-bit curve, mirroring vko's wire format (each coordinate a 32-byte
// little-endian fixed-width buffer). Used to build valid keypairs on a non-TC26-A
// curve in-test so the curve parameter is exercised on its own constants.
func pubRawLE(t *testing.T, c *gost3410curves.Curve, privLE []byte) []byte {
	t.Helper()

	d := new(big.Int).SetBytes(reverseBytes(privLE))
	p := c.ScalarMult(d, c.Base())
	size := c.PointSize()
	out := make([]byte, 2*size)
	copy(out[:size], leFixed(p.X, size))
	copy(out[size:], leFixed(p.Y, size))

	return out
}

// reverseBytes returns a new reversed copy of b (LE↔BE for a fixed-width int).
func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}

	return out
}

// leFixed serializes n as a little-endian fixed-width (size bytes) slice.
func leFixed(n *big.Int, size int) []byte {
	be := make([]byte, size)
	n.FillBytes(be)

	return reverseBytes(be)
}

// TestKEG2012_256_CurveHonored proves the curve parameter is actually used
// (KEG-34): a keypair generated on CryptoPro 256-A (OID 1.2.643.2.2.35.1, a
// non-default 256-bit curve) runs through KEG without the "point not on curve"
// error that the old curve-ignoring code produced, is pair-symmetric, and
// differs from the TC26-256-A result for the same scalars.
func TestKEG2012_256_CurveHonored(t *testing.T) {
	t.Parallel()

	cp, err := gost3410curves.CurveByOID("1.2.643.2.2.35.1")
	if err != nil {
		t.Fatalf("CurveByOID CryptoPro-A: %v", err)
	}

	privA := mustHex(t, privAHex)
	privB := mustHex(t, privBHex)
	pubA := pubRawLE(t, cp, privA)
	pubB := pubRawLE(t, cp, privB)
	ukm := mustHex(t, ukmHex)

	ab, err := keg.KEG2012_256(cp, pubB, privA, ukm)
	if err != nil {
		t.Fatalf("KEG on CryptoPro-A A→B: %v", err)
	}

	ba, err := keg.KEG2012_256(cp, pubA, privB, ukm)
	if err != nil {
		t.Fatalf("KEG on CryptoPro-A B→A: %v", err)
	}

	if ab != ba {
		t.Fatalf("KEG on CryptoPro-A not pair-symmetric:\n A→B %x\n B→A %x", ab[:], ba[:])
	}

	// On TC26-256-A the same private scalars yield a different public point and
	// thus a different shared secret; the result must differ from the CryptoPro
	// derivation, confirming the curve is honored end-to-end.
	tcA, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.1.1")
	if err != nil {
		t.Fatalf("CurveByOID TC26-256-A: %v", err)
	}

	tcPubB := pubRawLE(t, tcA, privB)

	tcAB, err := keg.KEG2012_256(tcA, tcPubB, privA, ukm)
	if err != nil {
		t.Fatalf("KEG on TC26-256-A: %v", err)
	}

	if ab == tcAB {
		t.Fatal("CryptoPro-A and TC26-256-A produced identical output; curve not honored")
	}

	// nil defaults to TC26-256-A: same scalars/pub on tcA must match the nil call.
	nilAB, err := keg.KEG2012_256(nil, tcPubB, privA, ukm)
	if err != nil {
		t.Fatalf("KEG nil-curve: %v", err)
	}

	if nilAB != tcAB {
		t.Fatalf("nil curve != explicit TC26-256-A:\n nil %x\n tc26 %x", nilAB[:], tcAB[:])
	}
}

// TestKEG2012_256_Reject512 pins that a 512-bit curve is rejected with an error
// rather than silently running the wrong (256-bit) algorithm on it (KEG-34).
func TestKEG2012_256_Reject512(t *testing.T) {
	t.Parallel()

	c512, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.2.1") // tc26-512-A.
	if err != nil {
		t.Fatalf("CurveByOID tc26-512-A: %v", err)
	}

	// 64-byte priv / 128-byte pub would be needed for a 512 curve, but the size
	// check fires before VKO — keg must reject the curve up front regardless.
	_, err = keg.KEG2012_256(c512, make([]byte, 128), make([]byte, 64), mustHex(t, ukmHex))
	if err == nil {
		t.Fatal("expected error for 512-bit curve, got nil")
	}
}
