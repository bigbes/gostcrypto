// Package vko_test contains negative-path and VKO-62 (UKM reduction) tests.
package vko_test

import (
	"bytes"
	"math/big"
	"testing"

	crv "github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/vko"
)

// mustDeriveQ derives the LE-encoded public point for dLE on curve c.
func mustDeriveQ(t *testing.T, c *crv.Curve, dLE []byte) []byte {
	t.Helper()

	q, err := vko.DeriveQLE(c, dLE)
	if err != nil {
		t.Fatalf("DeriveQLE: %v", err)
	}

	return q
}

// testCurve256A is the tc26-256-A cofactor-4 curve.
func testCurve256A(t *testing.T) *crv.Curve {
	t.Helper()

	c, err := crv.CurveByOID("1.2.643.7.1.2.1.1.1")
	if err != nil {
		t.Fatalf("CurveByOID 256-A: %v", err)
	}

	return c
}

// testCurve512A is the tc26-512-A cofactor-1 curve.
func testCurve512A(t *testing.T) *crv.Curve {
	t.Helper()

	c, err := crv.CurveByOID("1.2.643.7.1.2.1.2.1")
	if err != nil {
		t.Fatalf("CurveByOID 512-A: %v", err)
	}

	return c
}

// ---------------------------------------------------------------------------
// VKO-64 — negative-path tests for every error return.
// ---------------------------------------------------------------------------

// TestInputValidation_BadPrivLen pins errBadPrivLen for each variant.
func TestInputValidation_BadPrivLen(t *testing.T) {
	t.Parallel()

	c := testCurve256A(t)
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := mustDeriveQ(t, c, priv)
	ukm := bytes.Repeat([]byte{0x01}, 8)

	for _, badLen := range []int{0, 1, 31, 33, 64} {
		badPriv := bytes.Repeat([]byte{0x01}, badLen)
		if _, err := vko.KEK2012256(c, badPriv, pub, ukm); err == nil {
			t.Errorf("badPrivLen=%d: expected error, got nil", badLen)
		}
	}
}

// TestInputValidation_BadPubLen pins errBadPubLen.
func TestInputValidation_BadPubLen(t *testing.T) {
	t.Parallel()

	c := testCurve256A(t)
	priv := bytes.Repeat([]byte{0x11}, 32)
	ukm := bytes.Repeat([]byte{0x01}, 8)

	for _, badLen := range []int{0, 1, 63, 65, 128} {
		badPub := bytes.Repeat([]byte{0x01}, badLen)
		if _, err := vko.KEK2012256(c, priv, badPub, ukm); err == nil {
			t.Errorf("badPubLen=%d: expected error, got nil", badLen)
		}
	}
}

// TestInputValidation_ZeroPrivate pins errZeroPrivate for an all-zero scalar
// and for a scalar that is an exact LE encoding of q (zero after Mod q).
func TestInputValidation_ZeroPrivate(t *testing.T) {
	t.Parallel()

	c := testCurve256A(t)
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := mustDeriveQ(t, c, priv)
	ukm := bytes.Repeat([]byte{0x01}, 8)

	// All-zero scalar.
	zeroPriv := make([]byte, 32)
	if _, err := vko.KEK2012256(c, zeroPriv, pub, ukm); err == nil {
		t.Error("zero scalar: expected error, got nil")
	}

	// LE-encoded q (scalar that is zero mod q after reduction).
	qBytes := c.Q.Bytes() // big-endian
	qLE := make([]byte, 32)
	for i, b := range qBytes {
		qLE[32-1-i] = b
	}

	if _, err := vko.KEK2012256(c, qLE, pub, ukm); err == nil {
		t.Error("private=LE(q): expected error (zero mod q), got nil")
	}
}

// TestInputValidation_ZeroUKM pins errZeroUKM.
func TestInputValidation_ZeroUKM(t *testing.T) {
	t.Parallel()

	c := testCurve256A(t)
	priv := bytes.Repeat([]byte{0x11}, 32)
	pub := mustDeriveQ(t, c, priv)

	// Empty UKM decodes to zero.
	if _, err := vko.KEK2012256(c, priv, pub, []byte{}); err == nil {
		t.Error("empty UKM: expected error, got nil")
	}

	// All-zero UKM is also zero.
	zeroUKM := make([]byte, 8)
	if _, err := vko.KEK2012256(c, priv, pub, zeroUKM); err == nil {
		t.Error("all-zero UKM: expected error, got nil")
	}
}

// TestInputValidation_OffCurvePub pins errPubNotOn for an off-curve public point
// and for the all-zero public key buffer.
func TestInputValidation_OffCurvePub(t *testing.T) {
	t.Parallel()

	c := testCurve256A(t)
	priv := bytes.Repeat([]byte{0x11}, 32)
	ukm := bytes.Repeat([]byte{0x01}, 8)

	// Valid pub, then flip the last byte to make it off-curve.
	goodPub := mustDeriveQ(t, c, priv)
	badPub := make([]byte, len(goodPub))
	copy(badPub, goodPub)
	badPub[len(badPub)-1] ^= 0xff

	if _, err := vko.KEK2012256(c, priv, badPub, ukm); err == nil {
		t.Error("off-curve pub (flipped last byte): expected error, got nil")
	}

	// All-zero 64-byte pub: (0,0) fails y²=x³+ax+b on this curve.
	zeroPub := make([]byte, 64)
	if _, err := vko.KEK2012256(c, priv, zeroPub, ukm); err == nil {
		t.Error("all-zero pub: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// VKO-62 — UKM reduction test: oversized UKM yields the same KEK as UKM mod fullOrder.
// ---------------------------------------------------------------------------

// TestUKMReduction_256A verifies that oversized UKM is reduced mod cofactor·q
// and produces the same KEK as the reduced UKM passed directly.
// This tests both that the reduction is implemented and that it is KEK-preserving.
func TestUKMReduction_256A(t *testing.T) {
	t.Parallel()

	c := testCurve256A(t) // cofactor-4 curve.

	privA := bytes.Repeat([]byte{0x11}, 32)
	privB := bytes.Repeat([]byte{0x22}, 32)
	pubA := mustDeriveQ(t, c, privA)
	pubB := mustDeriveQ(t, c, privB)

	// Compute fullOrder = cofactor * q = 4 * q.
	fullOrder := new(big.Int).Mul(big.NewInt(4), c.Q)

	// Pick a small UKM value that fits in 8 bytes.
	baseUKM := new(big.Int).SetInt64(0x0102030405060708)

	// Compute ukmLarge = baseUKM + fullOrder*3 (still ≡ baseUKM mod fullOrder).
	ukmLarge := new(big.Int).Mul(fullOrder, big.NewInt(3))
	ukmLarge.Add(ukmLarge, baseUKM)

	// Encode both as little-endian byte slices.
	ukmBaseLE := bigToLE(baseUKM, 8)
	ukmLargeLE := bigToLE(ukmLarge, (ukmLarge.BitLen()+7)/8)

	// Reference KEK with the small UKM.
	wantKEK, err := vko.KEK2012256(c, privA, pubB, ukmBaseLE)
	if err != nil {
		t.Fatalf("base UKM KEK: %v", err)
	}

	// KEK with the oversized UKM — should equal the base KEK after reduction.
	gotKEK, err := vko.KEK2012256(c, privA, pubB, ukmLargeLE)
	if err != nil {
		t.Fatalf("large UKM KEK: %v", err)
	}

	if !bytes.Equal(gotKEK, wantKEK) {
		t.Errorf("UKM reduction not KEK-preserving:\n  baseUKM   KEK = %x\n  largeUKM  KEK = %x", wantKEK, gotKEK)
	}

	// Symmetry: same result from Bob's side.
	gotKEKBob, err := vko.KEK2012256(c, privB, pubA, ukmLargeLE)
	if err != nil {
		t.Fatalf("large UKM KEK (Bob): %v", err)
	}

	if !bytes.Equal(gotKEKBob, wantKEK) {
		t.Errorf("UKM reduction broke symmetry: alice=%x bob=%x", gotKEK, gotKEKBob)
	}
}

// TestUKMReduction_512C verifies UKM reduction on a cofactor-4 512-bit curve.
func TestUKMReduction_512C(t *testing.T) {
	t.Parallel()

	c, err := crv.CurveByOID("1.2.643.7.1.2.1.2.3") // tc26-512-C, cofactor 4.
	if err != nil {
		t.Fatalf("CurveByOID 512-C: %v", err)
	}

	privA := bytes.Repeat([]byte{0x33}, 64)
	privB := bytes.Repeat([]byte{0x44}, 64)
	pubB := mustDeriveQ(t, c, privB)

	// fullOrder = 4 * q.
	fullOrder := new(big.Int).Mul(big.NewInt(4), c.Q)

	// Small base UKM.
	baseUKM := new(big.Int).SetInt64(0x0102030405060708)

	// Large UKM ≡ baseUKM mod fullOrder.
	ukmLarge := new(big.Int).Add(baseUKM, fullOrder)
	ukmBaseLE := bigToLE(baseUKM, 8)
	ukmLargeLE := bigToLE(ukmLarge, (ukmLarge.BitLen()+7)/8)

	wantKEK, err := vko.KEK2012256(c, privA, pubB, ukmBaseLE)
	if err != nil {
		t.Fatalf("base KEK: %v", err)
	}

	gotKEK, err := vko.KEK2012256(c, privA, pubB, ukmLargeLE)
	if err != nil {
		t.Fatalf("large UKM KEK: %v", err)
	}

	if !bytes.Equal(gotKEK, wantKEK) {
		t.Errorf("512-C UKM reduction not KEK-preserving:\n  base  KEK = %x\n  large KEK = %x", wantKEK, gotKEK)
	}
}

// TestExistingKATsUnchanged verifies that the 8-byte UKM KATs from the main
// test file still pass with the VKO-62 reduction in place. The reduction is a
// no-op for small UKMs (ukm*cofactor << fullOrder), so all existing vectors
// must be byte-identical.
func TestExistingKATsUnchanged(t *testing.T) {
	t.Parallel()

	// Cofactor-4 vector from cofactor4_test.go — must be unchanged.
	c, err := crv.CurveByOID("1.2.643.7.1.2.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	priv := bytes.Repeat([]byte{0x11}, 32)
	pub, _ := hexDecode(t, "5bdf2b87cb48d375feaed65e3c840548d0c3c497f1dbbba163a6a25077a927b8"+
		"5b99b9f94433e8fe42aaf7190f5ae254695f65b52e111a129f1a65e3a62976ce")
	ukm := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	want, _ := hexDecode(t, "0fb3a1f57deab23f4ac566ae07707169f1f5ec7fea2477625b58b259cf529453")

	got, err := vko.KEK2012256(c, priv, pub, ukm)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("cofactor-4 KAT changed:\n got  %x\n want %x", got, want)
	}
}

// bigToLE encodes n as a little-endian byte slice of exactly size bytes.
func bigToLE(n *big.Int, size int) []byte {
	be := n.Bytes()
	// Pad to size if needed.
	if len(be) < size {
		pad := make([]byte, size-len(be))
		be = append(pad, be...)
	}

	out := make([]byte, len(be))
	for i, b := range be {
		out[len(be)-1-i] = b
	}

	return out
}

// hexDecode is a test helper decoding hex; fails the test on error.
func hexDecode(t *testing.T, s string) ([]byte, error) {
	t.Helper()

	var b []byte
	var err error

	for i := 0; i < len(s); i += 2 {
		var v byte
		for _, c := range s[i : i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= byte(c-'A') + 10
			default:
				t.Fatalf("invalid hex char %q", c)
			}
		}

		b = append(b, v)
	}

	return b, err
}
