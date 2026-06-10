package kuznyechik //nolint:testpackage // white-box: accesses unexported gf, slEncrypt, lInvFast, s, sInv, l, lInv.

import (
	"bytes"
	"testing"
)

// TestGF_ChecklistVector pins the GF(2^8) multiply against the guide's step-1
// checklist vector. The expected result is taken directly from:
//
//	kuznyechik/kuznyechik-gost34122015.md:413
//
// which states "gf(0x02, 0x80) = 0xC3 (i.e. 2*128 = x^8 mod p(x))".
// Mechanically: 0x80 has bit-7 set, so one left-shift of 0x02 overflows bit 7
// (0x02<<1 = 0x04 — wait, a=0x02, b=0x80). Walk: b=0x80 is 10000000; the loop
// processes each bit of b. Bit-7 of b is 1 only at the last iteration (after 7
// right-shifts of b). During those shifts a doubles 7 times: 0x02 → 0x04 →
// 0x08 → 0x10 → 0x20 → 0x40 → 0x80 → (overflow) 0x80<<1 = 0x00 ^ 0xC3 = 0xC3.
// The XOR accumulates: c ^= a = 0xC3 when b&1 fires. Result: 0xC3.
func TestGF_ChecklistVector(t *testing.T) {
	t.Parallel()

	// kuznyechik/kuznyechik-gost34122015.md:413: checklist step 1 states
	// gf(0x02, 0x80) equals 0xC3, i.e. 2*128 = x^8 mod p(x).
	const want = byte(0xC3)

	got := gf(0x02, 0x80)
	if got != want {
		t.Fatalf("gf(0x02, 0x80) = 0x%02X, want 0xC3 (kuznyechik-gost34122015.md:413)", got)
	}
}

// TestFusedTableVsSlowPath asserts that slEncrypt and lInvFast (table-driven
// paths) produce outputs byte-for-byte identical to the reference slow path
// (l+s for the forward direction, lInv+sInv for the inverse) across 256
// deterministic inputs. The fused tables are built by calling the same verified
// slow transforms on unit vectors (see buildTables), so this test pins that
// the packing/XOR accumulation is a true identity rather than an approximation.
//
// By construction the assertion can only fail if (a) buildTables or the packing
// has a bug, or (b) the slow l/lInv functions themselves have a regression that
// shifts test outputs in a way that two different bugs cancel — the independent
// KAT coverage in TestStageKATs guards against (b).
func TestFusedTableVsSlowPath(t *testing.T) {
	t.Parallel()

	// Ensure tables are built before calling table-driven paths.
	tableOnce.Do(buildTables)

	for i := range 256 {
		// Deterministic but varied: fill the 16-byte block with a simple
		// non-uniform pattern that exercises all 16 table positions.
		var src [BlockSize]byte
		for j := range src {
			src[j] = byte((i + j*17 + j*j) & 0xFF)
		}

		// --- Forward direction: S then L ---
		// Slow path: s then l on a copy.
		slow := src
		s(&slow)
		l(&slow)

		// Fast path: slEncrypt on a separate copy.
		fast := src
		slEncrypt(&fast)

		if fast != slow {
			t.Fatalf("slEncrypt vs s+l mismatch at i=%d:\n  fast=%x\n  slow=%x",
				i, fast, slow)
		}

		// --- Inverse direction: L⁻¹ (then S⁻¹ is separate in Decrypt) ---
		// Slow path: lInv only (sInv is bytewise and not fused).
		slowInv := src
		lInv(&slowInv)

		fastInv := src
		lInvFast(&fastInv)

		if fastInv != slowInv {
			t.Fatalf("lInvFast vs lInv mismatch at i=%d:\n  fast=%x\n  slow=%x",
				i, fastInv, slowInv)
		}
	}
}

// FuzzEncrypt exercises two round-trip properties for arbitrary 16-byte blocks
// and the fixed §A.1 key:
//
//  1. Decrypt(Encrypt(p)) == p  for all 16-byte inputs.
//  2. Encrypting into a separate dst equals encrypting in place (dst == src).
//
// No expected-byte literals are introduced here: the properties are purely
// algebraic and depend only on the package's own code being consistent with
// itself.  The parity oracle against gogost lives in gostcrypto-compat.
func FuzzEncrypt(f *testing.F) {
	// Seed corpus: the §A.1 plaintext and a few structural variants.
	seeds := [][]byte{
		{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88},
		make([]byte, BlockSize), // all-zero block.
		bytes.Repeat([]byte{0xFF}, BlockSize),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	key := [32]byte{
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	}

	c := NewCipher(key[:])

	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) != BlockSize {
			// The fuzzer may produce inputs of any length; skip non-block-sized ones.
			// (The block cipher only operates on exactly 16-byte inputs.)
			return
		}

		// Property 1: Decrypt(Encrypt(p)) == p.
		ct := make([]byte, BlockSize)
		c.Encrypt(ct, p)

		rt := make([]byte, BlockSize)
		c.Decrypt(rt, ct)

		if !bytes.Equal(rt, p) {
			t.Fatalf(
				"round-trip failed: Decrypt(Encrypt(plaintext)) != plaintext\n  pt=%x\n  ct=%x\n  rt=%x",
				p, ct, rt,
			)
		}

		// Property 2: in-place Encrypt == out-of-place Encrypt.
		inPlace := append([]byte(nil), p...)
		c.Encrypt(inPlace, inPlace)

		if !bytes.Equal(inPlace, ct) {
			t.Fatalf("in-place Encrypt != out-of-place Encrypt\n  p       =%x\n  in-place=%x\n  separate=%x",
				p, inPlace, ct)
		}
	})
}
