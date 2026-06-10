package gost3410sign_test

// rejection_test.go — pins every rejection path of Sign/Verify (GOST-25) and
// provides fuzz targets (GOST-26).
//
// The test curve used here is the id-GostR3410-2001-TestParamSet from RFC 7091
// §7.1, constructed in gost3410sign_test.go:testParamSetCurve().

import (
	"encoding/hex"
	"math/big"
	"testing"

	gost3410sign "github.com/bigbes/gostcrypto/gost3410sign"
)

// hexDecodeStringLocal decodes a hex string; used internally so rejection_test.go
// does not depend on an unexported helper from gost3410sign_test.go.
func hexDecodeStringLocal(s string) ([]byte, error) { return hex.DecodeString(s) }

// katFieldsR returns the canonical 256-bit KAT components (dig, pub, sig —
// all byte slices are freshly decoded on every call so callers can mutate freely).
// (Distinct name from katFields to avoid conflict if the main test file adds one.)
func katFieldsR(t *testing.T) (dig, pub, sig []byte) {
	t.Helper()

	dig = mustHex(t, katDigBE)
	pub = append(mustHex(t, katPubX), mustHex(t, katPubY)...)
	sig = mustHex(t, katSigSR)

	return
}

// cloneBytes returns a copy of b.
func cloneBytes(b []byte) []byte { return append([]byte(nil), b...) }

// q256 is the subgroup order for the 256-bit test curve (testParamSetCurve).
// q = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3.
var q256, _ = new(big.Int).SetString(
	"8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3", 16,
)

// bigToBeFixed serialises n as a fixed-width big-endian byte slice.
func bigToBeFixed(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}

	out := make([]byte, size)
	copy(out[size-len(b):], b)

	return out
}

// ─── GOST-25: Rejection paths ──────────────────────────────────────────────.

// TestVerify_RejectsMalformedLengths checks that VerifyDigest returns false
// (no panic) when the signature or public-key byte slice has the wrong length.
// Enumerated from gost3410sign.go:127 (length gate).
func TestVerify_RejectsMalformedLengths(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	dig, pub, sig := katFieldsR(t)

	cases := []struct {
		name   string
		pubRaw []byte
		sigRaw []byte
	}{
		{"sig_nil", pub, nil},
		{"sig_zero", pub, []byte{}},
		{"sig_short1", pub, sig[:len(sig)-1]},
		{"sig_long1", pub, append(cloneBytes(sig), 0x00)},
		{"pub_nil", nil, sig},
		{"pub_zero", []byte{}, sig},
		{"pub_short1", pub[:len(pub)-1], sig},
		{"pub_long1", append(cloneBytes(pub), 0x00), sig},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if gost3410sign.VerifyDigest(c, tc.pubRaw, dig, tc.sigRaw) {
				t.Fatalf("%s: expected false, got true", tc.name)
			}
		})
	}
}

// TestVerify_RejectsOutOfRangeRS checks that VerifyDigest returns false when
// r or s is 0 or ≥ q (§6.2 step-1 strict range gate, gost3410sign.go:136).
func TestVerify_RejectsOutOfRangeRS(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	dig, pub, sig := katFieldsR(t)

	ps := c.PointSize() // 32 bytes for the 256-bit test curve.
	qBytes := bigToBeFixed(q256, ps)

	// Build a signature with s = 0 (first half zeroed).
	sigSZero := cloneBytes(sig)
	for i := range ps {
		sigSZero[i] = 0x00
	}

	// Build a signature with r = 0 (second half zeroed).
	sigRZero := cloneBytes(sig)
	for i := ps; i < 2*ps; i++ {
		sigRZero[i] = 0x00
	}

	// Build a signature with s = q (s-half set to BE(q)).
	sigSEqQ := cloneBytes(sig)
	copy(sigSEqQ[:ps], qBytes)
	// Build a signature with r = q (r-half set to BE(q)).
	sigREqQ := cloneBytes(sig)
	copy(sigREqQ[ps:], qBytes)
	// r + q: r-half set to BE(r + q), which is > q and fits in 32 bytes
	// since r < q < 2^255, so r + q < 2^256.
	rBig := new(big.Int).SetBytes(sig[ps:])
	rPlusQ := new(big.Int).Add(rBig, q256)
	sigRPlusQ := cloneBytes(sig)
	copy(sigRPlusQ[ps:], bigToBeFixed(rPlusQ, ps))

	cases := []struct {
		name string
		s    []byte
	}{
		{"s_zero", sigSZero},
		{"r_zero", sigRZero},
		{"s_eq_q", sigSEqQ},
		{"r_eq_q", sigREqQ},
		{"r_plus_q", sigRPlusQ},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if gost3410sign.VerifyDigest(c, pub, dig, tc.s) {
				t.Fatalf("%s: expected false (out-of-range r/s), got true", tc.name)
			}
		})
	}
}

// TestVerify_RejectsOffCurvePub checks that VerifyDigest returns false when
// the public key is off-curve or all-zero.
// Exercises gost3410sign.go:147 (IsOnCurve / infinity gate).
func TestVerify_RejectsOffCurvePub(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	dig, pub, sig := katFieldsR(t)

	// all-zero pub: (0,0) is not on the curve.
	allZero := make([]byte, len(pub))

	// one-byte-flipped pub (first byte of X coordinate, LE) — almost certainly
	// not on the curve.
	flipped := cloneBytes(pub)

	flipped[0] ^= 0x01

	cases := []struct {
		name string
		p    []byte
	}{
		{"all_zero", allZero},
		{"byte_flipped", flipped},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if gost3410sign.VerifyDigest(c, tc.p, dig, sig) {
				t.Fatalf("%s: expected false (off-curve pub), got true", tc.name)
			}
		})
	}
}

// TestSign_RejectsDegenerateInputs checks that SignDigest returns nil for:
//   - zero private key (d ≡ 0 mod q, gost3410sign.go:61)
//   - private key equal to q in LE form (d ≡ 0 mod q after reduction)
//   - nonce k = BE(q) (k ≡ 0 mod q, gost3410sign.go:78)
func TestSign_RejectsDegenerateInputs(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	dig, _, _ := katFieldsR(t)
	validK := mustHex(t, katNonce)
	validPrv := mustHex(t, katPrvLE)

	ps := c.PointSize()
	zeroPrv := make([]byte, ps)

	// prv = LE(q): package reads prv as little-endian, reverses it, then
	// reduces mod q → 0.  So the LE encoding of q is reverse(BE(q)).
	prvEqQLE := bigToBeFixed(q256, ps)
	for i, j := 0, len(prvEqQLE)-1; i < j; i, j = i+1, j-1 {
		prvEqQLE[i], prvEqQLE[j] = prvEqQLE[j], prvEqQLE[i]
	}

	// k = BE(q): package reads k as big-endian, reduces mod q → 0.
	kEqQ := bigToBeFixed(q256, ps)

	cases := []struct {
		name string
		prv  []byte
		k    []byte
	}{
		{"zero_prv", zeroPrv, validK},
		{"prv_eq_q", prvEqQLE, validK},
		{"k_eq_q", validPrv, kEqQ},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := gost3410sign.SignDigest(c, tc.prv, dig, tc.k)
			if got != nil {
				t.Fatalf("%s: expected nil from SignDigest, got sig %x", tc.name, got)
			}
		})
	}
}

// TestEZeroSubstitution pins the e=0→e=1 substitution (§6.1/§6.2 step 2).
// Both a digest equal to BE(q) (reduces to 0 mod q) and an empty digest
// (also 0) produce e=1; with the same prv and k they must yield identical
// signatures, and both signatures must verify against both digests.
// This pins the branches at gost3410sign.go:69 (sign) and :155 (verify).
func TestEZeroSubstitution(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	k := mustHex(t, katNonce)
	prv := mustHex(t, katPrvLE)
	pub := append(mustHex(t, katPubX), mustHex(t, katPubY)...)

	ps := c.PointSize()
	// digest = BE(q) → e = q mod q = 0 → e = 1.
	digQ := bigToBeFixed(q256, ps)
	// empty digest → alpha = 0 → e = 1.
	digEmpty := []byte{}

	sig1 := gost3410sign.SignDigest(c, prv, digQ, k)
	if sig1 == nil {
		t.Fatal("SignDigest(digest=q) returned nil")
	}

	sig2 := gost3410sign.SignDigest(c, prv, digEmpty, k)
	if sig2 == nil {
		t.Fatal("SignDigest(digest=empty) returned nil")
	}

	// Both digests yield e=1, so with the same prv and k the signatures must
	// be byte-identical — this pins the branch by content, not just round-trip.
	if len(sig1) != len(sig2) {
		t.Fatalf("sig length mismatch: %d vs %d", len(sig1), len(sig2))
	}

	for i := range sig1 {
		if sig1[i] != sig2[i] {
			t.Fatalf("signatures differ at byte %d: %02x vs %02x", i, sig1[i], sig2[i])
		}
	}

	// Both signatures must verify against both "e=0" digests.
	if !gost3410sign.VerifyDigest(c, pub, digQ, sig1) {
		t.Fatal("VerifyDigest(digest=q, sig1) returned false")
	}

	if !gost3410sign.VerifyDigest(c, pub, digEmpty, sig1) {
		t.Fatal("VerifyDigest(digest=empty, sig1) returned false")
	}
}

// TestBitFlipSweep checks that flipping any single byte of a valid signature
// causes VerifyDigest to return false (GOST-25 requirement).
// 64 iterations for the 256-bit KAT signature (2×32 bytes).
func TestBitFlipSweep(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	dig, pub, sig := katFieldsR(t)

	for i := range sig {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			bad := cloneBytes(sig)

			bad[i] ^= 0xFF
			if gost3410sign.VerifyDigest(c, pub, dig, bad) {
				t.Fatalf("VerifyDigest accepted sig with byte %d flipped", i)
			}
		})
	}
}

// ─── GOST-26: Fuzz targets ─────────────────────────────────────────────────.

// mustHexFF is a fuzz-setup-time hex decode helper.
func mustHexFF(f *testing.F, s string) []byte {
	f.Helper()

	b, err := hexDecodeStringLocal(s)
	if err != nil {
		f.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// FuzzVerifyNeverPanics pins the documented contract that VerifyDigest never
// panics on any input: "returns false (never panics) on any malformed input"
// (gost3410sign.go:120-122).  Seeded from the existing KATs.
func FuzzVerifyNeverPanics(f *testing.F) {
	c := testParamSetCurve()

	pub := append(mustHexFF(f, katPubX), mustHexFF(f, katPubY)...)
	dig := mustHexFF(f, katDigBE)
	sig := mustHexFF(f, katSigSR)
	f.Add(pub, dig, sig)

	// Additional seeds: degenerate sizes.
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 64), make([]byte, 32), make([]byte, 64))

	f.Fuzz(func(t *testing.T, pubRaw, digest, sigB []byte) {
		// Must not panic; return value can be anything.
		_ = gost3410sign.VerifyDigest(c, pubRaw, digest, sigB)
	})
}

// FuzzSignVerifyRoundTrip checks that if SignDigest returns a non-nil signature,
// then VerifyDigest with the matching public key returns true, and a one-byte
// mutation of the digest causes it to return false.
// Seeded from the 256-bit and 512-bit KATs.
func FuzzSignVerifyRoundTrip(f *testing.F) {
	c := testParamSetCurve()

	prv256 := mustHexFF(f, katPrvLE)
	dig256 := mustHexFF(f, katDigBE)
	k256 := mustHexFF(f, katNonce)
	f.Add(prv256, dig256, k256)

	// Seed with the 512-bit KAT values (different slice lengths exercise the
	// PointSize-driven sizing path).
	prv512 := mustHexFF(f, katPrv512LE)
	dig512 := mustHexFF(f, katDig512BE)
	k512 := mustHexFF(f, katNonce512)
	f.Add(prv512, dig512, k512)

	// Degenerate seeds.
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, prv, dig, kBytes []byte) {
		sig := gost3410sign.SignDigest(c, prv, dig, kBytes)
		if sig == nil {
			// Degenerate input (zero key, zero k, etc.): nothing more to check.
			return
		}

		pub := gost3410sign.PublicKeyRaw(c, prv)
		if pub == nil {
			// Zero private key: SignDigest should not have returned non-nil, but
			// guard defensively.
			return
		}

		if !gost3410sign.VerifyDigest(c, pub, dig, sig) {
			t.Fatal("SignDigest produced a signature that VerifyDigest rejects")
		}

		// A one-byte mutation of the digest must fail Verify.
		if len(dig) > 0 {
			mutDig := append([]byte(nil), dig...)

			mutDig[0] ^= 0x01
			if gost3410sign.VerifyDigest(c, pub, mutDig, sig) {
				t.Fatal("VerifyDigest accepted a mutated digest")
			}
		}
	})
}
