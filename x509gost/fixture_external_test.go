package x509gost_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/bigbes/gostcrypto/x509gost"
)

// fixtureValidTime is inside the validity window of the externally-generated
// GOST fixtures (2026-06-10 .. 2036-06-07; see testdata/certs/generate.sh).
var fixtureValidTime = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

// TestVerify_GOST_ExternalFixture parses and verifies GOST-signed certificates
// produced by an independent implementation (OpenSSL 3 + gost-engine 3.0.3, see
// testdata/certs/generate.sh). Unlike the in-process self-signed certs, these
// pin the GOST certificate wire format (signature BIT STRING ordering, the
// LE(X)||LE(Y) public key encoding, signwithdigest OID handling) against an
// implementation that does not share this module's signing code, so a
// systematic format error cannot cancel out (X509-70).
//
// The two self-signed fixtures also cover the Streebog-512 verify branch
// (AlgoR341012_512), previously never executed by any test (X509-71 #3).
func TestVerify_GOST_ExternalFixture(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		rel  string
		algo x509gost.GOSTAlgorithm
	}{
		{"gost256-selfsigned", "testdata/certs/gost256_selfsigned.crt", x509gost.AlgoR341012_256},
		{"gost512-selfsigned", "testdata/certs/gost512_selfsigned.crt", x509gost.AlgoR341012_512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			der := mustReadPEMCert(t, tc.rel)

			cert, err := x509gost.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}

			if !cert.IsGOST {
				t.Fatal("IsGOST should be true for a GOST-signed fixture")
			}

			if cert.SigGOSTAlgo != tc.algo {
				t.Fatalf("SigGOSTAlgo = %v, want %v", cert.SigGOSTAlgo, tc.algo)
			}

			chains, err := cert.Verify(x509gost.VerifyOptions{
				GOSTRoots:   []*x509gost.Certificate{cert},
				CurrentTime: fixtureValidTime,
			})
			if err != nil {
				t.Fatalf("Verify externally-signed self-signed fixture: %v", err)
			}

			if len(chains) == 0 {
				t.Fatal("expected at least one verified chain")
			}
		})
	}
}

// TestVerify_GOST_ExternalChain verifies the mixed-strength chain produced
// externally: a 256-bit subject key signed by a 512-bit CA with
// signwithdigest-512. The leaf's signature OID (512) differs from its subject
// key OID (256). It verifies only when the TBSCertificate digest is taken from
// the signature OID (Streebog-512), which is the X509-65 fix; with the old
// pubkey-OID-driven hash (Streebog-256) it fails. This also exercises the
// depth-1 distinct-root success path (X509-71 #1) and the issuer-IsCA gate.
func TestVerify_GOST_ExternalChain(t *testing.T) {
	t.Parallel()

	caDER := mustReadPEMCert(t, "testdata/certs/ca512.crt")
	leafDER := mustReadPEMCert(t, "testdata/certs/leaf256_signedby512.crt")

	ca, err := x509gost.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate(ca512): %v", err)
	}

	leaf, err := x509gost.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate(leaf256): %v", err)
	}

	// The mixed-strength scenario: subject key is 256-bit, signature is 512-bit.
	if leaf.GOSTAlgo != x509gost.AlgoR341012_256 {
		t.Fatalf("leaf GOSTAlgo (subject key) = %v, want AlgoR341012_256", leaf.GOSTAlgo)
	}

	if leaf.SigGOSTAlgo != x509gost.AlgoR341012_512 {
		t.Fatalf("leaf SigGOSTAlgo = %v, want AlgoR341012_512", leaf.SigGOSTAlgo)
	}

	chains, err := leaf.Verify(x509gost.VerifyOptions{
		GOSTRoots:   []*x509gost.Certificate{ca},
		CurrentTime: fixtureValidTime,
	})
	if err != nil {
		t.Fatalf("Verify mixed-strength chain (512 CA -> 256 leaf): %v", err)
	}

	if len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatalf("want a single depth-1 chain of length 2, got %d chains", len(chains))
	}
}

// TestPubKeyRaw_ByteOrder_LE_X_then_Y empirically confirms the corrected
// PubKeyRaw byte-order documentation (X509-72): the buffer is LE(X)||LE(Y),
// little-endian X coordinate followed by little-endian Y. The X/Y recovered
// this way must form a point that lies on the externally-generated fixture's
// curve. (gost-engine wrote this SubjectPublicKeyInfo, so the test cross-checks
// the encoding against an independent implementation, not against ourselves.)
//
// We confirm on-curveness without exposing curve internals by checking the
// Weierstrass equation y^2 == x^3 + a*x + b (mod p) using the public curve
// parameters; the externally-produced key satisfies it only under the
// LE(X)||LE(Y) reading.
func TestPubKeyRaw_ByteOrder_LE_X_then_Y(t *testing.T) {
	t.Parallel()

	der := mustReadPEMCert(t, "testdata/certs/gost256_selfsigned.crt")

	cert, err := x509gost.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	raw := cert.PubKeyRaw
	if len(raw) != 64 {
		t.Fatalf("PubKeyRaw len = %d, want 64 (256-bit key)", len(raw))
	}

	// LE(X)||LE(Y): reverse each half to obtain big-endian X, Y.
	x := new(big.Int).SetBytes(reversed(raw[:32]))
	y := new(big.Int).SetBytes(reversed(raw[32:]))

	// CryptoPro-A curve parameters, copied from the clean-room curve
	// definition gost3410curves/curves.go:126-128 (curveCryptoProA): P, A and
	// B=0xA6=166. RFC 4357, id-GostR3410-2001-CryptoPro-A-ParamSet.
	p := mustHex(t, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97")
	a := mustHex(t, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94")
	b := big.NewInt(166)

	// y^2 mod p.
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p)

	// x^3 + a*x + b mod p.
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)

	ax := new(big.Int).Mul(a, x)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)

	if lhs.Cmp(rhs) != 0 {
		t.Fatalf("recovered (X,Y) is not on CryptoPro-A under LE(X)||LE(Y); " +
			"PubKeyRaw byte order doc is wrong")
	}
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}

	return out
}

func mustHex(t *testing.T, s string) *big.Int {
	t.Helper()

	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad hex constant %q", s)
	}

	return n
}
