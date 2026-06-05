package x509gost_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bigbes/gostcrypto/x509gost"
)

func mustReadPEMCert(t *testing.T, rel string) []byte {
	t.Helper()

	path := rel

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}

	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 {
		t.Fatalf("pem.Decode(%s) failed: block=%v rest=%d", path, block != nil, len(rest))
	}

	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM type for %s = %q, want CERTIFICATE", path, block.Type)
	}

	return block.Bytes
}

// TestParseCertificate_FixtureGOSTCerts verifies that the checked-in
// Tarantool server certs with GOST public keys parse correctly, including the
// mixed case where the cert is RSA-signed but carries a GOST SPKI.
func TestParseCertificate_FixtureGOSTCerts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		rel      string
		algo     x509gost.GOSTAlgorithm
		curveOID []int
	}{
		{
			name:     "server-gost-2012",
			rel:      "testdata/certs/server_gost.crt",
			algo:     x509gost.AlgoR341012_256,
			curveOID: []int{1, 2, 643, 2, 2, 35, 1},
		},
		{
			name:     "server-gost-2001",
			rel:      "testdata/certs/server_gost2001.crt",
			algo:     x509gost.AlgoR341001,
			curveOID: []int{1, 2, 643, 2, 2, 35, 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			der := mustReadPEMCert(t, tc.rel)

			cert, err := x509gost.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}

			// These fixtures are RSA-signed by the local CA, but carry GOST SPKIs.
			if cert.IsGOST {
				t.Fatal("IsGOST unexpectedly true for RSA-signed fixture")
			}

			if !cert.HasGOSTPubKey {
				t.Fatal("HasGOSTPubKey unexpectedly false")
			}

			if cert.GOSTAlgo != tc.algo {
				t.Fatalf("GOSTAlgo = %v, want %v", cert.GOSTAlgo, tc.algo)
			}

			if !cert.CurveOID.Equal(tc.curveOID) {
				t.Fatalf("CurveOID = %v, want %v", cert.CurveOID, tc.curveOID)
			}

			if len(cert.PubKeyRaw) == 0 {
				t.Fatal("PubKeyRaw is empty")
			}

			if len(cert.SPKIAlgorithmDER) == 0 {
				t.Fatal("SPKIAlgorithmDER is empty")
			}

			if cert.Stdlib == nil {
				t.Fatal("Stdlib cert is nil")
			}
		})
	}
}

// TestVerify_FixtureGOSTPubKeyDelegatesToStdlib verifies that the
// real Tarantool fixture certs still verify through the stdlib path when they
// are not GOST-signed, even though they carry GOST public keys.
func TestVerify_FixtureGOSTPubKeyDelegatesToStdlib(t *testing.T) {
	t.Parallel()

	caDER := mustReadPEMCert(t, "testdata/certs/ca.crt")

	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(CA): %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	for _, rel := range []string{
		"testdata/certs/server_gost.crt",
		"testdata/certs/server_gost2001.crt",
	} {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			t.Parallel()

			der := mustReadPEMCert(t, rel)

			cert, err := x509gost.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}

			chains, err := cert.Verify(x509gost.VerifyOptions{
				Roots:       roots,
				DNSName:     "localhost",
				CurrentTime: time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}

			if len(chains) == 0 {
				t.Fatal("expected at least one verified chain")
			}
		})
	}
}
