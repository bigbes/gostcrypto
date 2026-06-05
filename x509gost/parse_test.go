package x509gost //nolint:testpackage // white-box: uses unexported helpers buildCertDER/buildParams

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestParseCertificate_StdlibNonGOST verifies that a standard RSA-signed
// certificate parses correctly with IsGOST == false.
func TestParseCertificate_StdlibNonGOST(t *testing.T) {
	t.Parallel()

	// Generate a minimal self-signed RSA cert.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA cert: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if cert.Stdlib == nil {
		t.Error("Stdlib field is nil for non-GOST cert")
	}

	if cert.IsGOST {
		t.Error("IsGOST should be false for RSA cert")
	}

	if len(cert.PubKeyRaw) != 0 {
		t.Errorf("PubKeyRaw should be empty for non-GOST cert, got %d bytes", len(cert.PubKeyRaw))
	}

	if cert.GOSTAlgo != 0 {
		t.Errorf("GOSTAlgo should be zero for non-GOST cert, got %v", cert.GOSTAlgo)
	}

	if cert.Stdlib.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		t.Error("stdlib should recognise the RSA signature algorithm")
	}
}

// TestParseCertificate_GOST_R341012_256 builds a GOST R 34.10-2012/256
// self-signed cert inline and verifies the parser extracts the GOST fields.
func TestParseCertificate_GOST_R341012_256(t *testing.T) {
	t.Parallel()

	privRaw, pubRaw, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	notBefore, notAfter := validityWindow()

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       privRaw,
		pubRaw:        pubRaw,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "test-gost-2012-256",
	})
	if err != nil {
		t.Fatalf("buildCertDER: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if !cert.IsGOST {
		t.Error("IsGOST should be true")
	}

	if cert.GOSTAlgo != AlgoR341012_256 {
		t.Errorf("GOSTAlgo: want AlgoR341012_256, got %v", cert.GOSTAlgo)
	}

	if len(cert.PubKeyRaw) == 0 {
		t.Error("PubKeyRaw should be non-empty")
	}

	if len(cert.CurveOID) == 0 {
		t.Error("CurveOID should be populated")
	}

	if !cert.CurveOID.Equal(OIDParamCryptoProA) {
		t.Errorf("CurveOID: want %v, got %v", OIDParamCryptoProA, cert.CurveOID)
	}

	if cert.Stdlib == nil {
		t.Error("Stdlib field should be populated")
	}
}

// TestParseCertificate_GOST_R342001 builds a GOST R 34.10-2001 self-signed
// cert inline and verifies the parser extracts the GOST fields.
func TestParseCertificate_GOST_R342001(t *testing.T) {
	t.Parallel()

	privRaw, pubRaw, err := buildTestKeypair2001()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	notBefore, notAfter := validityWindow()

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341001,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341001,
		curveOID:      OIDParamCryptoProA,
		privRaw:       privRaw,
		pubRaw:        pubRaw,
		gostAlgo:      AlgoR341001,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "test-gost-2001",
	})
	if err != nil {
		t.Fatalf("buildCertDER: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if !cert.IsGOST {
		t.Error("IsGOST should be true")
	}

	if cert.GOSTAlgo != AlgoR341001 {
		t.Errorf("GOSTAlgo: want AlgoR341001, got %v", cert.GOSTAlgo)
	}

	if len(cert.PubKeyRaw) == 0 {
		t.Error("PubKeyRaw should be non-empty")
	}
}

// TestParseCertificate_Rejects_Malformed verifies that truncated DER is
// rejected with a clear error.
func TestParseCertificate_Rejects_Malformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		der  []byte
	}{
		{"empty", []byte{}},
		{"truncated", []byte{0x30, 0x82, 0x03, 0x00, 0x00}},
		{"garbage", []byte{0xff, 0xfe, 0xfd}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseCertificate(tc.der)
			if err == nil {
				t.Errorf("expected error for %s input, got nil", tc.name)
			}
		})
	}
}
