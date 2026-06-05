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

// buildSelfSignedGOST256 is a test helper that builds a valid GOST R
// 34.10-2012/256 self-signed certificate and returns both the parsed
// Certificate and a function to re-parse a DER to easily create tampered
// variants.
func buildSelfSignedGOST256(t *testing.T) *Certificate {
	t.Helper()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("buildSelfSignedGOST256: keygen: %v", err)
	}

	notBefore, notAfter := validityWindow()

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "test",
	})
	if err != nil {
		t.Fatalf("buildSelfSignedGOST256: buildCertDER: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("buildSelfSignedGOST256: ParseCertificate: %v", err)
	}

	return cert
}

// TestVerify_GOST_SelfSigned_Happy verifies that a well-formed GOST self-signed
// cert placed in GOSTRoots passes verification.
func TestVerify_GOST_SelfSigned_Happy(t *testing.T) {
	t.Parallel()

	cert := buildSelfSignedGOST256(t)

	opts := VerifyOptions{
		GOSTRoots:   []*Certificate{cert},
		CurrentTime: time.Now(),
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if len(chains) == 0 {
		t.Error("expected at least one chain")
	}
}

// TestVerify_GOST_Tampered verifies that flipping one bit in the DER signature
// causes verification to fail with a meaningful error.
func TestVerify_GOST_Tampered(t *testing.T) {
	t.Parallel()

	cert := buildSelfSignedGOST256(t)

	// Flip one bit in the raw signature bytes.
	tamperedRaw := make([]byte, len(cert.Raw))
	copy(tamperedRaw, cert.Raw)

	// The signature is near the end; flip the last byte.
	tamperedRaw[len(tamperedRaw)-1] ^= 0x01

	// Parse the tampered bytes. The stdlib will still parse (it won't verify
	// GOST sigs), but GOST verification should fail.
	tamperedCert, err := ParseCertificate(tamperedRaw)
	if err != nil {
		// Tampering in the wrong place might break ASN.1 parsing — skip
		// rather than fail because the goal is to test the GOST sig path.
		t.Skipf("tampered DER failed to parse (expected): %v", err)
	}

	opts := VerifyOptions{
		GOSTRoots:   []*Certificate{tamperedCert},
		CurrentTime: time.Now(),
	}

	_, err = tamperedCert.Verify(opts)
	if err == nil {
		t.Error("expected verification failure for tampered cert, got nil error")
	}
}

// TestVerify_GOST_WrongSigner builds a chain where the leaf's signature was
// made with a different private key than the key advertised in the root.
func TestVerify_GOST_WrongSigner(t *testing.T) {
	t.Parallel()

	// Build the leaf cert with key1.
	key1Priv, key1Pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen key1: %v", err)
	}

	notBefore, notAfter := validityWindow()

	leafDER, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       key1Priv,
		pubRaw:        key1Pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "test",
	})
	if err != nil {
		t.Fatalf("buildCertDER leaf: %v", err)
	}

	// Build a root cert with key2 (different key, same CN so issuer match works).
	key2Priv, key2Pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen key2: %v", err)
	}

	rootDER, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       key2Priv,
		pubRaw:        key2Pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "test", // same CN → issuer == subject for both.
	})
	if err != nil {
		t.Fatalf("buildCertDER root: %v", err)
	}

	leafCert, err := ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	rootCert, err := ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	opts := VerifyOptions{
		GOSTRoots:   []*Certificate{rootCert},
		CurrentTime: time.Now(),
	}

	_, err = leafCert.Verify(opts)
	if err == nil {
		t.Error("expected verification failure (wrong signer), got nil")
	}
}

// TestVerify_NonGOST_DelegatesToStdlib verifies that a non-GOST cert in a
// stdlib pool is accepted via the stdlib delegation path.
func TestVerify_NonGOST_DelegatesToStdlib(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA cert: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert.Stdlib)

	opts := VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		t.Fatalf("Verify delegation to stdlib: %v", err)
	}

	if len(chains) == 0 {
		t.Error("expected at least one chain from stdlib delegation")
	}
}

// TestVerify_ExpiredCert builds a GOST cert with a past validity window and
// verifies that Verify returns an expiry error.
func TestVerify_ExpiredCert(t *testing.T) {
	t.Parallel()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	notBefore, notAfter := expiredValidityWindow()

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "expired",
	})
	if err != nil {
		t.Fatalf("buildCertDER: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	opts := VerifyOptions{
		GOSTRoots:   []*Certificate{cert},
		CurrentTime: time.Now(),
	}

	_, err = cert.Verify(opts)
	if err == nil {
		t.Error("expected expiry error, got nil")
	}
}

// TestVerify_NameMismatch verifies that a DNS name mismatch returns an error.
func TestVerify_NameMismatch(t *testing.T) {
	t.Parallel()

	// Use RSA cert for simplicity: we're testing the DNS name path via stdlib.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "correct.example.com"},
		DNSNames:              []string{"correct.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create RSA cert: %v", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert.Stdlib)

	opts := VerifyOptions{
		Roots:       roots,
		DNSName:     "wrong.example.com",
		CurrentTime: time.Now(),
	}

	_, err = cert.Verify(opts)
	if err == nil {
		t.Error("expected DNS name mismatch error, got nil")
	}
}
