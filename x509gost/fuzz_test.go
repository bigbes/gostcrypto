package x509gost //nolint:testpackage // white-box: uses unexported helpers buildCertDER/buildParams

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	stdrsa "crypto/rsa"
)

// FuzzParseCertificate hammers the attacker-facing DER entry point with
// arbitrary bytes. ParseCertificate consumes untrusted certificate bytes
// straight off a TLS wire, so the contract under fuzz is the robustness one:
// it must return an error on malformed input, never panic. Mismatched lengths,
// nested-tag overruns, and bogus GOST OIDs are exactly the inputs a remote
// peer controls.
//
// Coverage is seeded with real GOST 2012-256, GOST 2001, and stdlib RSA certs
// (so the mutator starts from inside the GOST-specific SPKI path), plus the
// truncated/garbage cases the unit tests already pin.
func FuzzParseCertificate(f *testing.F) {
	f.Add(seedGOST256Cert(f))
	f.Add(seedGOST2001Cert(f))
	f.Add(seedStdlibCert(f))

	// Malformed seeds mirroring TestParseCertificate_Rejects_Malformed.
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x82, 0x03, 0x00, 0x00})
	f.Add([]byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, der []byte) {
		// Contract: parsing attacker-controlled DER must never panic.
		// A returned error is the expected outcome for malformed input.
		cert, err := ParseCertificate(der)
		if err == nil && cert == nil {
			t.Fatal("ParseCertificate returned nil cert and nil error")
		}
	})
}

func seedGOST256Cert(f *testing.F) []byte {
	f.Helper()

	privRaw, pubRaw, err := buildTestKeypair256()
	if err != nil {
		f.Fatalf("seed keygen 256: %v", err)
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
		commonName:    "fuzz-seed-gost-2012-256",
	})
	if err != nil {
		f.Fatalf("seed buildCertDER 256: %v", err)
	}

	return der
}

func seedGOST2001Cert(f *testing.F) []byte {
	f.Helper()

	privRaw, pubRaw, err := buildTestKeypair2001()
	if err != nil {
		f.Fatalf("seed keygen 2001: %v", err)
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
		commonName:    "fuzz-seed-gost-2001",
	})
	if err != nil {
		f.Fatalf("seed buildCertDER 2001: %v", err)
	}

	return der
}

func seedStdlibCert(f *testing.F) []byte {
	f.Helper()

	key, err := stdrsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("seed rsa keygen: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz-seed-rsa"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatalf("seed CreateCertificate: %v", err)
	}

	return der
}
