package x509gost //nolint:testpackage // white-box: uses unexported buildCertDER/buildParams/buildExtensions

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// ekuServerAuth / ekuCodeSigning are the EKU OIDs used by the EKU tests.
var (
	ekuServerAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	ekuCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
)

// buildGOST256Cert builds a GOST R 34.10-2012/256 certificate. When signer is
// nil it is self-signed; otherwise it is signed by signer (a CA) with the
// issuer CN set accordingly. Optional extensions are embedded.
func buildGOST256Cert(t *testing.T, subjectCN string, signer *gostCA, ext extensionParams) *Certificate {
	t.Helper()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen %s: %v", subjectCN, err)
	}

	notBefore, notAfter := validityWindow()

	extDER, err := buildExtensionsDER(ext)
	if err != nil {
		t.Fatalf("buildExtensionsDER %s: %v", subjectCN, err)
	}

	bp := buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    subjectCN,
		extensionsDER: extDER,
	}

	if signer != nil {
		bp.issuerCN = signer.cn
		bp.signerPriv = signer.priv
		bp.signerCurveOID = OIDParamCryptoProA
	}

	der, err := buildCertDER(bp)
	if err != nil {
		t.Fatalf("buildCertDER %s: %v", subjectCN, err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate %s: %v", subjectCN, err)
	}

	return cert
}

// gostCA bundles a CA's signing key and CN.
type gostCA struct {
	cn   string
	priv []byte
	cert *Certificate
}

// newGOST256CA builds a self-signed GOST-256 CA (with BasicConstraints CA:TRUE
// and keyCertSign) and returns its handle.
func newGOST256CA(t *testing.T, cn string) *gostCA {
	t.Helper()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("CA keygen %s: %v", cn, err)
	}

	notBefore, notAfter := validityWindow()

	extDER, err := buildExtensionsDER(extensionParams{
		setBasicConstraints: true,
		isCA:                true,
		keyUsageCertSign:    true,
	})
	if err != nil {
		t.Fatalf("CA ext %s: %v", cn, err)
	}

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    cn,
		extensionsDER: extDER,
	})
	if err != nil {
		t.Fatalf("CA buildCertDER %s: %v", cn, err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("CA ParseCertificate %s: %v", cn, err)
	}

	return &gostCA{cn: cn, priv: priv, cert: cert}
}

// rsaSelfSignedGOSTRoot returns an RSA cert parsed as a (non-GOST) Certificate,
// for populating the GOST pools with a non-GOST entry.
func rsaSelfSignedGOSTRoot(t *testing.T) *Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "rsa-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("rsa CreateCertificate: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("rsa ParseCertificate: %v", err)
	}

	return cert
}

// TestVerify_GOST_Depth1_Success pins the depth-1 (CA-signed leaf) success path
// — previously only the negative TestVerify_GOST_WrongSigner exercised it
// (X509-71 #1). A 256-bit leaf signed by a distinct GOST-256 CA verifies, and
// the returned chain is leaf-then-root.
func TestVerify_GOST_Depth1_Success(t *testing.T) {
	t.Parallel()

	ca := newGOST256CA(t, "depth1-ca")
	leaf := buildGOST256Cert(t, "depth1-leaf", ca, extensionParams{})

	chains, err := leaf.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		CurrentTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Verify depth-1 chain: %v", err)
	}

	if len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatalf("want one chain of length 2, got %d chains", len(chains))
	}
}

// TestVerify_GOST_2001_Verify exercises the AlgoR341001 (GOST R 34.11-94 hash)
// verify branch, which no test executed before — 2001 certs were only parsed
// (X509-71 #2).
func TestVerify_GOST_2001_Verify(t *testing.T) {
	t.Parallel()

	priv, pub, err := buildTestKeypair2001()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	notBefore, notAfter := validityWindow()

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341001,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341001,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341001,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "gost-2001-selfsigned",
	})
	if err != nil {
		t.Fatalf("buildCertDER: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	chains, err := cert.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{cert},
		CurrentTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Verify GOST-2001 self-signed: %v", err)
	}

	if len(chains) == 0 {
		t.Fatal("expected at least one chain")
	}
}

// TestVerify_GOST_RootsEmpty pins errGOSTRootsEmpty (X509-71 #5).
func TestVerify_GOST_RootsEmpty(t *testing.T) {
	t.Parallel()

	cert := buildSelfSignedGOST256(t)

	_, err := cert.Verify(VerifyOptions{CurrentTime: time.Now()})
	if err == nil {
		t.Fatal("expected error for empty GOSTRoots, got nil")
	}
}

// TestVerify_GOST_NotYetValid pins errCertNotYetValid (X509-71 #4): only expiry
// was tested before.
func TestVerify_GOST_NotYetValid(t *testing.T) {
	t.Parallel()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Validity entirely in the future.
	notBefore := time.Now().Add(24 * time.Hour)
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	der, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "not-yet-valid",
	})
	if err != nil {
		t.Fatalf("buildCertDER: %v", err)
	}

	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	_, err = cert.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{cert},
		CurrentTime: time.Now(),
	})
	if err == nil {
		t.Fatal("expected not-yet-valid error, got nil")
	}
}

// TestVerify_GOST_MixedPoolOrdering pins X509-66: a non-GOST entry anywhere in
// GOSTRoots must be skipped, not abort the search. Both orderings of a
// [rsaRoot, gostRoot] pool must verify an otherwise-valid all-GOST chain.
func TestVerify_GOST_MixedPoolOrdering(t *testing.T) {
	t.Parallel()

	ca := newGOST256CA(t, "mixed-ca")
	leaf := buildGOST256Cert(t, "mixed-leaf", ca, extensionParams{})
	rsaRoot := rsaSelfSignedGOSTRoot(t)

	orderings := []struct {
		name  string
		roots []*Certificate
	}{
		{"rsa-first", []*Certificate{rsaRoot, ca.cert}},
		{"gost-first", []*Certificate{ca.cert, rsaRoot}},
	}

	for _, tc := range orderings {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			chains, err := leaf.Verify(VerifyOptions{
				GOSTRoots:   tc.roots,
				CurrentTime: time.Now(),
			})
			if err != nil {
				t.Fatalf("Verify with %s pool: %v", tc.name, err)
			}

			if len(chains) == 0 {
				t.Fatal("expected a verified chain")
			}
		})
	}
}

// TestVerify_GOST_SelfSignedMixedPool pins the self-signed-with-mixed-pool case
// (the inconsistency noted in X509-66): it must verify regardless of a non-GOST
// pool entry.
func TestVerify_GOST_SelfSignedMixedPool(t *testing.T) {
	t.Parallel()

	cert := buildSelfSignedGOST256(t)
	rsaRoot := rsaSelfSignedGOSTRoot(t)

	chains, err := cert.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{rsaRoot, cert},
		CurrentTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Verify self-signed with mixed pool: %v", err)
	}

	if len(chains) == 0 {
		t.Fatal("expected a verified chain")
	}
}

// TestVerify_GOST_KeyUsages pins X509-67: opts.KeyUsages must be enforced on the
// GOST leaf. A leaf with EKU=codeSigning fails a ServerAuth request, passes an
// empty request, and passes when ServerAuth is requested and present.
func TestVerify_GOST_KeyUsages(t *testing.T) {
	t.Parallel()

	ca := newGOST256CA(t, "eku-ca")

	codeSignLeaf := buildGOST256Cert(t, "code-sign-leaf", ca, extensionParams{
		ekuOIDs: []asn1.ObjectIdentifier{ekuCodeSigning},
	})
	serverAuthLeaf := buildGOST256Cert(t, "server-auth-leaf", ca, extensionParams{
		ekuOIDs: []asn1.ObjectIdentifier{ekuServerAuth},
	})

	roots := []*Certificate{ca.cert}

	// codeSigning leaf must FAIL a ServerAuth request.
	_, err := codeSignLeaf.Verify(VerifyOptions{
		GOSTRoots:   roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	})
	if err == nil {
		t.Fatal("codeSigning leaf unexpectedly passed a ServerAuth KeyUsages check")
	}

	// codeSigning leaf must PASS with empty KeyUsages.
	if _, err := codeSignLeaf.Verify(VerifyOptions{
		GOSTRoots:   roots,
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("codeSigning leaf failed with empty KeyUsages: %v", err)
	}

	// serverAuth leaf must PASS a ServerAuth request.
	if _, err := serverAuthLeaf.Verify(VerifyOptions{
		GOSTRoots:   roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("serverAuth leaf failed a ServerAuth KeyUsages check: %v", err)
	}
}

// TestVerify_GOST_IssuerNotCA pins X509-67's issuer constraint: a GOST issuer
// whose BasicConstraints says IsCA=false must not be accepted as a signer.
func TestVerify_GOST_IssuerNotCA(t *testing.T) {
	t.Parallel()

	// "CA" lacks the CA flag (BasicConstraints CA:FALSE present).
	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	notBefore, notAfter := validityWindow()

	notCAExt, err := buildExtensionsDER(extensionParams{
		setBasicConstraints: true,
		isCA:                false,
	})
	if err != nil {
		t.Fatalf("buildExtensionsDER: %v", err)
	}

	caDER, err := buildCertDER(buildParams{
		sigAlgoOID:    OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID: OIDPublicKeyGOSTR341012_256,
		curveOID:      OIDParamCryptoProA,
		privRaw:       priv,
		pubRaw:        pub,
		gostAlgo:      AlgoR341012_256,
		notBefore:     notBefore,
		notAfter:      notAfter,
		commonName:    "not-a-ca",
		extensionsDER: notCAExt,
	})
	if err != nil {
		t.Fatalf("buildCertDER CA: %v", err)
	}

	caCert, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}

	notCA := &gostCA{cn: "not-a-ca", priv: priv, cert: caCert}
	leaf := buildGOST256Cert(t, "leaf-under-noncaroot", notCA, extensionParams{})

	_, err = leaf.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{caCert},
		CurrentTime: time.Now(),
	})
	if err == nil {
		t.Fatal("leaf signed by a non-CA issuer unexpectedly verified")
	}
}

// TestVerify_GOST_Intermediate pins X509-68(b): a root -> intermediate -> leaf
// chain verifies when the intermediate is supplied in GOSTIntermediates, and a
// chain missing the intermediate fails.
func TestVerify_GOST_Intermediate(t *testing.T) {
	t.Parallel()

	root := newGOST256CA(t, "inter-root")

	// Intermediate: a CA cert signed by the root.
	interPriv, interPub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("inter keygen: %v", err)
	}

	notBefore, notAfter := validityWindow()

	interExt, err := buildExtensionsDER(extensionParams{
		setBasicConstraints: true,
		isCA:                true,
		keyUsageCertSign:    true,
	})
	if err != nil {
		t.Fatalf("inter ext: %v", err)
	}

	interDER, err := buildCertDER(buildParams{
		sigAlgoOID:     OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID:  OIDPublicKeyGOSTR341012_256,
		curveOID:       OIDParamCryptoProA,
		privRaw:        interPriv,
		pubRaw:         interPub,
		gostAlgo:       AlgoR341012_256,
		notBefore:      notBefore,
		notAfter:       notAfter,
		commonName:     "inter-ca",
		issuerCN:       root.cn,
		signerPriv:     root.priv,
		signerCurveOID: OIDParamCryptoProA,
		extensionsDER:  interExt,
	})
	if err != nil {
		t.Fatalf("inter buildCertDER: %v", err)
	}

	interCert, err := ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("inter ParseCertificate: %v", err)
	}

	interCA := &gostCA{cn: "inter-ca", priv: interPriv, cert: interCert}
	leaf := buildGOST256Cert(t, "inter-leaf", interCA, extensionParams{})

	// With the intermediate supplied: root -> inter -> leaf verifies.
	chains, err := leaf.Verify(VerifyOptions{
		GOSTRoots:         []*Certificate{root.cert},
		GOSTIntermediates: []*Certificate{interCert},
		CurrentTime:       time.Now(),
	})
	if err != nil {
		t.Fatalf("Verify root->inter->leaf: %v", err)
	}

	if len(chains) != 1 || len(chains[0]) != 3 {
		t.Fatalf("want one chain of length 3 (leaf,inter,root), got %d chains", len(chains))
	}

	// Without the intermediate: fails.
	_, err = leaf.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{root.cert},
		CurrentTime: time.Now(),
	})
	if err == nil {
		t.Fatal("chain missing the intermediate unexpectedly verified")
	}
}
