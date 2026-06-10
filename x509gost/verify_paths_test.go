package x509gost //nolint:testpackage // white-box: uses unexported buildCertDER/buildParams/buildExtensions

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
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

// newGOST256CASignedBy builds a GOST-256 CA cert (BasicConstraints CA:TRUE +
// keyCertSign) signed by the given parent CA. ext lets a caller add e.g. a
// pathLenConstraint to the BasicConstraints. Returns a gostCA handle.
func newGOST256CASignedBy(t *testing.T, cn string, parent *gostCA, ext extensionParams) *gostCA {
	t.Helper()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("CA keygen %s: %v", cn, err)
	}

	notBefore, notAfter := validityWindow()

	ext.setBasicConstraints = true
	ext.isCA = true
	ext.keyUsageCertSign = true

	extDER, err := buildExtensionsDER(ext)
	if err != nil {
		t.Fatalf("CA ext %s: %v", cn, err)
	}

	der, err := buildCertDER(buildParams{
		sigAlgoOID:     OIDSignatureGOSTR341012_256,
		pubKeyAlgoOID:  OIDPublicKeyGOSTR341012_256,
		curveOID:       OIDParamCryptoProA,
		privRaw:        priv,
		pubRaw:         pub,
		gostAlgo:       AlgoR341012_256,
		notBefore:      notBefore,
		notAfter:       notAfter,
		commonName:     cn,
		issuerCN:       parent.cn,
		signerPriv:     parent.priv,
		signerCurveOID: OIDParamCryptoProA,
		extensionsDER:  extDER,
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

// TestVerify_GOST_PathLenConstraint pins R2-X509-01: a CA carrying
// pathLenConstraint=0 must reject a chain that puts an intermediate below it.
// Chain root -> A(pathLen=0) -> B(CA) -> leaf: A permits B to be signed but B
// signing a further cert (leaf below B, below A) exceeds A's budget, so the
// 4-cert chain must be rejected; a chain where A directly signs an end-entity
// (no intermediate below A) still verifies.
func TestVerify_GOST_PathLenConstraint(t *testing.T) {
	t.Parallel()

	root := newGOST256CA(t, "pathlen-root")
	// A: pathLenConstraint=0 — may sign end-entities but no further CAs below it.
	caA := newGOST256CASignedBy(t, "pathlen-A", root, extensionParams{setPathLen: true, pathLen: 0})
	// B: an intermediate CA signed by A.
	caB := newGOST256CASignedBy(t, "pathlen-B", caA, extensionParams{})
	// leaf signed by B → chain [leaf, B, A, root]: one intermediate (B) below A.
	leaf := buildGOST256Cert(t, "pathlen-leaf", caB, extensionParams{})

	_, err := leaf.Verify(VerifyOptions{
		GOSTRoots:         []*Certificate{root.cert},
		GOSTIntermediates: []*Certificate{caA.cert, caB.cert},
		CurrentTime:       time.Now(),
	})
	if err == nil {
		t.Fatal("chain exceeding pathLenConstraint=0 unexpectedly verified")
	}

	// Sanity: A directly signing an end-entity (no intermediate below A) is
	// within pathLen=0 and must verify.
	directLeaf := buildGOST256Cert(t, "pathlen-direct-leaf", caA, extensionParams{})

	chains, err := directLeaf.Verify(VerifyOptions{
		GOSTRoots:         []*Certificate{root.cert},
		GOSTIntermediates: []*Certificate{caA.cert},
		CurrentTime:       time.Now(),
	})
	if err != nil {
		t.Fatalf("direct end-entity under pathLen=0 CA should verify: %v", err)
	}

	if len(chains) != 1 || len(chains[0]) != 3 {
		t.Fatalf("want one chain of length 3 (leaf,A,root), got %d chains", len(chains))
	}
}

// TestVerify_GOST_UnhandledCriticalExtension pins R2-X509-01: a cert in the
// chain carrying an unrecognized critical extension must be rejected (RFC 5280
// §4.2 MUST-reject), even though it parses and chains otherwise.
func TestVerify_GOST_UnhandledCriticalExtension(t *testing.T) {
	t.Parallel()

	ca := newGOST256CA(t, "critext-ca")
	// An arbitrary OID not recognized by the stdlib parser, marked critical.
	leaf := buildGOST256Cert(t, "critext-leaf", ca, extensionParams{
		unknownCriticalOID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
	})

	// Guard: the unknown critical extension must actually have landed in the
	// stdlib UnhandledCriticalExtensions set, else this test is vacuous.
	if len(leaf.Stdlib.UnhandledCriticalExtensions) == 0 {
		t.Fatal("test setup: expected an unhandled critical extension on the leaf")
	}

	_, err := leaf.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		CurrentTime: time.Now(),
	})
	if err == nil {
		t.Fatal("cert with an unhandled critical extension unexpectedly verified")
	}
}

// TestVerify_GOST_PoolLeafNotSelfSigned pins R2-X509-03: a non-self-signed
// (cross-signed) GOST CA placed directly in GOSTRoots while also being the leaf
// must still verify, provided a valid alternate signer is also in the pool. The
// old code ran verifyGOSTSignature(leaf, leaf) on a pool match and aborted the
// whole search on failure, so a cross-signed CA could not verify even with a
// valid signer present. The fix falls through to the recursive search, which
// finds the real signer in the pool.
func TestVerify_GOST_PoolLeafNotSelfSigned(t *testing.T) {
	t.Parallel()

	// signer is a real CA; crossSigned is a CA cert signed BY signer (so its
	// signature is NOT a valid self-signature). Both go in GOSTRoots; we verify
	// crossSigned directly as the leaf. Under the old self-signature-on-pool-
	// match check this aborted with a self-signed-sig-invalid error.
	signer := newGOST256CA(t, "cross-signer")
	crossSigned := newGOST256CASignedBy(t, "cross-signed-ca", signer, extensionParams{})

	chains, err := crossSigned.cert.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{crossSigned.cert, signer.cert},
		CurrentTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("cross-signed CA in pool with a valid alternate signer should verify: %v", err)
	}

	if len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatalf("want one chain of length 2 (crossSigned, signer), got %d chains of len %d",
			len(chains), chainLen(chains))
	}
}

// chainLen returns the length of the first chain, or -1 if there are none (for
// diagnostics only).
func chainLen(chains [][]*Certificate) int {
	if len(chains) == 0 {
		return -1
	}

	return len(chains[0])
}

// TestVerify_GOST_LeafAnyEKU pins R2-X509-02: a leaf asserting
// anyExtendedKeyUsage must satisfy a specific KeyUsages request (it is valid
// for any purpose), instead of being falsely rejected.
func TestVerify_GOST_LeafAnyEKU(t *testing.T) {
	t.Parallel()

	ca := newGOST256CA(t, "anyeku-ca")
	// anyExtendedKeyUsage OID 2.5.29.37.0.
	anyEKU := asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	leaf := buildGOST256Cert(t, "anyeku-leaf", ca, extensionParams{
		ekuOIDs: []asn1.ObjectIdentifier{anyEKU},
	})

	// Guard: the leaf must actually carry ExtKeyUsageAny, else the test is vacuous.
	if !sliceContainsAny(leaf.Stdlib.ExtKeyUsage) {
		t.Fatal("test setup: expected leaf to assert ExtKeyUsageAny")
	}

	if _, err := leaf.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf asserting anyExtendedKeyUsage should satisfy a ServerAuth request: %v", err)
	}
}

// sliceContainsAny reports whether ekus contains x509.ExtKeyUsageAny.
func sliceContainsAny(ekus []x509.ExtKeyUsage) bool {
	return slices.Contains(ekus, x509.ExtKeyUsageAny)
}

// newGOST256CAWithExt builds a self-signed GOST-256 CA (CA:TRUE + keyCertSign)
// with the supplied extra extension knobs (e.g. permittedDNS) merged in.
func newGOST256CAWithExt(t *testing.T, cn string, ext extensionParams) *gostCA {
	t.Helper()

	priv, pub, err := buildTestKeypair256()
	if err != nil {
		t.Fatalf("CA keygen %s: %v", cn, err)
	}

	notBefore, notAfter := validityWindow()

	ext.setBasicConstraints = true
	ext.isCA = true
	ext.keyUsageCertSign = true

	extDER, err := buildExtensionsDER(ext)
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

// TestVerify_GOST_NameConstraint_PermittedDNS pins R2-X509-01's name-constraint
// processing: a CA with PermittedDNSDomains=["example.com"] must REJECT a leaf
// whose only SAN is out of scope ("evil.org") and ACCEPT one whose SAN is
// in scope ("host.example.com"). Reverting applyNameConstraints fails the
// reject leg (the out-of-scope leaf would verify).
func TestVerify_GOST_NameConstraint_PermittedDNS(t *testing.T) {
	t.Parallel()

	ca := newGOST256CAWithExt(t, "nc-permitted-ca", extensionParams{
		permittedDNS: []string{"example.com"},
	})

	// Guard: the CA must actually carry the parsed permitted constraint, else
	// the test is vacuous.
	if !slices.Contains(ca.cert.Stdlib.PermittedDNSDomains, "example.com") {
		t.Fatal("test setup: CA missing PermittedDNSDomains=example.com")
	}

	inScope := buildGOST256Cert(t, "in-scope-leaf", ca, extensionParams{
		dnsSANs: []string{"host.example.com"},
	})
	outOfScope := buildGOST256Cert(t, "out-of-scope-leaf", ca, extensionParams{
		dnsSANs: []string{"evil.org"},
	})

	// Guard: SANs must have parsed.
	if !slices.Contains(outOfScope.Stdlib.DNSNames, "evil.org") {
		t.Fatal("test setup: out-of-scope leaf missing DNS SAN evil.org")
	}

	// In-scope leaf must verify.
	if _, err := inScope.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("in-scope leaf (host.example.com) should verify under PermittedDNSDomains=example.com: %v", err)
	}

	// Out-of-scope leaf must be rejected.
	if _, err := outOfScope.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		CurrentTime: time.Now(),
	}); err == nil {
		t.Fatal("out-of-scope leaf (evil.org) unexpectedly verified under PermittedDNSDomains=example.com")
	}
}

// TestVerify_GOST_NameConstraint_ExcludedDNS pins the excluded-domain leg of
// R2-X509-01: a CA with ExcludedDNSDomains=["bad.example.com"] must REJECT a
// leaf SAN inside the excluded subtree and ACCEPT one outside it.
func TestVerify_GOST_NameConstraint_ExcludedDNS(t *testing.T) {
	t.Parallel()

	ca := newGOST256CAWithExt(t, "nc-excluded-ca", extensionParams{
		excludedDNS: []string{"bad.example.com"},
	})

	if !slices.Contains(ca.cert.Stdlib.ExcludedDNSDomains, "bad.example.com") {
		t.Fatal("test setup: CA missing ExcludedDNSDomains=bad.example.com")
	}

	allowed := buildGOST256Cert(t, "allowed-leaf", ca, extensionParams{
		dnsSANs: []string{"good.example.com"},
	})
	blocked := buildGOST256Cert(t, "blocked-leaf", ca, extensionParams{
		dnsSANs: []string{"host.bad.example.com"},
	})

	if _, err := allowed.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("leaf outside the excluded subtree should verify: %v", err)
	}

	if _, err := blocked.Verify(VerifyOptions{
		GOSTRoots:   []*Certificate{ca.cert},
		CurrentTime: time.Now(),
	}); err == nil {
		t.Fatal("leaf inside ExcludedDNSDomains=bad.example.com unexpectedly verified")
	}
}
