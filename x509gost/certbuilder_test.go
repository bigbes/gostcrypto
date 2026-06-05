package x509gost //nolint:testpackage // white-box: shared helpers use unexported types (subjectPublicKeyInfoForBuild)

// certbuilder_test.go provides a minimal in-test X.509 DER builder for
// GOST-signed self-signed certificates. It is used by the test suite to
// produce parseable GOST cert DER without relying on external tools.
//
// This builder emits a minimal TBSCertificate with:
//   - Version 3
//   - A fixed serial number
//   - The specified signature algorithm OID
//   - Subject/Issuer both set to CN=test
//   - A fixed validity window
//   - SubjectPublicKeyInfo for GOST with the supplied curve OID and public key
//   - No extensions
//
// The outer Certificate is then signed using the supplied private key.
//
// Approximate LOC: ~200.

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	gost "github.com/bigbes/gostcrypto"
)

// buildParams holds parameters for building a minimal test certificate.
type buildParams struct {
	// sigAlgoOID is the signature algorithm OID (placed in both the
	// TBSCertificate.SignatureAlgorithm and the outer Certificate.SignatureAlgorithm).
	sigAlgoOID asn1.ObjectIdentifier

	// pubKeyAlgoOID is placed in SubjectPublicKeyInfo.Algorithm.Algorithm.
	pubKeyAlgoOID asn1.ObjectIdentifier

	// curveOID is the curve parameter OID in SubjectPublicKeyInfo.Algorithm.Parameters.
	curveOID asn1.ObjectIdentifier

	// privRaw is the LE-encoded private key used to sign the TBSCertificate.
	privRaw []byte

	// pubRaw is the LE-encoded public key (LE(Y)||LE(X)) to embed in the SPKI.
	pubRaw []byte

	// gostAlgo determines which hash to use for signing.
	gostAlgo GOSTAlgorithm

	// notBefore / notAfter control the validity window.
	notBefore time.Time
	notAfter  time.Time

	// commonName is used for both Subject and Issuer.
	commonName string
}

// buildCertDER produces a minimal DER-encoded GOST certificate. It encodes
// the SPKI AlgorithmIdentifier parameters as a bare curve OID; real
// Tarantool-EE certs use the SEQUENCE form and are covered by the checked-in
// fixtures (testdata/certs, fixture_parse_test.go), so the two test sets
// together exercise both parameter encodings parseCurveOID accepts.
func buildCertDER(p buildParams) ([]byte, error) {
	// ── 1. Build SubjectPublicKeyInfo ────────────────────────────────────────
	// The public key bytes are wrapped in an OCTET STRING per RFC 4491 §2.1.
	pubKeyRaw := p.pubRaw // LE(Y)||LE(X).

	// Encode raw public key as an OCTET STRING.
	pubKeyOctetString, err := asn1.Marshal(pubKeyRaw)
	if err != nil {
		return nil, err
	}

	// Encode curve OID as a bare OID (the Parameters field of the SPKI
	// AlgorithmIdentifier). Some GOST implementations use a bare OID here.
	curveOIDRaw, err := asn1.Marshal(p.curveOID)
	if err != nil {
		return nil, err
	}

	spki, err := asn1.Marshal(subjectPublicKeyInfoForBuild{
		Algorithm: algorithmIdentifierForBuild{
			Algorithm:  p.pubKeyAlgoOID,
			Parameters: asn1.RawValue{FullBytes: curveOIDRaw},
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyOctetString,
			BitLength: len(pubKeyOctetString) * 8,
		},
	})
	if err != nil {
		return nil, err
	}

	// ── 2. Build Subject / Issuer (both = CN=test) ───────────────────────────
	// RDN = SEQUENCE { SET { SEQUENCE { OID(2.5.4.3), UTF8String(commonName) } } }.
	cnOID := asn1.ObjectIdentifier{2, 5, 4, 3}

	rdnAttr, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}{cnOID, p.commonName})
	if err != nil {
		return nil, err
	}

	rdnSet, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      rdnAttr,
	})
	if err != nil {
		return nil, err
	}

	rdnSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rdnSet,
	})
	if err != nil {
		return nil, err
	}

	// ── 3. Build Validity ─────────────────────────────────────────────────────.
	validity, err := asn1.Marshal(struct {
		NotBefore time.Time
		NotAfter  time.Time
	}{p.notBefore.UTC(), p.notAfter.UTC()})
	if err != nil {
		return nil, err
	}

	// ── 4. Build AlgorithmIdentifier for signature (outer + TBS) ─────────────
	// For GOST signature OIDs we use an absent parameters field (NULL is not
	// applicable). Some implementations encode NULL; we omit it.
	sigAlgoRaw, err := asn1.Marshal(struct {
		Algorithm asn1.ObjectIdentifier
	}{p.sigAlgoOID})
	if err != nil {
		return nil, err
	}

	// ── 5. Build TBSCertificate ───────────────────────────────────────────────.
	serialNumber := big.NewInt(1)

	serialBytes, err := asn1.Marshal(serialNumber)
	if err != nil {
		return nil, err
	}

	// version [0] EXPLICIT INTEGER := 2 (version 3).
	versionBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      []byte{0x02, 0x01, 0x02}, // INTEGER 2.
	})
	if err != nil {
		return nil, err
	}

	tbsBody := concatBytes(
		versionBytes,
		serialBytes,
		sigAlgoRaw,
		rdnSeq, // issuer.
		validity,
		rdnSeq, // subject (same as issuer for self-signed).
		spki,
	)

	tbsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	})
	if err != nil {
		return nil, err
	}

	// ── 6. Sign the TBSCertificate ────────────────────────────────────────────.
	digest, err := hashForSign(p.gostAlgo, tbsDER)
	if err != nil {
		return nil, err
	}

	curve, err := gost.CurveByOID(p.curveOID)
	if err != nil {
		return nil, err
	}

	sig, err := gost.SignDigestOnCurve(curve, p.privRaw, digest, rand.Reader)
	if err != nil {
		return nil, err
	}

	// Encode signature as a BIT STRING.
	sigBitString := asn1.BitString{
		Bytes:     sig,
		BitLength: len(sig) * 8,
	}

	// ── 7. Assemble the outer Certificate SEQUENCE ────────────────────────────.
	certBody := concatBytes(tbsDER, sigAlgoRaw)

	sigBitStringDER, err := asn1.Marshal(sigBitString)
	if err != nil {
		return nil, err
	}

	certBody = append(certBody, sigBitStringDER...)

	certDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certBody,
	})
	if err != nil {
		return nil, err
	}

	return certDER, nil
}

// hashForSign hashes data with the hash algorithm implied by algo.
func hashForSign(algo GOSTAlgorithm, data []byte) ([]byte, error) {
	var h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}

	switch algo {
	case AlgoR341001:
		h = gost.NewGOSTR341194CryptoProHash()
	case AlgoR341012_256:
		h = gost.NewStreebog256Hash()
	case AlgoR341012_512:
		h = gost.NewStreebog512Hash()
	default:
		return nil, fmt.Errorf("unknown algo %d", int(algo))
	}

	_, _ = h.Write(data)

	return h.Sum(nil), nil
}

// concatBytes concatenates byte slices.
func concatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}

	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}

	return out
}

// buildTestKeypair256 generates a fresh GOST R 34.10-2012 256-bit keypair
// using the CryptoPro-A parameter set (OIDParamCryptoProA / tc26-256-paramSetB).
func buildTestKeypair256() (privRaw, pubRaw []byte, err error) {
	return gost.GenerateEphemeralKey(gost.GOST2001CryptoProAParamSetCurve(), rand.Reader)
}

// buildTestKeypair2001 generates a fresh GOST R 34.10-2001 keypair using
// the CryptoPro-A parameter set.
func buildTestKeypair2001() (privRaw, pubRaw []byte, err error) {
	// 2001 keys use the same curve family as 2012-256.
	return buildTestKeypair256()
}

// algorithmIdentifierForBuild is used only in buildCertDER.
type algorithmIdentifierForBuild struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// subjectPublicKeyInfoForBuild is used only in buildCertDER.
type subjectPublicKeyInfoForBuild struct {
	Algorithm algorithmIdentifierForBuild
	PublicKey asn1.BitString
}

// validityWindow returns a validity window: [now-1h, now+1year].
func validityWindow() (time.Time, time.Time) {
	now := time.Now().UTC()
	return now.Add(-time.Hour), now.Add(365 * 24 * time.Hour)
}

// expiredValidityWindow returns a validity window entirely in the past.
func expiredValidityWindow() (time.Time, time.Time) {
	past := time.Now().UTC().Add(-48 * time.Hour)
	return past.Add(-24 * time.Hour), past
}
