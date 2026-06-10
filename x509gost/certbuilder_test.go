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

	// privRaw is the LE-encoded private key whose curve is curveOID. When no
	// distinct signer is configured (signerPriv == nil) it both backs the
	// embedded SPKI and signs the TBSCertificate (self-signed cert).
	privRaw []byte

	// pubRaw is the raw public key (LE(X)||LE(Y)) to embed in the SPKI.
	pubRaw []byte

	// gostAlgo determines which hash to use for signing (the digest implied by
	// sigAlgoOID). For a CA-signed leaf this is the CA's signature digest, not
	// the leaf key's strength.
	gostAlgo GOSTAlgorithm

	// notBefore / notAfter control the validity window.
	notBefore time.Time
	notAfter  time.Time

	// commonName is the Subject CN. It is also the Issuer CN unless issuerCN
	// is set.
	commonName string

	// issuerCN, when non-empty, overrides the Issuer CN (for CA-signed certs
	// where issuer != subject).
	issuerCN string

	// signerPriv / signerCurveOID, when set, sign the TBSCertificate with a
	// distinct CA key on signerCurveOID instead of privRaw/curveOID. This
	// produces a depth-1 (CA-signed) leaf rather than a self-signed cert.
	signerPriv     []byte
	signerCurveOID asn1.ObjectIdentifier

	// extensionsDER, when non-empty, is the pre-encoded [3] EXPLICIT
	// Extensions field appended to the TBSCertificate (e.g. EKU,
	// BasicConstraints). Build it with buildExtensionsDER.
	extensionsDER []byte
}

// buildCertDER produces a minimal DER-encoded GOST certificate. It encodes
// the SPKI AlgorithmIdentifier parameters as a bare curve OID; real
// Tarantool-EE certs use the SEQUENCE form and are covered by the checked-in
// fixtures (testdata/certs, fixture_parse_test.go), so the two test sets
// together exercise both parameter encodings parseCurveOID accepts.
func buildCertDER(p buildParams) ([]byte, error) {
	// ── 1. Build SubjectPublicKeyInfo ────────────────────────────────────────
	// The public key bytes are wrapped in an OCTET STRING per RFC 4491 §2.1.
	pubKeyRaw := p.pubRaw // LE(X)||LE(Y).

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

	// ── 2. Build Subject / Issuer ────────────────────────────────────────────
	// Subject = CN=commonName. Issuer = CN=issuerCN if set, else commonName
	// (self-signed).
	subjectSeq, err := buildRDN(p.commonName)
	if err != nil {
		return nil, err
	}

	issuerCN := p.issuerCN
	if issuerCN == "" {
		issuerCN = p.commonName
	}

	issuerSeq, err := buildRDN(issuerCN)
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
		issuerSeq,
		validity,
		subjectSeq,
		spki,
	)

	// Optional extensions: [3] EXPLICIT Extensions.
	if len(p.extensionsDER) > 0 {
		tbsBody = append(tbsBody, p.extensionsDER...)
	}

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
	// Sign with the configured CA key (signerPriv/signerCurveOID) when present,
	// otherwise self-sign with privRaw/curveOID.
	signPriv := p.privRaw
	signCurveOID := p.curveOID

	if p.signerPriv != nil {
		signPriv = p.signerPriv
		signCurveOID = p.signerCurveOID
	}

	digest, err := hashForSign(p.gostAlgo, tbsDER)
	if err != nil {
		return nil, err
	}

	curve, err := gost.CurveByOID(signCurveOID)
	if err != nil {
		return nil, err
	}

	sig, err := gost.SignDigestOnCurve(curve, signPriv, digest, rand.Reader)
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

// hashForSign hashes data with the hash algorithm implied by algo and returns
// the digest in the little-endian byte order the GOST signing/verification math
// consumes (gost.SignDigestOnCurve / VerifyDigestOnCurve read the digest as the
// big-endian integer "alpha"; the natural hash.Sum output is the reverse). This
// matches what OpenSSL+gost-engine puts on the wire — confirmed by
// TestVerify_GOST_ExternalFixture — so certs built here verify under the same
// digest convention as externally-produced certs.
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

	digest := h.Sum(nil)

	digestLE := make([]byte, len(digest))
	for i := range digest {
		digestLE[len(digest)-1-i] = digest[i]
	}

	return digestLE, nil
}

// buildRDN encodes a Name with a single CN attribute:
// SEQUENCE { SET { SEQUENCE { OID(2.5.4.3), UTF8String(cn) } } }.
func buildRDN(cn string) ([]byte, error) {
	cnOID := asn1.ObjectIdentifier{2, 5, 4, 3}

	rdnAttr, err := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value string `asn1:"utf8"`
	}{cnOID, cn})
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

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rdnSet,
	})
}

// extensionParams describes the X.509 v3 extensions to embed in a test cert.
type extensionParams struct {
	// isCA, when set, emits a critical BasicConstraints extension with the
	// given CA flag.
	setBasicConstraints bool
	isCA                bool

	// keyUsageCertSign, when set, emits a KeyUsage extension asserting
	// keyCertSign (bit 5).
	keyUsageCertSign bool

	// ekuOIDs, when non-empty, emits an ExtKeyUsage extension listing them.
	ekuOIDs []asn1.ObjectIdentifier
}

// buildExtensionsDER builds the [3] EXPLICIT Extensions field for a
// TBSCertificate from the given params. Returns nil if no extension is set.
func buildExtensionsDER(p extensionParams) ([]byte, error) {
	var extns [][]byte

	if p.setBasicConstraints {
		bcVal, err := asn1.Marshal(struct {
			CA bool `asn1:"optional"`
		}{p.isCA})
		if err != nil {
			return nil, err
		}

		ext, err := marshalExtension(asn1.ObjectIdentifier{2, 5, 29, 19}, true, bcVal)
		if err != nil {
			return nil, err
		}

		extns = append(extns, ext)
	}

	if p.keyUsageCertSign {
		// KeyUsage BIT STRING with bit 5 (keyCertSign) set.
		ku := asn1.BitString{Bytes: []byte{0x04}, BitLength: 6}

		kuVal, err := asn1.Marshal(ku)
		if err != nil {
			return nil, err
		}

		ext, err := marshalExtension(asn1.ObjectIdentifier{2, 5, 29, 15}, true, kuVal)
		if err != nil {
			return nil, err
		}

		extns = append(extns, ext)
	}

	if len(p.ekuOIDs) > 0 {
		ekuVal, err := asn1.Marshal(p.ekuOIDs)
		if err != nil {
			return nil, err
		}

		ext, err := marshalExtension(asn1.ObjectIdentifier{2, 5, 29, 37}, false, ekuVal)
		if err != nil {
			return nil, err
		}

		extns = append(extns, ext)
	}

	if len(extns) == 0 {
		return nil, nil
	}

	// Extensions ::= SEQUENCE OF Extension.
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(extns...),
	})
	if err != nil {
		return nil, err
	}

	// [3] EXPLICIT.
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      seq,
	})
}

// marshalExtension builds one Extension: SEQUENCE { extnID OID, critical
// BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
func marshalExtension(oid asn1.ObjectIdentifier, critical bool, value []byte) ([]byte, error) {
	type extension struct {
		ID       asn1.ObjectIdentifier
		Critical bool `asn1:"optional"`
		Value    []byte
	}

	return asn1.Marshal(extension{ID: oid, Critical: critical, Value: value})
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
