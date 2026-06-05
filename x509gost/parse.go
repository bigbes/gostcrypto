package x509gost

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	errEmptyDERInput           = errors.New("x509gost: empty DER input")
	errTrailingData            = errors.New("x509gost: trailing data after certificate")
	errSigGOSTButPubKeyNotGOST = errors.New(
		"x509gost: GOST signature OID but public key OID is not a recognized GOST public key OID",
	)
	errSPKINoParameters     = errors.New("SPKI AlgorithmIdentifier has no parameters")
	errCannotParseCurveOID  = errors.New("cannot parse curve OID from SPKI parameters")
	errEmptyPubKeyBitString = errors.New("empty public key BIT STRING value")
)

// GOSTAlgorithm identifies which GOST signature family is used.
type GOSTAlgorithm int

const (
	// AlgoR341001 is GOST R 34.10-2001.
	AlgoR341001 GOSTAlgorithm = iota + 1
	// AlgoR341012_256 is GOST R 34.10-2012 with 256-bit key.
	AlgoR341012_256
	// AlgoR341012_512 is GOST R 34.10-2012 with 512-bit key.
	AlgoR341012_512
)

func (a GOSTAlgorithm) String() string {
	switch a {
	case AlgoR341001:
		return "GOST R 34.10-2001"
	case AlgoR341012_256:
		return "GOST R 34.10-2012/256"
	case AlgoR341012_512:
		return "GOST R 34.10-2012/512"
	default:
		return fmt.Sprintf("GOSTAlgorithm(%d)", int(a))
	}
}

// Certificate wraps x509.Certificate with GOST-specific fields when the
// signature algorithm is one of the GOST OIDs. Non-GOST certs parse through
// the stdlib unchanged and get stored in .Stdlib.
type Certificate struct {
	// Stdlib is always present. For GOST-signed certs it will have
	// SignatureAlgorithm == UnknownSignatureAlgorithm because the stdlib
	// cannot verify GOST signatures.
	Stdlib *x509.Certificate

	// Raw is the original DER encoding of the certificate.
	Raw []byte

	// IsGOST is true when the signature algorithm is one of the GOST OIDs.
	IsGOST bool

	// HasGOSTPubKey is true when SubjectPublicKeyInfo carries a GOST public
	// key OID — independent of signature algorithm. A cert signed with RSA
	// but carrying a GOST pubkey (common in test fixtures and in
	// deployments that use a non-GOST CA) will have IsGOST=false and
	// HasGOSTPubKey=true. The KEX path only needs HasGOSTPubKey; chain
	// verification via x509gost.Verify needs IsGOST.
	HasGOSTPubKey bool

	// GOSTAlgo identifies which GOST variant the certificate is associated
	// with, derived from the SPKI pubkey OID when present, otherwise from
	// the signature OID. Zero/undefined when both IsGOST and HasGOSTPubKey
	// are false.
	GOSTAlgo GOSTAlgorithm

	// PubKeyRaw contains the raw GOST public key bytes extracted from
	// SubjectPublicKeyInfo. The encoding is LE(Y)||LE(X) as produced by
	// gogost's PublicKey.Raw() method (little-endian X||Y with byte
	// reversal applied), confirmed against Tarantool-EE 3.5.0 GOST2001 and
	// GOST2012 server certs via TestTarantoolEE_Ping_GOST_Pure — VKO KEX
	// and cert-signature verify both succeed with bytes passed through as-is.
	PubKeyRaw []byte

	// CurveOID is the curve parameter OID extracted from the
	// AlgorithmIdentifier.Parameters of the SubjectPublicKeyInfo.
	// Zero-length when IsGOST == false or when the curve OID could not be
	// determined.
	CurveOID asn1.ObjectIdentifier

	// SPKIAlgorithmDER is the full DER encoding of the SubjectPublicKeyInfo
	// AlgorithmIdentifier SEQUENCE (pubkey algorithm OID + curve/hash
	// parameters). Callers that need to construct a new SPKI for an
	// ephemeral key on the same curve can reuse this verbatim.
	SPKIAlgorithmDER []byte
}

// tbsCertificate mirrors the ASN.1 TBSCertificate structure for
// partial parsing. We only need the fields up to SubjectPublicKeyInfo.
type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm pkixAlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          subjectPublicKeyInfo
}

type pkixAlgorithmIdentifier struct {
	Raw        asn1.RawContent
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm pkixAlgorithmIdentifier
	PublicKey asn1.BitString
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkixAlgorithmIdentifier
	Signature          asn1.BitString
}

// ParseCertificate parses a DER-encoded certificate. If the signature
// algorithm is recognized as one of the GOST OIDs, the returned Certificate
// will have IsGOST == true and the GOST-specific fields populated.
// Non-GOST certs delegate to the stdlib; GOST certs invoke the stdlib parser
// (which will leave SignatureAlgorithm = UnknownSignatureAlgorithm) and
// additionally populate the GOST fields.
//
// Returns an error if the DER is malformed.
func ParseCertificate(der []byte) (*Certificate, error) {
	if len(der) == 0 {
		return nil, errEmptyDERInput
	}

	// Always run stdlib parser — it handles SANs, validity, key usage, etc.
	// For GOST certs it will succeed but leave SignatureAlgorithm unknown.
	stdlibCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("x509gost: stdlib parse: %w", err)
	}

	rawCopy := make([]byte, len(der))
	copy(rawCopy, der)

	cert := &Certificate{
		Stdlib: stdlibCert,
		Raw:    rawCopy,
	}

	// Walk the DER to extract the signature algorithm OID.
	var outer certificate

	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, fmt.Errorf("x509gost: asn1 unmarshal: %w", err)
	}

	if len(rest) != 0 {
		return nil, fmt.Errorf("x509gost: trailing data after certificate (%d bytes): %w", len(rest), errTrailingData)
	}

	sigOID := outer.SignatureAlgorithm.Algorithm
	sigAlgo, sigIsGOST := gostAlgoFromSigOID(sigOID)

	spki := outer.TBSCertificate.PublicKey
	pkAlgOID := spki.Algorithm.Algorithm
	pkAlgo, pkIsGOST := gostAlgoFromPubKeyOID(pkAlgOID)

	if sigIsGOST && !pkIsGOST {
		return nil, fmt.Errorf(
			"x509gost: GOST signature OID %v but public key OID %v: %w",
			sigOID, pkAlgOID, errSigGOSTButPubKeyNotGOST,
		)
	}

	if !sigIsGOST && !pkIsGOST {
		// Non-GOST cert — stdlib path only.
		return cert, nil
	}

	if sigIsGOST {
		cert.IsGOST = true
	}

	if pkIsGOST {
		cert.HasGOSTPubKey = true
		cert.GOSTAlgo = pkAlgo
	} else {
		cert.GOSTAlgo = sigAlgo
	}

	// Preserve the DER of the SPKI AlgorithmIdentifier so callers can reuse
	// it when building an ephemeral SPKI on the same curve.
	cert.SPKIAlgorithmDER = append([]byte(nil), spki.Algorithm.Raw...)

	// Extract curve parameter OID from the AlgorithmIdentifier.Parameters.
	// Per RFC 4491 / RFC 7091 the parameters is a SEQUENCE containing the
	// curve OID (and optionally a digest OID); RFC 7091 §2 also permits a
	// bare OID. parseCurveOID accepts both — Tarantool-EE 3.5.0 certs use
	// the SEQUENCE form; the bare-OID branch is defensive.
	curveOID, err := parseCurveOID(spki.Algorithm.Parameters)
	if err != nil {
		return nil, fmt.Errorf("x509gost: parse curve OID from SPKI parameters: %w", err)
	}

	cert.CurveOID = curveOID

	// Extract raw public key bytes from the BIT STRING.
	// Per RFC 4491 §2.1 the BIT STRING value is an OCTET STRING containing
	// the raw key bytes; some implementations embed the bytes directly.
	// extractGOSTPubKeyBytes tries OCTET STRING first, then raw. Tarantool-EE
	// 3.5.0 uses the OCTET STRING form (confirmed end-to-end via Ping).
	pubKeyBytes, err := extractGOSTPubKeyBytes(spki.PublicKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509gost: extract GOST public key bytes: %w", err)
	}

	cert.PubKeyRaw = pubKeyBytes

	return cert, nil
}

// gostAlgoFromSigOID returns the GOSTAlgorithm and true if the OID is a known
// GOST signature algorithm OID.
func gostAlgoFromSigOID(oid asn1.ObjectIdentifier) (GOSTAlgorithm, bool) {
	switch {
	case oid.Equal(OIDSignatureGOSTR341001):
		return AlgoR341001, true
	case oid.Equal(OIDSignatureGOSTR341012_256):
		return AlgoR341012_256, true
	case oid.Equal(OIDSignatureGOSTR341012_512):
		return AlgoR341012_512, true
	}

	return 0, false
}

// gostAlgoFromPubKeyOID returns the GOSTAlgorithm implied by a GOST public
// key OID and true when the OID is recognized.
func gostAlgoFromPubKeyOID(oid asn1.ObjectIdentifier) (GOSTAlgorithm, bool) {
	switch {
	case oid.Equal(OIDPublicKeyGOSTR341001):
		return AlgoR341001, true
	case oid.Equal(OIDPublicKeyGOSTR341012_256):
		return AlgoR341012_256, true
	case oid.Equal(OIDPublicKeyGOSTR341012_512):
		return AlgoR341012_512, true
	}

	return 0, false
}

// parseCurveOID parses the curve parameter OID from the raw AlgorithmIdentifier
// Parameters field. Per RFC 4491 §2.1 the parameters contains a SEQUENCE of
// { curveOID, hashOID } (GostR3410-2001-ParamSet). Per RFC 7091 §2 it may be
// a bare OID.
//
// We try:
//  1. Unmarshal as a bare OID.
//  2. Unmarshal as a SEQUENCE { OID, ... } and take the first OID.
//
// Tarantool-EE 3.5.0 uses the SEQUENCE form (the bare-OID branch is
// defensive for other implementations).
func parseCurveOID(params asn1.RawValue) (asn1.ObjectIdentifier, error) {
	if len(params.FullBytes) == 0 && len(params.Bytes) == 0 {
		return nil, errSPKINoParameters
	}

	var oid asn1.ObjectIdentifier

	// Try bare OID first (class=Universal, tag=6).
	if params.Class == asn1.ClassUniversal && params.Tag == asn1.TagOID {
		if _, err := asn1.Unmarshal(params.FullBytes, &oid); err == nil {
			return oid, nil
		}
	}

	// Try SEQUENCE { OID, ... }.
	if params.Class == asn1.ClassUniversal && params.Tag == asn1.TagSequence {
		rest := params.Bytes

		var rest2 []byte

		rest2, err := asn1.Unmarshal(rest, &oid)

		_ = rest2

		if err == nil {
			return oid, nil
		}
	}

	return nil, fmt.Errorf("%w (tag=%d class=%d)", errCannotParseCurveOID, params.Tag, params.Class)
}

// extractGOSTPubKeyBytes extracts the raw GOST public key bytes from the
// value carried in the BIT STRING.
//
// RFC 4491 §2.1 specifies that the BIT STRING contains an OCTET STRING
// whose value is the raw key bytes. Some encodings omit the OCTET STRING
// wrapper and embed the bytes directly. Tarantool-EE 3.5.0 uses the
// OCTET STRING form (the raw-bytes fallback is defensive).
func extractGOSTPubKeyBytes(bits []byte) ([]byte, error) {
	if len(bits) == 0 {
		return nil, errEmptyPubKeyBitString
	}

	// Try to parse as OCTET STRING (tag=4).
	var inner []byte

	rest, err := asn1.Unmarshal(bits, &inner)

	if err == nil && len(rest) == 0 && len(inner) > 0 {
		return inner, nil
	}

	// Assume raw bytes directly. gogost expects 2*pointSize bytes.
	// For a 256-bit key that is 64 bytes; for 512-bit it is 128 bytes.
	// We accept any non-empty byte slice and let the caller validate length.
	rawCopy := make([]byte, len(bits))
	copy(rawCopy, bits)

	return rawCopy, nil
}
