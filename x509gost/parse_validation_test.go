package x509gost //nolint:testpackage // white-box: tests unexported extractGOSTPubKeyBytes + sentinel errors

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// TestExtractGOSTPubKeyBytes_LengthValidation pins X509-69: extractGOSTPubKeyBytes
// must reject keys that are not exactly 2*pointSize bytes, in both the
// OCTET-STRING and raw branches, and must not silently mis-parse a raw key whose
// leading bytes look like an OCTET STRING header.
func TestExtractGOSTPubKeyBytes_LengthValidation(t *testing.T) {
	t.Parallel()

	const wantLen = 64 // 256-bit key.

	// A well-formed 64-byte raw key wrapped in an OCTET STRING parses fine.
	good := make([]byte, wantLen)
	for i := range good {
		good[i] = byte(i + 1)
	}

	wrapped, err := asn1.Marshal(good)
	if err != nil {
		t.Fatalf("marshal OCTET STRING: %v", err)
	}

	got, err := extractGOSTPubKeyBytes(wrapped, wantLen)
	if err != nil {
		t.Fatalf("extractGOSTPubKeyBytes(wrapped 64): %v", err)
	}

	if len(got) != wantLen || string(got) != string(good) {
		t.Fatalf("wrapped 64-byte key not round-tripped")
	}

	// Raw 64-byte key (no OCTET STRING wrapper) is accepted.
	raw64 := make([]byte, wantLen)
	for i := range raw64 {
		raw64[i] = 0xAB
	}

	got, err = extractGOSTPubKeyBytes(raw64, wantLen)
	if err != nil {
		t.Fatalf("extractGOSTPubKeyBytes(raw 64): %v", err)
	}

	if len(got) != wantLen {
		t.Fatalf("raw 64-byte key length = %d, want %d", len(got), wantLen)
	}

	// Negative cases: wrong lengths must be rejected.
	bad := []struct {
		name  string
		input []byte
	}{
		{"raw-63", make([]byte, 63)},
		{"raw-1", make([]byte, 1)},
		{"raw-65", make([]byte, 65)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := extractGOSTPubKeyBytes(tc.input, wantLen); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestExtractGOSTPubKeyBytes_RawWithOctetHeader pins the disambiguation half of
// X509-69: a raw 64-byte key whose first two bytes form a plausible OCTET STRING
// header (0x04, len==62) must NOT be silently mis-parsed into the 62-byte inner
// value — because 62 != wantLen the wrapped parse is rejected and the bytes are
// taken raw (and then rejected for length, since a genuine raw key is 64 bytes
// and this crafted one is too). The point is that the 62-byte mis-parse never
// silently wins.
func TestExtractGOSTPubKeyBytes_RawWithOctetHeader(t *testing.T) {
	t.Parallel()

	const wantLen = 64

	// 0x04 0x3E (len=62) followed by 62 bytes => total 64. Under the old
	// "OCTET STRING first" logic this parsed to a 62-byte key.
	crafted := make([]byte, wantLen)

	crafted[0] = 0x04
	crafted[1] = 0x3E

	for i := 2; i < wantLen; i++ {
		crafted[i] = byte(i)
	}

	got, err := extractGOSTPubKeyBytes(crafted, wantLen)
	// The wrapped parse yields a 62-byte inner value (!= wantLen) so it is
	// rejected; the raw branch then accepts the full 64 bytes.
	if err != nil {
		t.Fatalf("crafted 64-byte key rejected: %v", err)
	}

	if len(got) != wantLen {
		t.Fatalf("crafted key mis-parsed to %d bytes, want %d (the 2^-16 misparse)", len(got), wantLen)
	}
}

// TestParseCertificate_SigGOSTButPubKeyNotGOST pins errSigGOSTButPubKeyNotGOST
// (X509-71 #5): a structurally valid cert with a GOST signature OID but a
// (valid, RSA) non-GOST SPKI is rejected by our extra check — after the stdlib
// parse succeeds. We assemble such a cert from a real RSA SPKI plus a GOST
// signature OID; ParseCertificate must surface errSigGOSTButPubKeyNotGOST, not
// a stdlib error.
func TestParseCertificate_SigGOSTButPubKeyNotGOST(t *testing.T) {
	t.Parallel()

	// Real RSA SPKI so the stdlib parser accepts the key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	der := buildCertWithSPKIAndSigOID(t, spkiDER, OIDSignatureGOSTR341012_256)

	// Sanity: stdlib alone parses it (the structure is valid; only the GOST
	// sig algo is unknown to stdlib).
	if _, serr := x509.ParseCertificate(der); serr != nil {
		t.Fatalf("precondition: stdlib must parse the spliced cert, got: %v", serr)
	}

	_, err = ParseCertificate(der)
	if err == nil {
		t.Fatal("expected errSigGOSTButPubKeyNotGOST, got nil")
	}

	if !errors.Is(err, errSigGOSTButPubKeyNotGOST) {
		t.Fatalf("error = %v, want errSigGOSTButPubKeyNotGOST", err)
	}
}

// buildCertWithSPKIAndSigOID assembles a minimal v3 certificate DER carrying the
// given (pre-encoded) SubjectPublicKeyInfo and signature algorithm OID, with a
// dummy signature BIT STRING (ParseCertificate does not verify the signature).
func buildCertWithSPKIAndSigOID(t *testing.T, spkiDER []byte, sigOID asn1.ObjectIdentifier) []byte {
	t.Helper()

	subjectSeq, err := buildRDN("sig-gost-pub-rsa")
	if err != nil {
		t.Fatalf("buildRDN: %v", err)
	}

	notBefore, notAfter := validityWindow()

	validity, err := asn1.Marshal(struct {
		NotBefore time.Time
		NotAfter  time.Time
	}{notBefore.UTC(), notAfter.UTC()})
	if err != nil {
		t.Fatalf("marshal validity: %v", err)
	}

	sigAlgoRaw, err := asn1.Marshal(struct{ Algorithm asn1.ObjectIdentifier }{sigOID})
	if err != nil {
		t.Fatalf("marshal sigAlgo: %v", err)
	}

	serialBytes, err := asn1.Marshal(big.NewInt(1))
	if err != nil {
		t.Fatalf("marshal serial: %v", err)
	}

	versionBytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      []byte{0x02, 0x01, 0x02}, // INTEGER 2 (v3).
	})
	if err != nil {
		t.Fatalf("marshal version: %v", err)
	}

	tbsBody := concatBytes(
		versionBytes,
		serialBytes,
		sigAlgoRaw,
		subjectSeq, // issuer.
		validity,
		subjectSeq, // subject.
		spkiDER,
	)

	tbsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	})
	if err != nil {
		t.Fatalf("marshal tbs: %v", err)
	}

	dummySig := asn1.BitString{Bytes: make([]byte, 64), BitLength: 64 * 8}

	sigBitStringDER, err := asn1.Marshal(dummySig)
	if err != nil {
		t.Fatalf("marshal sig bitstring: %v", err)
	}

	certBody := concatBytes(tbsDER, sigAlgoRaw, sigBitStringDER)

	certDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certBody,
	})
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}

	return certDER
}
