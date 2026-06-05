package x509gost //nolint:testpackage // white-box: tests unexported parseCurveOID/extractGOSTPubKeyBytes

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"testing"

	gost "github.com/bigbes/gostcrypto"
)

var (
	oidParamTC26_256B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}
	oidParamTC26_256C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}
	oidParamTC26_256D = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}
	oidParamTC26_512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}
	oidParamTC26_512C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
)

type privateKeyInfoForTest struct {
	Version    int
	Algorithm  algorithmIdentifierForBuild
	PrivateKey []byte
}

// TestKeyEncoding_SPKI_PEM_DER_RoundTrip verifies that the SPKI convention
// this repo relies on is stable across DER and PEM round-trips for all covered
// GOST curve families.
func TestKeyEncoding_SPKI_PEM_DER_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		pubKeyOID asn1.ObjectIdentifier
		curveOID  asn1.ObjectIdentifier
	}{
		{"2001-A", OIDPublicKeyGOSTR341001, OIDParamCryptoProA},
		{"2001-B", OIDPublicKeyGOSTR341001, OIDParamCryptoProB},
		{"2001-C", OIDPublicKeyGOSTR341001, OIDParamCryptoProC},
		{"2012-256-A", OIDPublicKeyGOSTR341012_256, OIDParamTC26_256A},
		{"2012-256-B", OIDPublicKeyGOSTR341012_256, oidParamTC26_256B},
		{"2012-256-C", OIDPublicKeyGOSTR341012_256, oidParamTC26_256C},
		{"2012-256-D", OIDPublicKeyGOSTR341012_256, oidParamTC26_256D},
		{"2012-512-A", OIDPublicKeyGOSTR341012_512, OIDParamTC26_512A},
		{"2012-512-B", OIDPublicKeyGOSTR341012_512, oidParamTC26_512B},
		{"2012-512-C", OIDPublicKeyGOSTR341012_512, oidParamTC26_512C},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			curve, err := gost.CurveByOID(tc.curveOID)
			if err != nil {
				t.Fatalf("CurveByOID: %v", err)
			}

			_, pubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateEphemeralKey: %v", err)
			}

			pubOctetString, err := asn1.Marshal(pubRaw)
			if err != nil {
				t.Fatalf("marshal pub OCTET STRING: %v", err)
			}

			curveOIDRaw, err := asn1.Marshal(tc.curveOID)
			if err != nil {
				t.Fatalf("marshal curve OID: %v", err)
			}

			spkiDER, err := asn1.Marshal(subjectPublicKeyInfoForBuild{
				Algorithm: algorithmIdentifierForBuild{
					Algorithm:  tc.pubKeyOID,
					Parameters: asn1.RawValue{FullBytes: curveOIDRaw},
				},
				PublicKey: asn1.BitString{
					Bytes:     pubOctetString,
					BitLength: len(pubOctetString) * 8,
				},
			})
			if err != nil {
				t.Fatalf("marshal SPKI: %v", err)
			}

			pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})
			block, rest := pem.Decode(pemBlock)

			if block == nil || len(rest) != 0 {
				t.Fatalf("pem.Decode failed: block=%v rest=%d", block != nil, len(rest))
			}

			if block.Type != "PUBLIC KEY" {
				t.Fatalf("PEM type=%q, want PUBLIC KEY", block.Type)
			}

			var spki subjectPublicKeyInfo

			if rest, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
				t.Fatalf("asn1.Unmarshal SPKI: %v", err)
			} else if len(rest) != 0 {
				t.Fatalf("trailing SPKI bytes: %d", len(rest))
			}

			if !spki.Algorithm.Algorithm.Equal(tc.pubKeyOID) {
				t.Fatalf("SPKI algorithm OID = %v, want %v", spki.Algorithm.Algorithm, tc.pubKeyOID)
			}

			gotCurveOID, err := parseCurveOID(spki.Algorithm.Parameters)
			if err != nil {
				t.Fatalf("parseCurveOID: %v", err)
			}

			if !gotCurveOID.Equal(tc.curveOID) {
				t.Fatalf("curve OID = %v, want %v", gotCurveOID, tc.curveOID)
			}

			gotPubRaw, err := extractGOSTPubKeyBytes(spki.PublicKey.Bytes)
			if err != nil {
				t.Fatalf("extractGOSTPubKeyBytes: %v", err)
			}

			if string(gotPubRaw) != string(pubRaw) {
				t.Fatalf("public key round-trip mismatch")
			}
		})
	}
}

// TestKeyEncoding_PrivateKey_PEM_DER_RoundTrip verifies that a minimal
// PKCS#8-like PrivateKeyInfo carrying the raw LE private key bytes round-trips
// through DER and PEM for the same curve set.
func TestKeyEncoding_PrivateKey_PEM_DER_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		pubKeyOID asn1.ObjectIdentifier
		curveOID  asn1.ObjectIdentifier
	}{
		{"2001-A", OIDPublicKeyGOSTR341001, OIDParamCryptoProA},
		{"2001-B", OIDPublicKeyGOSTR341001, OIDParamCryptoProB},
		{"2001-C", OIDPublicKeyGOSTR341001, OIDParamCryptoProC},
		{"2012-256-A", OIDPublicKeyGOSTR341012_256, OIDParamTC26_256A},
		{"2012-256-B", OIDPublicKeyGOSTR341012_256, oidParamTC26_256B},
		{"2012-256-C", OIDPublicKeyGOSTR341012_256, oidParamTC26_256C},
		{"2012-256-D", OIDPublicKeyGOSTR341012_256, oidParamTC26_256D},
		{"2012-512-A", OIDPublicKeyGOSTR341012_512, OIDParamTC26_512A},
		{"2012-512-B", OIDPublicKeyGOSTR341012_512, oidParamTC26_512B},
		{"2012-512-C", OIDPublicKeyGOSTR341012_512, oidParamTC26_512C},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			curve, err := gost.CurveByOID(tc.curveOID)
			if err != nil {
				t.Fatalf("CurveByOID: %v", err)
			}

			privRaw, _, err := gost.GenerateEphemeralKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("GenerateEphemeralKey: %v", err)
			}

			curveOIDRaw, err := asn1.Marshal(tc.curveOID)
			if err != nil {
				t.Fatalf("marshal curve OID: %v", err)
			}

			der, err := asn1.Marshal(privateKeyInfoForTest{
				Version: 0,
				Algorithm: algorithmIdentifierForBuild{
					Algorithm:  tc.pubKeyOID,
					Parameters: asn1.RawValue{FullBytes: curveOIDRaw},
				},
				PrivateKey: privRaw,
			})
			if err != nil {
				t.Fatalf("marshal PrivateKeyInfo: %v", err)
			}

			pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			block, rest := pem.Decode(pemBlock)

			if block == nil || len(rest) != 0 {
				t.Fatalf("pem.Decode failed: block=%v rest=%d", block != nil, len(rest))
			}

			if block.Type != "PRIVATE KEY" {
				t.Fatalf("PEM type=%q, want PRIVATE KEY", block.Type)
			}

			var pki privateKeyInfoForTest

			if rest, err := asn1.Unmarshal(block.Bytes, &pki); err != nil {
				t.Fatalf("asn1.Unmarshal PrivateKeyInfo: %v", err)
			} else if len(rest) != 0 {
				t.Fatalf("trailing PrivateKeyInfo bytes: %d", len(rest))
			}

			if pki.Version != 0 {
				t.Fatalf("PKI version=%d, want 0", pki.Version)
			}

			if !pki.Algorithm.Algorithm.Equal(tc.pubKeyOID) {
				t.Fatalf("PrivateKeyInfo algorithm OID = %v, want %v", pki.Algorithm.Algorithm, tc.pubKeyOID)
			}

			gotCurveOID, err := parseCurveOID(pki.Algorithm.Parameters)
			if err != nil {
				t.Fatalf("parseCurveOID: %v", err)
			}

			if !gotCurveOID.Equal(tc.curveOID) {
				t.Fatalf("curve OID = %v, want %v", gotCurveOID, tc.curveOID)
			}

			if string(pki.PrivateKey) != string(privRaw) {
				t.Fatalf("private key round-trip mismatch")
			}
		})
	}
}
