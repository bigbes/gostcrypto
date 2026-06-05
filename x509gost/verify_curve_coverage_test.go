package x509gost_test

import (
	"testing"

	gost "github.com/bigbes/gostcrypto"
	"github.com/bigbes/gostcrypto/x509gost"
)

// TestCurveFromOID_FullSupportedSet asserts that every curve parameter OID
// x509gost claims to support resolves through the shared internal/gost curve
// resolver (which x509gost.Verify delegates to) and yields a curve of the
// expected coordinate size.
func TestCurveFromOID_FullSupportedSet(t *testing.T) {
	t.Parallel()

	// Coordinate size in bytes for each curve family: a 256-bit curve has
	// 32-byte coordinates, a 512-bit curve 64-byte.
	const (
		coord256 = 256 / 8
		coord512 = 512 / 8
	)

	cases := []struct {
		name      string
		curveOID  []int
		pointSize int
	}{
		{"CryptoPro-A", x509gost.OIDParamCryptoProA, coord256},
		{"CryptoPro-B", x509gost.OIDParamCryptoProB, coord256},
		{"CryptoPro-C", x509gost.OIDParamCryptoProC, coord256},
		{"TC26-256-A", x509gost.OIDParamTC26_256A, coord256},
		{"TC26-256-B", x509gost.OIDParamTC26_256B, coord256},
		{"TC26-256-C", x509gost.OIDParamTC26_256C, coord256},
		{"TC26-256-D", x509gost.OIDParamTC26_256D, coord256},
		{"TC26-512-A", x509gost.OIDParamTC26_512A, coord512},
		{"TC26-512-B", x509gost.OIDParamTC26_512B, coord512},
		{"TC26-512-C", x509gost.OIDParamTC26_512C, coord512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := gost.CurveByOID(tc.curveOID)
			if err != nil {
				t.Fatalf("CurveByOID(%v): %v", tc.curveOID, err)
			}

			if got.Name() == "" {
				t.Fatalf("CurveByOID(%v): empty curve name", tc.curveOID)
			}

			if got.PointSize() != tc.pointSize {
				t.Fatalf("CurveByOID(%v): PointSize=%d, want %d", tc.curveOID, got.PointSize(), tc.pointSize)
			}
		})
	}
}
