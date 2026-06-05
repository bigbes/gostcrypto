package gost28147imit //nolint:testpackage // white-box: tests the unexported imit and v2Message helpers

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// imitKey is the V1/V3 ASCII key; its hex form is the ASCII bytes of the
// digits (guide §"Test vectors").
var imitKey = []byte("0123456789abcdef0123456789abcdef")

// TestIMIT_GuideVectors pins the engine-validated 4-byte TLS-truncated IMIT
// tags from the guide: the short-message rows (V3, exercising the trailing
// all-zero block §2.1 rule 3 / D5), the two-block chaining row (V3), the
// 1024-byte meshing-boundary row (V1, no mesh fires), and the 266240-byte
// meshing row (V2, mesh crosses the 1024-byte boundary 260 times).
func TestIMIT_GuideVectors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		msg  []byte
		want string
	}{
		{"V3_partial_5B", []byte("12345"), "77a62d81"},
		{"V3_one_block_8B", []byte("12345670"), "ac2b5ad6"},
		{"V3_two_blocks_16B", []byte("1234567012345670"), "7862d83a"},
		{"V1_1024B_no_mesh", []byte(strings.Repeat("12345670", 128)), "2ee8d13d"},
		{"V2_266240B_mesh", v2Message(), "5efab81f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want)
			got := IMIT(imitKey, tc.msg)

			if !bytes.Equal(got, want) {
				t.Fatalf("IMIT(%s) len=%d = %x, want %s", tc.name, len(tc.msg), got, tc.want)
			}
		})
	}
}

// v2Message builds the V2 input: ("12345670" x8, then a "\n" byte) repeated
// 4096 times = 4096 * 65 = 266240 bytes.
func v2Message() []byte {
	unit := append([]byte(strings.Repeat("12345670", 8)), '\n')
	if len(unit) != 65 {
		panic("v2 unit length")
	}

	return bytes.Repeat(unit, 4096)
}

// TestIMIT_EngineTclVectors ports the gost-engine tcl `dgst -mac gost-mac`
// vectors (tmp/engine/tcl_tests/mac.try). The tcl `-macopt
// key:12345678901234567890123456789012` passes the 32 ASCII digit bytes raw
// (NOT hex-decoded); mac.try:48-50 proves it by reproducing the same tag with
// `hexkey:3132...3132`. Inputs are the generated dgst*.dat files
// (mac.try:7-14, tcl makeFile ... binary writes the string verbatim, no
// trailing newline):
//
//	dgst.dat  = "Test data to digest.\n" x 100 (2100 bytes — CryptoPro key
//	            meshing fires twice, at the 1024- and 2048-byte boundaries)
//	dgst2.dat = "1\n"
//	dgst8.dat = "1\n1\n1\n1\n"
//
// gost-mac uses the engine default paramset id-Gost28147-89-CryptoPro-A;
// gost-mac-12 uses id-tc26-gost-28147-param-Z (mac.try:68-70 shows gost-mac
// with an explicit param-Z override equals gost-mac-12). The default tag is
// the leading 4 bytes; `-sigopt size:N` (mac.try:84-106) lengthens it, so the
// 8- and 6-byte rows pin deeper prefixes of the same state.
func TestIMIT_EngineTclVectors(t *testing.T) {
	t.Parallel()

	keyASCII := []byte("12345678901234567890123456789012")
	dgst := []byte(strings.Repeat("Test data to digest.\n", 100))
	dgst2 := []byte("1\n")
	dgst8 := []byte(strings.Repeat("1\n", 4))

	cases := []struct {
		name string
		sbox gost28147.SBox
		msg  []byte
		want string // expected tag prefix, hex.
		cite string
	}{
		{"gost-mac_dgst.dat", gost28147.SboxCryptoProA, dgst, "37f646d2",
			"tmp/engine/tcl_tests/mac.try:40-42"},
		{"gost-mac_dgst2.dat", gost28147.SboxCryptoProA, dgst2, "87ea321f",
			"tmp/engine/tcl_tests/mac.try:56-58"},
		{"gost-mac_dgst8.dat_size8", gost28147.SboxCryptoProA, dgst8, "ad9aeae05a7f6f71",
			"tmp/engine/tcl_tests/mac.try:60-62 (4B) + :84-86 (size:8)"},
		{"gost-mac-12_dgst8.dat_size6", gost28147.SboxTC26Z, dgst8, "be70ba5ed6b0",
			"tmp/engine/tcl_tests/mac.try:64-66 (4B) + :88-90 (size:6)"},
	}

	var iv [8]byte

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want)
			full := imit(keyASCII, iv[:], tc.msg, tc.sbox)

			if !bytes.Equal(full[:len(want)], want) {
				t.Fatalf("%s: imit = %x, want prefix %s (%s)", tc.name, full, tc.want, tc.cite)
			}
		})
	}

	// The public TLS-truncated facade over the engine-default paramset must
	// agree with the gost-mac dgst.dat row (tmp/engine/tcl_tests/mac.try:40-42).
	if got, want := IMIT(keyASCII, dgst), mustHex(t, "37f646d2"); !bytes.Equal(got, want) {
		t.Fatalf("IMIT(dgst.dat) = %x, want %x", got, want)
	}
}
