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

// TestSeqMACBlock_GuideStep1KAT pins the raw 16-round chaining state (before
// finalization) for a single block (GOST-15). The values are deliberately
// different from the finalized IMIT tags because finalization for a
// single-block (8-byte) input appends a trailing all-zero block per §2.1
// rule 3 / D5:
//
//   - CryptoPro-A: SeqMACBlock("12345670") = 832e9da41b6e6d6b
//     (guide §"Re-implementation checklist" step 1; verified empirically
//     against the clean-room macBlock, 2026-06-10)
//   - tc26-Z: SeqMACBlock("12345670") = 611451608741d776
//     (computed by the same code path after confirming the CryptoPro-A
//     value matches the guide; the two differ only in the S-box applied by t())
//
// Contrast with the finalized IMIT for "12345670": ac2b5ad6… (CryptoPro-A,
// V3 in TestIMIT_GuideVectors) — the trailing zero block changes the state.
//
// This test is intentionally white-box (same package) to call SeqMACBlock
// and directly compare the raw chaining state. A regression that silently
// folds in finalization (e.g. by reusing imit() inside SeqMACBlock) would
// pass every existing IMIT test while corrupting every GOST-CNT TLS record MAC.
func TestSeqMACBlock_GuideStep1KAT(t *testing.T) {
	t.Parallel()

	key := imitKey // "0123456789abcdef0123456789abcdef" ASCII, 32 bytes
	block := []byte("12345670")

	cases := []struct {
		name string
		sbox gost28147.SBox
		want string // raw 8-byte chaining state, hex
	}{
		// guide §"Re-implementation checklist" step 1; verified 2026-06-10.
		{"CryptoPro-A", gost28147.SboxCryptoProA, "832e9da41b6e6d6b"},
		// computed from the clean-room implementation, 2026-06-10.
		{"tc26-Z", gost28147.SboxTC26Z, "611451608741d776"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want)
			got := SeqMACBlock(key, tc.sbox, block)

			if !bytes.Equal(got, want) {
				t.Fatalf("SeqMACBlock(%s, %q) = %x, want %s", tc.name, block, got, tc.want)
			}
		})
	}
}

// TestSeqMACBlock_StreamingMatchesIMIT verifies that driving the same messages
// block-by-block through SeqMACBlock with the guide's §2.1 buffering rules
// (defer the trailing 1–8 bytes; fire the trailing-zero-block rule when the
// whole message fits in one block) produces the same 4-byte tag as the
// one-shot IMIT (GOST-15). This pins that SeqMACBlock chaining composes to
// the same MAC — exactly how gostls uses it.
//
// Chaining semantics: SeqMACBlock(key, sbox, block) computes MACBLOCK(block)
// starting from a zero state. To chain, the caller XORs the previous MAC
// state into the incoming block before passing it to SeqMACBlock — i.e.
//
//	prev = SeqMACBlock(key, sbox, XOR(prev, plaintext))
//
// This mirrors gostls/internal/record/protection_gost.go:195-203:
//
//	for i := range gostBlockSize { xored[i] = m.prev[i] ^ block[i] }
//	m.prev = m.macBlockEncrypt(m.cipher, xored)
//
// Buffering rule: process blocks while more than 8 bytes remain (strict "> 8",
// matching gost-engine's gost_imit_update at tmp/engine/gost_crypt.c:1547).
func TestSeqMACBlock_StreamingMatchesIMIT(t *testing.T) {
	t.Parallel()

	key := imitKey
	sbox := gost28147.SboxCryptoProA

	cases := []struct {
		name string
		msg  []byte
		want string // 4-byte TLS-truncated IMIT, hex (matches TestIMIT_GuideVectors)
	}{
		// All four V3/V1 vectors. Sources: tmp/engine/test/02-mac.t:158-173
		// (key "0123456789abcdef" x 2 ASCII; message = "12345670" x 128).
		{"V3_partial_5B", []byte("12345"), "77a62d81"},
		{"V3_one_block_8B", []byte("12345670"), "ac2b5ad6"},
		{"V3_two_blocks_16B", []byte("1234567012345670"), "7862d83a"},
		{"V1_1024B_no_mesh", []byte(strings.Repeat("12345670", 128)), "2ee8d13d"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want)

			// Streaming driver mirroring guide §2.1 buffering and gostls
			// chaining semantics.
			var prev [blockSize]byte // chaining state, starts all-zero
			count := 0

			processBlock := func(blk [blockSize]byte) {
				// XOR prev state into the block (CBC-MAC chaining), then run
				// 16-round SeqMAC from zero state. SeqMACBlock(xored) =
				// MACBLOCK(0 XOR xored) = MACBLOCK(prev XOR block).
				var xored [blockSize]byte
				for i := range blockSize {
					xored[i] = prev[i] ^ blk[i]
				}
				result := SeqMACBlock(key, sbox, xored[:])
				copy(prev[:], result)
				count = count%meshPeriod + blockSize
			}

			msg := tc.msg
			i := 0
			// Process all blocks except the last 1–8 bytes (strict "> 8").
			for len(msg)-i > blockSize {
				var blk [blockSize]byte
				copy(blk[:], msg[i:i+blockSize])
				processBlock(blk)
				i += blockSize
			}

			// Remaining bytes (1–8) form the deferred trailing block.
			rem := msg[i:]
			var blk [blockSize]byte
			copy(blk[:], rem) // zero-padded for partial blocks

			dataCountWasZero := (count == 0)
			processBlock(blk)

			// §2.1 rule 3: total length 1–8, append trailing all-zero block.
			if dataCountWasZero {
				processBlock([blockSize]byte{})
			}

			// The tag is the leading 4 bytes of the chaining state.
			got := prev[:tlsTagLen]

			if !bytes.Equal(got, want) {
				t.Fatalf("streaming SeqMACBlock(%s) = %x, want %s", tc.name, got, tc.want)
			}

			// Sanity: must also agree with the one-shot IMIT.
			ref := IMIT(key, tc.msg)
			if !bytes.Equal(got, ref) {
				t.Fatalf("streaming %x != one-shot IMIT %x (%s)", got, ref, tc.name)
			}
		})
	}
}

// TestIMIT_TC26Z_1024B_Meshing ports the engine's gost-mac-12 vector
// (GOST-16): tc26-Z S-box + CryptoPro key meshing over 1024 bytes.
// Source: tmp/engine/test/02-mac.t:190-194 (key "0123456789abcdef" x 2 ASCII,
// message = "12345670" x 128 = 1024 bytes, paramset tc26-Z = gost-mac-12).
// Full 8-byte tag: be4453ec1ec327be; 4-byte prefix: be4453ec.
//
// This is the only tc26-Z + meshing coverage point in the module. The sbox-
// parameterized internal imit() is the designed reference for both paramsets;
// tc26-Z meshing exercised here catches bugs in mesh()'s cipher re-keying when
// the S-box is not CryptoPro-A.
func TestIMIT_TC26Z_1024B_Meshing(t *testing.T) {
	t.Parallel()

	key := imitKey
	msg := []byte(strings.Repeat("12345670", 128)) // 1024 bytes

	// Full 8-byte tag via internal imit() with tc26-Z S-box.
	// Source: tmp/engine/test/02-mac.t:190-194 (gost-mac-12, testdata.dat).
	wantFull := mustHex(t, "be4453ec1ec327be")
	wantTLS := wantFull[:4] // "be4453ec" — the 4-byte TLS-truncated tag.

	got := imit(key, msg, gost28147.SboxTC26Z)

	if !bytes.Equal(got, wantFull) {
		t.Fatalf("imit(tc26-Z, 1024B) = %x, want %x", got, wantFull)
	}

	if !bytes.Equal(got[:4], wantTLS) {
		t.Fatalf("imit(tc26-Z, 1024B)[:4] = %x, want %x", got[:4], wantTLS)
	}
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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want)
			full := imit(keyASCII, tc.msg, tc.sbox)

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
