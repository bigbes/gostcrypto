package gost28147cnt_test

// engine_vector_test.go pins the GOST 28147-89 CNT keystream against a
// 4096-byte fixture produced by gost-engine 3.0.3 (CryptoPro-A S-box).

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147cnt"
)

// TestCNT_Engine4K_CarryAndMeshing loads the pre-generated 4096-byte
// keystream fixture and asserts that the clean-room CNT reproduces it
// exactly, both one-shot and in a split-write variant.
//
// Fixture provenance (gost28147cnt/testdata/engine-cnt-cryptoproa-4096.hex):
//
//	key = 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
//	iv  = 0102030405060708
//	S-box: CryptoPro-A
//	OPENSSL_CONF=/opt/homebrew/etc/gost/gost-engine.cnf \
//	  /opt/homebrew/opt/openssl@3/bin/openssl enc -gost89-cnt -nopad \
//	  -K <key> -iv <iv> -in zeros4096.bin    # gost-engine 3.0.3
//
// It was cross-checked byte-for-byte (4096/4096) against this module's
// NewCNT(NewCipher(key, SboxCryptoProA), iv).XORKeyStream on 2026-06-10.
//
// Coverage argument: the counter's upper word increases by C1=0x01010104 per
// block with end-around carry, so a carry occurs at least once every
// ⌈2³²/C1⌉ ≈ 256 blocks; 512 blocks (4096 bytes / 8 bytes per block) therefore
// force ≥1 carry (typically 2) regardless of starting state, and the stream
// crosses the 1024-byte CryptoPro meshing boundary 3 times. A mutation that
// deletes or breaks the carry (e.g. `hi++` → no-op, or `>` → `>=`) would
// diverge from the ground truth before block 256 and fail this test.
func TestCNT_Engine4K_CarryAndMeshing(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "0102030405060708")

	want := loadHexFixture(t, "testdata/engine-cnt-cryptoproa-4096.hex")
	if len(want) != 4096 {
		t.Fatalf("fixture length = %d, want 4096", len(want))
	}

	sbox := gost28147.SboxCryptoProA

	// One-shot: XOR 4096 zero bytes and compare.
	t.Run("one-shot", func(t *testing.T) {
		t.Parallel()

		got := make([]byte, 4096)
		gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv).XORKeyStream(got, got)

		if !bytes.Equal(got, want) {
			t.Errorf("one-shot mismatch at first diff offset %d", firstDiff(got, want))
		}
	})

	// Split-write: chunks of 1000 / 96 / 3000 bytes.
	t.Run("split-1000-96-3000", func(t *testing.T) {
		t.Parallel()

		got := make([]byte, 4096)
		s := gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv)
		s.XORKeyStream(got[0:1000], got[0:1000])
		s.XORKeyStream(got[1000:1096], got[1000:1096])
		s.XORKeyStream(got[1096:4096], got[1096:4096])

		if !bytes.Equal(got, want) {
			t.Errorf("split mismatch at first diff offset %d", firstDiff(got, want))
		}
	})
}

// loadHexFixture reads a file of hex lines (no separators within a line,
// one '\n' per line) and returns the decoded bytes.
func loadHexFixture(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	var buf []byte

	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		b, err := hex.DecodeString(line)
		if err != nil {
			t.Fatalf("decode hex line %q: %v", line, err)
		}

		buf = append(buf, b...)
	}

	return buf
}

// firstDiff returns the index of the first differing byte between a and b.
func firstDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}

	return len(a)
}
