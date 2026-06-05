package omac_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	"github.com/bigbes/gostcrypto/omac"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}

	return b
}

// TestOMAC_Kuznyechik_EngineOracleKAT pins the guide's full-width 16-byte
// Kuznyechik OMAC vector (key 0xAA*32, msg "hello"). Because "hello" is
// shorter than a block, this exercises the K2/padding branch end-to-end.
// omac.md "Inline verified Kuznyechik OMAC KAT".
func TestOMAC_Kuznyechik_EngineOracleKAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	want := mustHex(t, "96e6c1913fd788e3922e617fdd341edf")

	m := omac.New(kuznyechik.NewCipher(key), 16)

	_, _ = m.Write([]byte("hello"))

	got := m.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

// TestOMAC_Kuznyechik_KAT pins GOST R 34.13-2015 A.1.6 (truncated to 8).
// P is a multiple of the block size -> K1 (complete-block) path.
func TestOMAC_Kuznyechik_KAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	p := mustHex(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011")
	want := mustHex(t, "336f4d296059fbe3")

	m := omac.New(kuznyechik.NewCipher(key), 8)

	_, _ = m.Write(p)

	got := m.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

// TestOMAC_Magma_KAT pins GOST R 34.13-2015 A.2.6 (truncated to 4).
// P is a multiple of 8 -> K1 path.
func TestOMAC_Magma_KAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	p := mustHex(t, "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")
	want := mustHex(t, "154e7210")

	m := omac.New(magma.NewCipher(key), 4)

	_, _ = m.Write(p)

	got := m.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

// TestOMAC_EngineTclVectors ports the gost-engine tcl `dgst -mac` OMAC
// vectors from tmp/engine/tcl_tests/mac.try. Keys are given as `-macopt
// hexkey:...` (hex-decoded, unlike `key:` which is raw ASCII). Inputs are the
// binary etalon files tmp/engine/tcl_tests/mac-magma.dat (32 bytes) and
// mac-grasshopper.dat (64 bytes), inlined here in full; they are the GOST R
// 34.13-2015 A.2/A.1 example plaintexts, so these rows extend the truncated
// standard KATs above to the engine's full default tag widths (8 bytes for
// magma-mac, 16 for kuznyechik-mac).
func TestOMAC_EngineTclVectors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		block  func([]byte) cipher.Block
		key    string // hexkey: from mac.try
		msg    string // inlined data file, hex.
		want   string // full-width expected MAC, hex.
		tagLen int
		cite   string
	}{
		{
			name:  "magma-mac_mac-magma.dat",
			block: func(k []byte) cipher.Block { return magma.NewCipher(k) },
			key:   "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			msg: "92def06b3c130a59db54c704f8189d20" +
				"4a98fb2e67a8024c8912409b17b57e41",
			want:   "154e72102030c5bb",
			tagLen: 8,
			cite:   "tmp/engine/tcl_tests/mac.try:112-114",
		},
		{
			name:  "kuznyechik-mac_mac-grasshopper.dat",
			block: func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
			key:   "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
			msg: "1122334455667700ffeeddccbbaa9988" +
				"00112233445566778899aabbcceeff0a" +
				"112233445566778899aabbcceeff0a00" +
				"2233445566778899aabbcceeff0a0011",
			want:   "336f4d296059fbe34ddeb35b37749c67",
			tagLen: 16,
			cite:   "tmp/engine/tcl_tests/mac.try:117-119",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m := omac.New(tc.block(mustHex(t, tc.key)), tc.tagLen)

			_, _ = m.Write(mustHex(t, tc.msg))

			got := m.Sum(nil)
			if want := mustHex(t, tc.want); !bytes.Equal(got, want) {
				t.Fatalf("%s: got %x, want %x (%s)", tc.name, got, want, tc.cite)
			}
		})
	}
}

// TestOMAC_SumIdempotent: two Sums with no Write between are equal.
func TestOMAC_SumIdempotent(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	m := omac.New(kuznyechik.NewCipher(key), 16)

	_, _ = m.Write([]byte("the quick brown fox"))

	a := m.Sum(nil)
	b := m.Sum(nil)

	if !bytes.Equal(a, b) {
		t.Fatalf("Sum not idempotent: %x vs %x", a, b)
	}
}

// TestOMAC_SumAfterWrite: Write half1; Sum; Write half2; Sum equals a fresh
// OMAC over the concatenation. Proves Sum is non-destructive and that split
// Writes match a one-shot Write.
func TestOMAC_SumAfterWrite(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	full := mustHex(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011")

	m := omac.New(kuznyechik.NewCipher(key), 16)

	_, _ = m.Write(full[:19]) // split across a block boundary.

	_ = m.Sum(nil) // intermediate Sum must not corrupt state.
	_, _ = m.Write(full[19:])

	got := m.Sum(nil)

	ref := omac.New(kuznyechik.NewCipher(key), 16)

	_, _ = ref.Write(full)

	want := ref.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("split-write mismatch: got %x want %x", got, want)
	}
}

// TestOMAC_EmptyMessage exercises the empty-message K2 path (pad = 0x80
// at index 0). We just assert it does not panic and is stable.
func TestOMAC_EmptyMessage(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	m := omac.New(kuznyechik.NewCipher(key), 16)
	a := m.Sum(nil)
	b := m.Sum(nil)

	if !bytes.Equal(a, b) || len(a) != 16 {
		t.Fatalf("empty-message tag unstable: %x vs %x", a, b)
	}
}
