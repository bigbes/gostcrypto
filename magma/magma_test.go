package magma //nolint:testpackage // white-box: TestSboxPermutation tests the unexported sboxTC26Z

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// TestRFC8891KAT validates the RFC 8891 Appendix A single-block vector
// (also pinned in magma-gost34122015.md §V1).
func TestRFC8891KAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := mustHex(t, "fedcba9876543210")
	want := mustHex(t, "4ee901e5c2d8ca3d")

	got := MagmaEncrypt(key, pt)
	if !bytes.Equal(got, want) {
		t.Fatalf("Encrypt = %x, want %x", got, want)
	}

	back := MagmaDecrypt(key, want)
	if !bytes.Equal(back, pt) {
		t.Fatalf("Decrypt = %x, want %x", back, pt)
	}
}

// TestECB_A21 pins the multi-block ECB sequence from GOST R 34.13-2015 §A.2.1
// (key/plaintext from §A.2). Expected ciphertext re-derived against gost-engine
// 3.0.3: openssl enc -magma-ecb -K <Km> -nopad.
func TestECB_A21(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := mustHex(t, "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")
	want := mustHex(t, "2b073f0494f372a0de70e715d3556e4811d8d9e9eacfbc1e7c68260996c67efb")

	c := NewCipher(key)
	got := make([]byte, len(pt))

	for off := 0; off < len(pt); off += BlockSize {
		c.Encrypt(got[off:off+BlockSize], pt[off:off+BlockSize])
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("ECB encrypt = %x, want %x", got, want)
	}

	back := make([]byte, len(want))
	for off := 0; off < len(want); off += BlockSize {
		c.Decrypt(back[off:off+BlockSize], want[off:off+BlockSize])
	}

	if !bytes.Equal(back, pt) {
		t.Fatalf("ECB decrypt = %x, want %x", back, pt)
	}
}

// TestRoundTrip checks Decrypt(Encrypt(p)) == p over random blocks.
func TestRoundTrip(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(1))
	key := make([]byte, KeySize)
	pt := make([]byte, BlockSize)
	ct := make([]byte, BlockSize)
	back := make([]byte, BlockSize)
	c := func(k []byte) *Cipher { return NewCipher(k) }

	for range 10000 {
		rng.Read(key)
		rng.Read(pt)

		ci := c(key)
		ci.Encrypt(ct, pt)
		ci.Decrypt(back, ct)

		if !bytes.Equal(back, pt) {
			t.Fatalf("round-trip failed: key=%x pt=%x ct=%x back=%x", key, pt, ct, back)
		}
	}
}

// TestSboxPermutation verifies each S-box row is a permutation of 0..15.
func TestSboxPermutation(t *testing.T) {
	t.Parallel()

	for i, row := range sboxTC26Z {
		var seen [16]bool

		for _, v := range row {
			if v > 15 {
				t.Fatalf("s[%d] has out-of-range value %d", i, v)
			}

			if seen[v] {
				t.Fatalf("s[%d] is not a permutation: %d repeats", i, v)
			}

			seen[v] = true
		}
	}
}
