package kuznyechik //nolint:testpackage // white-box: tests unexported s, r, l, lInv, cnst, ks

import (
	"bytes"
	"encoding/hex"
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

// TestPrimaryKAT exercises the pinned GOST R 34.12-2015 §A.1 / RFC 7801
// §5.5–5.6 test vector plus the Decrypt(Encrypt)=identity round-trip.
func TestPrimaryKAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt := mustHex(t, "1122334455667700ffeeddccbbaa9988")
	want := mustHex(t, "7f679d90bebc24305a468d42b9d4edcd")

	c := NewCipher(key)

	got := make([]byte, BlockSize)
	c.Encrypt(got, pt)

	if !bytes.Equal(got, want) {
		t.Fatalf("Encrypt: got %x want %x", got, want)
	}

	rt := make([]byte, BlockSize)
	c.Decrypt(rt, got)

	if !bytes.Equal(rt, pt) {
		t.Fatalf("Decrypt(Encrypt(p)): got %x want %x", rt, pt)
	}

	// Direct decrypt of the known ciphertext.
	dp := make([]byte, BlockSize)
	c.Decrypt(dp, want)

	if !bytes.Equal(dp, pt) {
		t.Fatalf("Decrypt: got %x want %x", dp, pt)
	}
}

// TestECB_A11 pins the 4-block ECB sequence from GOST R 34.13-2015 §A.1.1
// (key/plaintext from §A.1). Vector bytes taken verbatim from gost-engine 3.0.3
// test_ciphers.c (P / E_ecb, :74-104).
func TestECB_A11(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt := mustHex(t, "1122334455667700ffeeddccbbaa9988"+
		"00112233445566778899aabbcceeff0a"+
		"112233445566778899aabbcceeff0a00"+
		"2233445566778899aabbcceeff0a0011")
	want := mustHex(t, "7f679d90bebc24305a468d42b9d4edcd"+
		"b429912c6e0032f9285452d76718d08b"+
		"f0ca33549d247ceef3f5a5313bd4b157"+
		"d0b09ccde830b9eb3a02c4c5aa8ada98")

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

// TestStageKATs pins each transform independently against the guide's
// intermediate vectors, so a failure localizes the defective stage.
func TestStageKATs(t *testing.T) {
	t.Parallel()

	// S: one π pass.
	t.Run("S", func(t *testing.T) {
		t.Parallel()

		var blk [BlockSize]byte

		copy(blk[:], mustHex(t, "ffeeddccbbaa99881122334455667700"))
		s(&blk)

		want := mustHex(t, "b66cd8887d38e8d77765aeea0c9a7efc")
		if !bytes.Equal(blk[:], want) {
			t.Fatalf("S: got %x want %x", blk, want)
		}
	})

	// R: one LFSR step, blk[14]=0x01.
	t.Run("R", func(t *testing.T) {
		t.Parallel()

		var blk [BlockSize]byte

		blk[14] = 0x01
		r(&blk)

		want := mustHex(t, "94000000000000000000000000000001")
		if !bytes.Equal(blk[:], want) {
			t.Fatalf("R: got %x want %x", blk, want)
		}
	})

	// L = R^16.
	t.Run("L", func(t *testing.T) {
		t.Parallel()

		var blk [BlockSize]byte

		copy(blk[:], mustHex(t, "64a59400000000000000000000000000"))
		l(&blk)

		want := mustHex(t, "d456584dd0e3e84cc3166e4b7fa2890d")
		if !bytes.Equal(blk[:], want) {
			t.Fatalf("L: got %x want %x", blk, want)
		}
	})

	// Round constants C_1, C_2 (cnst[0], cnst[1]).
	t.Run("C", func(t *testing.T) {
		t.Parallel()

		c1 := mustHex(t, "6ea276726c487ab85d27bd10dd849401")
		c2 := mustHex(t, "dc87ece4d890f4b3ba4eb92079cbeb02")

		if !bytes.Equal(cnst[0][:], c1) {
			t.Fatalf("C_1: got %x want %x", cnst[0], c1)
		}

		if !bytes.Equal(cnst[1][:], c2) {
			t.Fatalf("C_2: got %x want %x", cnst[1], c2)
		}
	})

	// Round keys: K_10 (ks[9]) for the §A.1 key.
	t.Run("RoundKeys", func(t *testing.T) {
		t.Parallel()

		c := NewCipher(mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"))
		k10 := mustHex(t, "72e9dd7416bcf45b755dbaa88e4a4043")

		if !bytes.Equal(c.ks[9][:], k10) {
			t.Fatalf("K_10: got %x want %x", c.ks[9], k10)
		}
	})
}

// TestRoundTripRandom verifies L^{-1}(L(x))==x and Decrypt(Encrypt(x))==x over
// a spread of inputs without any external oracle.
func TestRoundTripRandom(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	c := NewCipher(key)

	for i := range 256 {
		var src, blk [BlockSize]byte

		for j := range src {
			src[j] = byte(i*7 + j*13)
		}

		blk = src
		l(&blk)
		lInv(&blk)

		if blk != src {
			t.Fatalf("lInv(l(x)) != x at i=%d: %x vs %x", i, blk, src)
		}

		ct := make([]byte, BlockSize)
		pt := make([]byte, BlockSize)

		c.Encrypt(ct, src[:])
		c.Decrypt(pt, ct)

		if !bytes.Equal(pt, src[:]) {
			t.Fatalf("Decrypt(Encrypt(x)) != x at i=%d", i)
		}
	}
}

func TestNewCipherPanicsOnBadKey(t *testing.T) {
	t.Parallel()

	mustPanic := func(name string, n int) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic on %d-byte key", name, n)
			}
		}()

		NewCipher(make([]byte, n))
	}

	mustPanic("short", 16)  // under 32 bytes.
	mustPanic("oversize", 33) // over 32 bytes: len(key) != keySize rejects this too.
}

// TestEncryptDecryptInPlace pins full-overlap (dst == src) aliasing for the §A.1
// vector: cipher.Block permits dst and src to overlap entirely, and in-module
// omac.go relies on Encrypt(b, b). A future table tweak writing dst incrementally
// must not break this. (KUZN-46)
func TestEncryptDecryptInPlace(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt := mustHex(t, "1122334455667700ffeeddccbbaa9988")
	ct := mustHex(t, "7f679d90bebc24305a468d42b9d4edcd")

	c := NewCipher(key)

	enc := append([]byte(nil), pt...)
	c.Encrypt(enc, enc)

	if !bytes.Equal(enc, ct) {
		t.Fatalf("in-place Encrypt: got %x want %x", enc, ct)
	}

	dec := append([]byte(nil), ct...)
	c.Decrypt(dec, dec)

	if !bytes.Equal(dec, pt) {
		t.Fatalf("in-place Decrypt: got %x want %x", dec, pt)
	}
}

// TestNewCipherCopiesKey pins that NewCipher does not retain the caller's key
// slice: zeroing the key after construction must not change ciphertext. (KUZN-47)
func TestNewCipherCopiesKey(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt := mustHex(t, "1122334455667700ffeeddccbbaa9988")
	want := mustHex(t, "7f679d90bebc24305a468d42b9d4edcd")

	c := NewCipher(key)

	for i := range key {
		key[i] = 0
	}

	got := make([]byte, BlockSize)
	c.Encrypt(got, pt)

	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext changed after zeroing caller key: got %x want %x", got, want)
	}
}

// BenchmarkEncrypt measures single-block throughput of the table-driven path.
func BenchmarkEncrypt(b *testing.B) {
	key := mustHexB(b, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	c := NewCipher(key)
	src := mustHexB(b, "1122334455667700ffeeddccbbaa9988")
	dst := make([]byte, BlockSize)

	b.SetBytes(BlockSize)
	b.ResetTimer()

	for range b.N {
		c.Encrypt(dst, src)
	}
}

// BenchmarkDecrypt mirrors BenchmarkEncrypt for the inverse path.
func BenchmarkDecrypt(b *testing.B) {
	key := mustHexB(b, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	c := NewCipher(key)
	src := mustHexB(b, "7f679d90bebc24305a468d42b9d4edcd")
	dst := make([]byte, BlockSize)

	b.SetBytes(BlockSize)
	b.ResetTimer()

	for range b.N {
		c.Decrypt(dst, src)
	}
}

func mustHexB(b *testing.B, s string) []byte {
	b.Helper()

	out, err := hex.DecodeString(s)
	if err != nil {
		b.Fatalf("bad hex %q: %v", s, err)
	}

	return out
}
