//go:build goexperiment.simd && amd64

package kuznyechik

import (
	"bytes"
	"math/rand"
	"testing"
)

// RFC 7801 §A.1 Kuznyechik known-answer vector, encrypted through the SIMD
// batch path (32 copies of the plaintext) — every lane must match.
func TestSimd_KAT(t *testing.T) {
	if !simdEncryptAvailable() {
		t.Skip("AVX2 unavailable")
	}
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	pt := mustHex(t, "1122334455667700ffeeddccbbaa9988")
	ct := mustHex(t, "7f679d90bebc24305a468d42b9d4edcd")

	src := make([]byte, simdBatch*BlockSize)
	for b := 0; b < simdBatch; b++ {
		copy(src[b*BlockSize:], pt)
	}
	dst := make([]byte, len(src))
	NewCipher(key).EncryptBlocks(dst, src)

	for b := 0; b < simdBatch; b++ {
		if !bytes.Equal(dst[b*BlockSize:(b+1)*BlockSize], ct) {
			t.Fatalf("block %d: got %x want %x", b, dst[b*BlockSize:(b+1)*BlockSize], ct)
		}
	}
}

// The SIMD batch path must reproduce the table cipher byte-for-byte for any key
// and input — the same oracle relationship the constant-time scalar path is
// held to (FuzzCT_vs_Table). simdBulkEncrypt is exercised directly so the whole
// input goes through SIMD with no scalar remainder masking a divergence.
func FuzzEncryptBlocks_vs_Table(f *testing.F) {
	if !simdEncryptAvailable() {
		f.Skip("AVX2 unavailable")
	}
	f.Add(uint64(1), uint64(2), 32)
	f.Add(uint64(0xdeadbeef), uint64(0x1234), 64)

	f.Fuzz(func(t *testing.T, ks0, ks1 uint64, nblk int) {
		if nblk <= 0 || nblk > 256 {
			nblk = 32
		}
		nblk -= nblk % simdBatch
		if nblk == 0 {
			nblk = simdBatch
		}

		key := make([]byte, keySize)
		rng := rand.New(rand.NewSource(int64(ks0) ^ int64(ks1)<<1))
		rng.Read(key)
		src := make([]byte, nblk*BlockSize)
		rng.Read(src)

		c := NewCipher(key)

		want := make([]byte, len(src))
		for i := 0; i < nblk; i++ {
			c.Encrypt(want[i*BlockSize:], src[i*BlockSize:])
		}

		got := make([]byte, len(src))
		n := simdBulkEncrypt(c, got, src)
		if n != len(src) {
			t.Fatalf("simd handled %d of %d bytes", n, len(src))
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("SIMD != table for key %x (nblk=%d)", key, nblk)
		}
	})
}
