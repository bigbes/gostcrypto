package kuznyechik //nolint:testpackage // white-box: uses unexported keySize.

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// EncryptBlocks must equal successive Encrypt calls for both cipher
// constructors and for block counts that straddle the 32-block SIMD chunk
// boundary (remainder handling). On default builds this exercises the pure-Go
// fallback; under GOEXPERIMENT=simd on amd64 it exercises the SIMD chunks plus
// the scalar remainder.
func TestEncryptBlocks_MatchesEncrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ctors := []struct {
		name string
		new  func([]byte) *Cipher
	}{
		{"table", NewCipher},
		{"ct", NewCipherCT},
	}
	counts := []int{1, 15, 31, 32, 33, 64, 65, 100}

	for _, ctor := range ctors {
		c := ctor.new(key)

		for _, nblk := range counts {
			src := make([]byte, nblk*BlockSize)
			if _, err := rand.Read(src); err != nil {
				t.Fatal(err)
			}

			want := make([]byte, len(src))
			for i := range nblk {
				c.Encrypt(want[i*BlockSize:], src[i*BlockSize:])
			}

			got := make([]byte, len(src))
			c.EncryptBlocks(got, src)

			if !bytes.Equal(got, want) {
				t.Fatalf("%s nblk=%d: EncryptBlocks != per-block Encrypt", ctor.name, nblk)
			}
		}
	}
}

// In-place encryption (dst == src, exact overlap) must be allowed and correct.
func TestEncryptBlocks_InPlace(t *testing.T) {
	t.Parallel()

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	c := NewCipher(key)

	const nblk = 40

	src := make([]byte, nblk*BlockSize)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}

	want := make([]byte, len(src))
	c.EncryptBlocks(want, src)

	buf := append([]byte(nil), src...)
	c.EncryptBlocks(buf, buf)

	if !bytes.Equal(buf, want) {
		t.Fatal("in-place EncryptBlocks differs from out-of-place")
	}
}

func TestEncryptBlocks_Panics(t *testing.T) {
	t.Parallel()

	c := NewCipher(make([]byte, keySize))
	cases := []struct {
		name     string
		dst, src []byte
	}{
		{"not whole blocks", make([]byte, BlockSize), make([]byte, BlockSize-1)},
		{"empty", make([]byte, 0), make([]byte, 0)},
		{"short dst", make([]byte, BlockSize-1), make([]byte, BlockSize)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Fatal("expected panic")
				}
			}()

			c.EncryptBlocks(tc.dst, tc.src)
		})
	}
}
