package kuznyechik_test

import (
	"testing"

	"github.com/bigbes/gostcrypto/kuznyechik"
)

// TestEncrypt_RejectsShortBlock: like crypto/aes, Encrypt/Decrypt must panic on
// a sub-block buffer rather than silently zero-pad src / truncate dst.
func TestEncrypt_RejectsShortBlock(t *testing.T) {
	t.Parallel()

	c := kuznyechik.NewCipher(make([]byte, 32))
	full := make([]byte, kuznyechik.BlockSize)
	short := make([]byte, kuznyechik.BlockSize-1)

	mustPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic on short buffer", name)
			}
		}()

		f()
	}
	mustPanic("Encrypt short src", func() { c.Encrypt(full, short) })
	mustPanic("Encrypt short dst", func() { c.Encrypt(short, full) })
	mustPanic("Decrypt short src", func() { c.Decrypt(full, short) })
	mustPanic("Decrypt short dst", func() { c.Decrypt(short, full) })
}
