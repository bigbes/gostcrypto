package magma_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/magma"
)

// compile-time: magma.Cipher must satisfy crypto/cipher.Block.
// (the facade exports.go also asserts this; the in-package assertion fires
// before the facade is compiled.)
var _ cipher.Block = (*magma.Cipher)(nil)

// mustHexG decodes a hex string, failing the test on any error.
func mustHexG(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// TestNewCipherPanicsOnBadKey pins the documented panic contract:
// NewCipher panics if the key is not exactly KeySize (32) bytes.  (MAGM-50)
func TestNewCipherPanicsOnBadKey(t *testing.T) {
	t.Parallel()

	mustPanic := func(name string, n int) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic on %d-byte key", name, n)
			}
		}()

		magma.NewCipher(make([]byte, n))
	}

	mustPanic("short-0", 0)
	mustPanic("short-31", 31)
	mustPanic("over-33", 33)
}

// TestEncryptDecryptPanicsOnShortBuffer pins the documented panics:
// Encrypt/Decrypt panic if src or dst is shorter than BlockSize.  (MAGM-50)
func TestEncryptDecryptPanicsOnShortBuffer(t *testing.T) {
	t.Parallel()

	c := magma.NewCipher(make([]byte, magma.KeySize))
	full := make([]byte, magma.BlockSize)
	short := make([]byte, magma.BlockSize-1)

	mustPanic := func(name string, f func()) {
		t.Helper()
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

// TestEncryptDecryptInPlace pins that full dst==src overlap works correctly
// against the RFC 8891 Appendix A KAT.  crypt() stages through a local
// tmp[8] buffer so in-place operation is safe, but no magma test previously
// pinned it — a future optimisation that writes dst before consuming src
// would silently break every composing mode (CTR/OMAC/MGM) that calls
// Encrypt(b, b).  (MAGM-50)
func TestEncryptDecryptInPlace(t *testing.T) {
	t.Parallel()

	// RFC 8891 Appendix A.3-A.4 KAT (same as TestRFC8891KAT).
	key := mustHexG(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := mustHexG(t, "fedcba9876543210")
	want := mustHexG(t, "4ee901e5c2d8ca3d")

	c := magma.NewCipher(key)

	// in-place encrypt: dst == src
	enc := append([]byte(nil), pt...)
	c.Encrypt(enc, enc)

	if !bytes.Equal(enc, want) {
		t.Fatalf("in-place Encrypt: got %x want %x", enc, want)
	}

	// in-place decrypt: dst == src, must recover plaintext
	dec := append([]byte(nil), want...)
	c.Decrypt(dec, dec)

	if !bytes.Equal(dec, pt) {
		t.Fatalf("in-place Decrypt: got %x want %x", dec, pt)
	}
}
