package gost28147_test

// Compile-time interface assertion (GOST-08): *Cipher must satisfy cipher.Block.
// A signature drift (e.g. BlockSize removed) breaks the build here rather than
// only being caught by downstream packages.
import (
	"crypto/cipher"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
)

var _ cipher.Block = (*gost28147.Cipher)(nil)

var testKey = []byte{
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
	0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xf0, 0xe1,
}

// TestNewCipher_PanicOnBadKey checks that NewCipher panics on incorrect key sizes.
func TestNewCipher_PanicOnBadKey(t *testing.T) {
	t.Parallel()

	for _, badLen := range []int{0, 1, 16, 31, 33, 64} {
		n := badLen

		t.Run("", func(t *testing.T) {
			t.Parallel()

			defer func() {
				if r := recover(); r == nil {
					t.Fatalf("NewCipher with key len %d: expected panic, got none", n)
				}
			}()

			gost28147.NewCipher(make([]byte, n), gost28147.SboxCryptoProA)
		})
	}
}

// TestEncrypt_PanicOnShortBuffer checks that Encrypt panics when src or dst are
// shorter than BlockSize.
func TestEncrypt_PanicOnShortBuffer(t *testing.T) {
	t.Parallel()

	c := gost28147.NewCipher(testKey, gost28147.SboxCryptoProA)

	t.Run("short-src", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Encrypt with short src: expected panic, got none")
			}
		}()

		c.Encrypt(make([]byte, gost28147.BlockSize), make([]byte, gost28147.BlockSize-1))
	})

	t.Run("short-dst", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Encrypt with short dst: expected panic, got none")
			}
		}()

		c.Encrypt(make([]byte, gost28147.BlockSize-1), make([]byte, gost28147.BlockSize))
	})
}

// TestDecrypt_PanicOnShortBuffer checks that Decrypt panics when src or dst are
// shorter than BlockSize.
func TestDecrypt_PanicOnShortBuffer(t *testing.T) {
	t.Parallel()

	c := gost28147.NewCipher(testKey, gost28147.SboxCryptoProA)

	t.Run("short-src", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Decrypt with short src: expected panic, got none")
			}
		}()

		c.Decrypt(make([]byte, gost28147.BlockSize), make([]byte, gost28147.BlockSize-1))
	})

	t.Run("short-dst", func(t *testing.T) {
		t.Parallel()

		defer func() {
			if r := recover(); r == nil {
				t.Fatal("Decrypt with short dst: expected panic, got none")
			}
		}()

		c.Decrypt(make([]byte, gost28147.BlockSize-1), make([]byte, gost28147.BlockSize))
	})
}

// TestEncryptDecrypt_InPlace checks that in-place Encrypt(buf, buf) / Decrypt(buf, buf)
// produce the same result as out-of-place Encrypt(dst, src) / Decrypt(dst, src).
// Higher modes (omac, keywrap) perform in-place block operations on shared buffers,
// so this property is load-bearing (GOST-07).
// Verified for both S-boxes against the existing V1/CryptoPro-A KAT.
func TestEncryptDecrypt_InPlace(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		sbox gost28147.SBox
		// plaintext from TestECB_KAT V1/CryptoProA and V1b/TC26Z.
		pt string
	}{
		{name: "CryptoProA", sbox: gost28147.SboxCryptoProA, pt: "1020304050607080"},
		{name: "TC26Z", sbox: gost28147.SboxTC26Z, pt: "1020304050607080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pt := mustHex(t, tc.pt)
			c := gost28147.NewCipher(testKey, tc.sbox)

			// Out-of-place reference.
			ctRef := make([]byte, gost28147.BlockSize)
			c.Encrypt(ctRef, pt)

			// In-place: buf starts as plaintext; after Encrypt it should be ciphertext.
			buf := make([]byte, gost28147.BlockSize)
			copy(buf, pt)
			c.Encrypt(buf, buf)

			for i, b := range buf {
				if b != ctRef[i] {
					t.Fatalf("Encrypt in-place: byte %d got %02x want %02x", i, b, ctRef[i])
				}
			}

			// Out-of-place decrypt reference.
			ptRef := make([]byte, gost28147.BlockSize)
			c.Decrypt(ptRef, ctRef)

			// In-place decrypt: buf now holds ciphertext.
			c.Decrypt(buf, buf)

			for i, b := range buf {
				if b != ptRef[i] {
					t.Fatalf("Decrypt in-place: byte %d got %02x want %02x", i, b, ptRef[i])
				}
			}
		})
	}
}
