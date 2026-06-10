package gost28147cnt_test

// guard_test.go pins the panic contracts promised by the package API.

import (
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147cnt"
)

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic, got none", name)
		}
	}()
	fn()
}

// TestNewCNT_PanicsOnBadIVLength verifies that NewCNT panics for every
// IV length that is not exactly 8 bytes (gost28147.BlockSize).
func TestNewCNT_PanicsOnBadIVLength(t *testing.T) {
	key := make([]byte, gost28147.KeySize)
	c := gost28147.NewCipher(key, gost28147.SboxCryptoProA)

	for _, badLen := range []int{0, 1, 7, 9, 16} {
		badIV := make([]byte, badLen)
		l := badLen // capture
		mustPanic(t, "IV len "+string(rune('0'+l)), func() {
			gost28147cnt.NewCNT(c, badIV)
		})
	}
}

// TestXORKeyStream_PanicsOnShortDst verifies that XORKeyStream panics when
// dst is shorter than src (cipher.Stream contract).
func TestXORKeyStream_PanicsOnShortDst(t *testing.T) {
	key := make([]byte, gost28147.KeySize)
	iv := make([]byte, gost28147.BlockSize)
	s := gost28147cnt.NewCNT(gost28147.NewCipher(key, gost28147.SboxCryptoProA), iv)

	src := make([]byte, 32)
	dst := make([]byte, 16) // shorter than src

	mustPanic(t, "short dst", func() {
		s.XORKeyStream(dst, src)
	})
}
