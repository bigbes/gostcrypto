package ctracpkm_test

import (
	"crypto/cipher"
	"testing"

	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
)

// TestNewCTRACPKM_RejectsBadKey: the ACPKM re-key always derives a 32-byte
// section key, so the master key must be 32 bytes; a wrong length must panic
// at construction, not silently corrupt records past the first mesh.
func TestNewCTRACPKM_RejectsBadKey(t *testing.T) {
	t.Parallel()

	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(make([]byte, 32)) }

	defer func() {
		if recover() == nil {
			t.Error("NewCTRACPKM with a 16-byte key: expected panic")
		}
	}()

	ctracpkm.NewCTRACPKM(newBlock, make([]byte, 16), make([]byte, 16), 32)
}
