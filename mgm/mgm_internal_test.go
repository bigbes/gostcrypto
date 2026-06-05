package mgm

import (
	"testing"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
)

// TestMaxFieldLen pins the per-field length cap that prevents the length-block
// overflow: each of the AAD and payload bit-lengths must fit in n/2 bits, so a
// field is capped at 2^(n/2-3)-1 bytes. (The buggy version capped the SUM at
// 2^(n/2)-1 bytes, letting a >=512 MiB Magma field silently forge a wrong tag.)
func TestMaxFieldLen(t *testing.T) {
	t.Parallel()

	// Magma: 64-bit block -> 32-bit length field -> 2^29-1 bytes (512 MiB-1).
	m8, err := NewMGM(magma.NewCipher(make([]byte, 32)), 8)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := m8.maxFieldLen(), (1<<29)-1; got != want {
		t.Errorf("magma maxFieldLen = %d, want %d", got, want)
	}

	// Kuznyechik: 128-bit block -> 64-bit length field -> 2^61-1 bytes.
	m16, err := NewMGM(kuznyechik.NewCipher(make([]byte, 32)), 16)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := m16.maxFieldLen(), (1<<61)-1; got != want {
		t.Errorf("kuznyechik maxFieldLen = %d, want %d", got, want)
	}
}
