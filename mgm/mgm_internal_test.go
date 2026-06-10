package mgm

import (
	"math/bits"
	"testing"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
)

// TestMaxFieldLen pins the per-field length cap and the 32-bit portability fix
// (MGM-51). On 32-bit platforms (bits.UintSize == 32) the Kuznyechik shift
// (n/2-3 = 61) does not fit a signed int — the old code returned -1, making
// every Seal/Open fail. The fix compares the shift against bits.UintSize-1 and
// returns maxInt when it would overflow.
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

	// Kuznyechik: 128-bit block -> 64-bit length field.
	// On 64-bit: expected (1<<61)-1. On 32-bit: expected maxInt.
	m16, err := NewMGM(kuznyechik.NewCipher(make([]byte, 32)), 16)
	if err != nil {
		t.Fatal(err)
	}

	got := m16.maxFieldLen()

	if got < 0 {
		t.Errorf("kuznyechik maxFieldLen = %d: must never be negative (32-bit portability bug)", got)
	}

	if bits.UintSize == 64 {
		if want := (1 << 61) - 1; got != want {
			t.Errorf("kuznyechik maxFieldLen (64-bit) = %d, want %d", got, want)
		}
	} else {
		// 32-bit: shift 61 does not fit int; must return maxInt.
		const maxInt = int(^uint(0) >> 1)
		if got != maxInt {
			t.Errorf("kuznyechik maxFieldLen (32-bit) = %d, want maxInt=%d", got, maxInt)
		}
	}
}

// TestValidateLens pins the RFC 9058 combined-length bound (MGM-55).
// rfc/rfc9058.txt:281-282: |A| + |P| < 2^(n/2) bits.
// We unit-test validateLens directly to avoid allocating gigabyte buffers.
func TestValidateLens(t *testing.T) {
	t.Parallel()

	// Magma: n=64, 2^(n/2) = 2^32 bits = 2^29 bytes.
	m8, err := NewMGM(magma.NewCipher(make([]byte, 32)), 8)
	if err != nil {
		t.Fatal(err)
	}

	const maxMagmaBytes = (1 << 29) - 1 // per-field cap

	// Both fields at the per-field cap: combined bit-length = 2*(2^29-1)*8 = 2^33-16 bits > 2^32.
	if m8.validateLens(maxMagmaBytes, maxMagmaBytes) {
		t.Error("Magma: expected validateLens to reject two max-size fields (sum exceeds 2^32 bits)")
	}

	// One field at per-field cap, other 1 byte: sum = (2^29-1)*8 + 8 = 2^32 bits = boundary, still invalid.
	if m8.validateLens(maxMagmaBytes, 1) {
		t.Error("Magma: expected validateLens to reject aLen=maxMagmaBytes + pLen=1 (sum == 2^32 bits)")
	}

	// One field at per-field cap, other empty: sum < 2^32 bits, valid.
	if !m8.validateLens(maxMagmaBytes, 0) {
		t.Error("Magma: expected validateLens to accept aLen=maxMagmaBytes + pLen=0")
	}

	// Both individually valid but sum at boundary (2^29 bytes = 2^32 bits exactly — invalid).
	// Use half per-field cap each: 2*(2^28)*8 = 2^32 bits, invalid.
	if m8.validateLens(1<<28, 1<<28) {
		t.Error("Magma: expected validateLens to reject sum == 2^32 bits (boundary)")
	}

	// Kuznyechik: n=128, 2^(n/2) = 2^64 bits — only overflow can violate this.
	m16, err := NewMGM(kuznyechik.NewCipher(make([]byte, 32)), 16)
	if err != nil {
		t.Fatal(err)
	}

	// Two reasonable sizes should always be valid for Kuznyechik.
	if !m16.validateLens(1024, 1024) {
		t.Error("Kuznyechik: expected validateLens to accept small fields")
	}
}
