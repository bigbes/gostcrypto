package ctracpkm_test

import (
	"crypto/cipher"
	"testing"

	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
)

// mustPanic asserts that f() panics.
func mustPanic(t *testing.T, desc string, f func()) {
	t.Helper()

	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected panic, got none", desc)
		}
	}()

	f()
}

// mustNotPanic asserts that f() does NOT panic.
func mustNotPanic(t *testing.T, desc string, f func()) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: unexpected panic: %v", desc, r)
		}
	}()

	f()
}

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

// TestNewCTRACPKM_RejectsNilBlock verifies that a nil newBlock panics at
// construction (CTRA-03).
func TestNewCTRACPKM_RejectsNilBlock(t *testing.T) {
	t.Parallel()

	mustPanic(t, "nil newBlock", func() {
		ctracpkm.NewCTRACPKM(nil, make([]byte, 32), make([]byte, 8), 8)
	})
}

// TestNewCTRACPKM_RejectsNonDividingBlockSize verifies that a block size that
// does not divide the 32-byte ACPKM key causes a panic at construction, not a
// mid-stream slice-bounds panic after data has already been emitted (CTRA-03).
// A 12-byte block is chosen because 32 % 12 != 0.
func TestNewCTRACPKM_RejectsNonDividingBlockSize(t *testing.T) {
	t.Parallel()

	// stubBlock12 is a cipher.Block with BlockSize() == 12.
	stub := &stubBlock{blockSize: 12}
	newBlock := func(k []byte) cipher.Block { return stub }

	// sectionSize=24 is a multiple of 12, so that check passes; only the
	// acpkmKeySize%bs != 0 check (32%12 != 0) should fire.
	mustPanic(t, "block size 12 does not divide 32", func() {
		ctracpkm.NewCTRACPKM(newBlock, make([]byte, 32), make([]byte, 12), 24)
	})
}

// TestNewCTR_RejectsBadIV verifies that NewCTR panics when the IV length does
// not equal the block size (CTRA-05).
func TestNewCTR_RejectsBadIV(t *testing.T) {
	t.Parallel()

	b := kuznyechik.NewCipher(make([]byte, 32))

	mustPanic(t, "NewCTR with 8-byte IV for 16-byte block", func() {
		ctracpkm.NewCTR(b, make([]byte, 8))
	})
}

// TestNewCTRACPKM_RejectsBadIV verifies that NewCTRACPKM panics when the IV
// length does not equal the block size (CTRA-05).
func TestNewCTRACPKM_RejectsBadIV(t *testing.T) {
	t.Parallel()

	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(make([]byte, 32)) }

	mustPanic(t, "NewCTRACPKM with 8-byte IV for 16-byte block", func() {
		ctracpkm.NewCTRACPKM(newBlock, make([]byte, 32), make([]byte, 8), 32)
	})
}

// TestNewCTRACPKM_RejectsNegativeSectionSize verifies that a negative
// sectionSize panics at construction (CTRA-05).
func TestNewCTRACPKM_RejectsNegativeSectionSize(t *testing.T) {
	t.Parallel()

	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(make([]byte, 32)) }

	mustPanic(t, "negative section size", func() {
		ctracpkm.NewCTRACPKM(newBlock, make([]byte, 32), make([]byte, 16), -1)
	})
}

// TestNewCTRACPKM_RejectsSectionSizeNotMultiple verifies that a sectionSize
// that is not a multiple of the block size panics at construction (CTRA-05).
func TestNewCTRACPKM_RejectsSectionSizeNotMultiple(t *testing.T) {
	t.Parallel()

	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(make([]byte, 32)) }

	mustPanic(t, "section size 17 not multiple of block size 16", func() {
		ctracpkm.NewCTRACPKM(newBlock, make([]byte, 32), make([]byte, 16), 17)
	})
}

// TestXORKeyStream_RejectsShortDst verifies that XORKeyStream panics when dst
// is shorter than src (CTRA-05).
func TestXORKeyStream_RejectsShortDst(t *testing.T) {
	t.Parallel()

	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(make([]byte, 32)) }
	s := ctracpkm.NewCTRACPKM(newBlock, make([]byte, 32), make([]byte, 16), 32)

	mustPanic(t, "dst shorter than src", func() {
		s.XORKeyStream(make([]byte, 10), make([]byte, 32))
	})
}

// TestXORKeyStream_RejectsInexactOverlap verifies that XORKeyStream panics on
// inexact buffer overlap, matching the cipher.Stream contract (CTRA-02).
func TestXORKeyStream_RejectsInexactOverlap(t *testing.T) {
	t.Parallel()

	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(make([]byte, 32)) }
	s := ctracpkm.NewCTRACPKM(newBlock, make([]byte, 32), make([]byte, 16), 32)

	buf := make([]byte, 64)

	mustPanic(t, "inexact overlap: dst = buf[1:], src = buf[:32]", func() {
		// dst starts 1 byte after src — inexact overlap.
		s.XORKeyStream(buf[1:], buf[:32])
	})
}

// TestXORKeyStream_AllowsExactOverlap verifies that XORKeyStream permits exact
// overlap (dst[0] == src[0]) — in-place encryption — as required by
// cipher.Stream (CTRA-02).
func TestXORKeyStream_AllowsExactOverlap(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	newBlock := func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }

	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = byte(i)
	}

	// Compute out-of-place reference.
	want := make([]byte, 32)
	ctracpkm.NewCTRACPKM(newBlock, key, iv, 32).XORKeyStream(want, buf)

	// In-place must not panic and must produce the same result.
	mustNotPanic(t, "exact overlap (in-place)", func() {
		ctracpkm.NewCTRACPKM(newBlock, key, iv, 32).XORKeyStream(buf, buf)
	})

	for i := range want {
		if buf[i] != want[i] {
			t.Fatalf("in-place result differs at byte %d: got %02x want %02x", i, buf[i], want[i])
		}
	}
}

// stubBlock is a minimal cipher.Block used to test panic guards with
// non-standard block sizes.
type stubBlock struct {
	blockSize int
}

func (s *stubBlock) BlockSize() int          { return s.blockSize }
func (s *stubBlock) Encrypt(dst, src []byte) {}
func (s *stubBlock) Decrypt(dst, src []byte) {}
