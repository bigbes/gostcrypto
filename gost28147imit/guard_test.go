package gost28147imit_test

import (
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147imit"
)

// mustPanic is a helper that asserts a function panics.
func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s: expected panic, got none", name)
		}
	}()

	fn()
}

// mustNotPanic is a helper that asserts a function does not panic.
func mustNotPanic(t *testing.T, name string, fn func()) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: unexpected panic: %v", name, r)
		}
	}()

	fn()
}

// TestIMIT_RejectsEmpty: an empty message would return the key-independent
// 0x00000000 IV state, which is a forgeable non-MAC; IMIT must panic instead.
func TestIMIT_RejectsEmpty(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)

	for _, msg := range [][]byte{nil, {}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("IMIT(key, %v): expected panic on empty message", msg)
				}
			}()

			gost28147imit.IMIT(key, msg)
		}()
	}
}

// TestSeqMACBlock_RejectsBadKeyLen verifies that SeqMACBlock panics for any
// key length != 32 bytes, including keys with spare capacity (GOST-14).
//
// The capacity-vs-length distinction matters: a []byte with len=16, cap=32
// would previously reach newMACCipher which sliced key[i*4:i*4+4] up to
// i=7 (offset 28–32), reading past len into the backing array. The explicit
// check must gate on len, not cap.
func TestSeqMACBlock_RejectsBadKeyLen(t *testing.T) {
	t.Parallel()

	sbox := gost28147.SboxCryptoProA
	block := make([]byte, 8)

	// 16-byte key with extra capacity: len=16 but backing array is 32 bytes.
	// Previously returned a tag silently computed over out-of-range key bytes.
	backing := make([]byte, 32)
	shortKeyWithCap := backing[:16]
	mustPanic(t, "16-byte key len=16 cap=32", func() {
		gost28147imit.SeqMACBlock(shortKeyWithCap, sbox, block)
	})

	// 16-byte key with exact capacity: previously panicked with raw
	// "slice bounds out of range" rather than a package-prefixed message.
	mustPanic(t, "16-byte key len=16 cap=16", func() {
		gost28147imit.SeqMACBlock(make([]byte, 16), sbox, block)
	})

	// 31 bytes (just short)
	mustPanic(t, "31-byte key", func() {
		gost28147imit.SeqMACBlock(make([]byte, 31), sbox, block)
	})

	// 33 bytes (just over)
	mustPanic(t, "33-byte key", func() {
		gost28147imit.SeqMACBlock(make([]byte, 33), sbox, block)
	})

	// 32 bytes must succeed
	mustNotPanic(t, "32-byte key (valid)", func() {
		gost28147imit.SeqMACBlock(make([]byte, 32), sbox, block)
	})
}

// TestSeqMACBlock_RejectsBadBlockLen verifies that SeqMACBlock panics for
// block lengths != 8 bytes (GOST-14). A block shorter than 8 would previously
// panic with a raw index-out-of-range; a longer block was silently truncated.
func TestSeqMACBlock_RejectsBadBlockLen(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	sbox := gost28147.SboxCryptoProA

	// 7-byte block: previously panicked with raw runtime error.
	mustPanic(t, "7-byte block", func() {
		gost28147imit.SeqMACBlock(key, sbox, make([]byte, 7))
	})

	// 9-byte block: previously silently truncated to first 8 bytes.
	mustPanic(t, "9-byte block", func() {
		gost28147imit.SeqMACBlock(key, sbox, make([]byte, 9))
	})

	// 0-byte block: empty.
	mustPanic(t, "0-byte block", func() {
		gost28147imit.SeqMACBlock(key, sbox, nil)
	})

	// 8 bytes must succeed.
	mustNotPanic(t, "8-byte block (valid)", func() {
		gost28147imit.SeqMACBlock(key, sbox, make([]byte, 8))
	})
}
