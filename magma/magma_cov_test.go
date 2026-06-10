package magma_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/magma"
)

// decodeHex decodes a hex string, calling tb.Fatal on error.
// Distinct from mustHexG defined in guard_test.go to avoid a redeclared-in-block error.
func decodeHex(tb testing.TB, s string) []byte {
	tb.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// FuzzRoundTrip exercises two round-trip properties for arbitrary 8-byte blocks:
//
//  1. Decrypt(Encrypt(p)) == p  for all 8-byte inputs.
//  2. In-place Encrypt(buf, buf) produces the same ciphertext as out-of-place
//     Encrypt(ct, p) — the implementation stages through a local tmp[8] array
//     so the two paths must agree.
//
// No expected-byte literals are introduced: the properties are purely algebraic
// and depend only on the package's own code being consistent with itself.  The
// byte-for-byte parity oracle against gogost lives in
// ../gostcrypto-compat/parity/magma/ (GPL-quarantined, not in this module's CI).
//
// Key is the RFC 8891 Appendix A key; seeds are the RFC Appendix A plaintext, the
// all-zero block, and the all-ones block to exercise boundary values.
func FuzzRoundTrip(f *testing.F) {
	// Seed corpus: RFC 8891 §A.3 plaintext, all-zero, all-ones.
	seeds := [][]byte{
		{0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}, // RFC 8891 Appendix A.3.
		make([]byte, magma.BlockSize),                    // All-zero block.
		bytes.Repeat([]byte{0xFF}, magma.BlockSize),      // All-ones block.
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	// Fixed RFC 8891 Appendix A key — same as TestRFC8891KAT.
	key := decodeHex(f, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	c := magma.NewCipher(key)

	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) != magma.BlockSize {
			// The fuzzer may produce inputs of any length; skip non-block-sized ones.
			return
		}

		// Property 1: Decrypt(Encrypt(p)) == p.
		ct := make([]byte, magma.BlockSize)
		c.Encrypt(ct, p)

		rt := make([]byte, magma.BlockSize)
		c.Decrypt(rt, ct)

		if !bytes.Equal(rt, p) {
			t.Fatalf("round-trip mismatch\n  plain=%x\n  ct   =%x\n  rt   =%x", p, ct, rt)
		}

		// Property 2: in-place Encrypt(buf, buf) == out-of-place Encrypt(ct, p).
		// crypt() stages through a local tmp[magma.BlockSize] array; both paths must
		// produce identical output for all 8-byte inputs.
		inPlace := append([]byte(nil), p...)
		c.Encrypt(inPlace, inPlace)

		if !bytes.Equal(inPlace, ct) {
			t.Fatalf("in-place Encrypt != out-of-place Encrypt\n  pt      =%x\n  in-place=%x\n  separate=%x",
				p, inPlace, ct)
		}
	})
}

// TestOversizeDstSrc checks that Encrypt/Decrypt operate only on the first
// magma.BlockSize bytes when dst or src are longer than one block.  cipher.Block's
// contract is that only the first BlockSize bytes of dst/src are used; trailing
// bytes must be left untouched.
//
// The expected ciphertext is derived from the same package via a correctly-sized
// call (no hand-invented bytes).
func TestOversizeDstSrc(t *testing.T) {
	t.Parallel()

	// RFC 8891 Appendix A key and plaintext.
	key := decodeHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := decodeHex(t, "fedcba9876543210")

	// Derive expected ciphertext from the package itself (same as TestRFC8891KAT).
	c := magma.NewCipher(key)
	wantCT := make([]byte, magma.BlockSize)
	c.Encrypt(wantCT, pt)

	sentinel := byte(0xAB) // Marker value to detect spurious writes.

	t.Run("Encrypt_oversize_dst", func(t *testing.T) {
		t.Parallel()

		// dst is 3×BlockSize; only the first BlockSize bytes should be written.
		dst := bytes.Repeat([]byte{sentinel}, 3*magma.BlockSize)
		c.Encrypt(dst, pt)

		if !bytes.Equal(dst[:magma.BlockSize], wantCT) {
			t.Fatalf("Encrypt with oversize dst: block[0:8] = %x, want %x", dst[:magma.BlockSize], wantCT)
		}

		// Bytes beyond the first block must not be touched.
		for i := magma.BlockSize; i < len(dst); i++ {
			if dst[i] != sentinel {
				t.Fatalf("Encrypt wrote beyond BlockSize: dst[%d] = 0x%02x, want 0x%02x", i, dst[i], sentinel)
			}
		}
	})

	t.Run("Encrypt_oversize_src", func(t *testing.T) {
		t.Parallel()

		// src is 3×BlockSize; only the first BlockSize bytes should be read.
		src := make([]byte, 3*magma.BlockSize)
		copy(src, pt)

		// Fill trailing bytes with a distinct sentinel so a stray read would
		// produce a wrong ciphertext.
		for i := magma.BlockSize; i < len(src); i++ {
			src[i] = sentinel
		}

		dst := make([]byte, magma.BlockSize)
		c.Encrypt(dst, src)

		if !bytes.Equal(dst, wantCT) {
			t.Fatalf("Encrypt with oversize src: got %x, want %x", dst, wantCT)
		}
	})

	t.Run("Decrypt_oversize_dst", func(t *testing.T) {
		t.Parallel()

		// dst is 3×BlockSize; only the first BlockSize bytes should be written.
		dst := bytes.Repeat([]byte{sentinel}, 3*magma.BlockSize)
		c.Decrypt(dst, wantCT)

		if !bytes.Equal(dst[:magma.BlockSize], pt) {
			t.Fatalf("Decrypt with oversize dst: block[0:8] = %x, want %x", dst[:magma.BlockSize], pt)
		}

		for i := magma.BlockSize; i < len(dst); i++ {
			if dst[i] != sentinel {
				t.Fatalf("Decrypt wrote beyond BlockSize: dst[%d] = 0x%02x, want 0x%02x", i, dst[i], sentinel)
			}
		}
	})

	t.Run("Decrypt_oversize_src", func(t *testing.T) {
		t.Parallel()

		// src is 3×BlockSize; only the first BlockSize bytes should be read.
		src := make([]byte, 3*magma.BlockSize)
		copy(src, wantCT)

		for i := magma.BlockSize; i < len(src); i++ {
			src[i] = sentinel
		}

		dst := make([]byte, magma.BlockSize)
		c.Decrypt(dst, src)

		if !bytes.Equal(dst, pt) {
			t.Fatalf("Decrypt with oversize src: got %x, want %x", dst, pt)
		}
	})
}

// TestPartialOverlap checks that Encrypt/Decrypt produce correct output when dst
// and src overlap at a nonzero byte offset.  The cipher.Block contract says
// "dst and src must overlap entirely or not at all" — but crypt() reads all of src
// into a local tmp[magma.BlockSize] array before writing any byte of dst, so
// partial overlap is in practice safe and produces the same bytes as a
// non-overlapping call.  This test pins that behaviour so that any future
// optimisation that drops the tmp staging (e.g. writing dst inline) cannot silently
// regress the composing modes (CTR, OMAC, MGM) that may call Encrypt(b[1:], b[:]).
//
// Expected values are derived from same-package non-overlapping calls (no
// hand-invented bytes, per the anti-footgun rules in docs/audit-remediation-pass2.md §1.1).
func TestPartialOverlap(t *testing.T) {
	t.Parallel()

	key := decodeHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	pt := decodeHex(t, "fedcba9876543210") // RFC 8891 Appendix A.3 plaintext.
	c := magma.NewCipher(key)

	// Derive reference ciphertext from the package (same as TestRFC8891KAT).
	wantCT := make([]byte, magma.BlockSize)
	c.Encrypt(wantCT, pt)

	// Encrypt with dst = buf[1:9], src = buf[0:8] (1-byte forward shift).
	t.Run("Encrypt_1byte_forward_shift", func(t *testing.T) {
		t.Parallel()

		// buf layout: buf[0..7] = pt, dst = buf[1..8] (1-byte overlap).
		buf := make([]byte, magma.BlockSize+1)
		copy(buf[0:magma.BlockSize], pt)

		c.Encrypt(buf[1:1+magma.BlockSize], buf[0:magma.BlockSize])

		if !bytes.Equal(buf[1:1+magma.BlockSize], wantCT) {
			t.Fatalf("Encrypt 1-byte forward shift: got %x, want %x", buf[1:1+magma.BlockSize], wantCT)
		}
	})

	// Encrypt with dst = buf[0:8], src = buf[1:9] (1-byte backward shift).
	t.Run("Encrypt_1byte_backward_shift", func(t *testing.T) {
		t.Parallel()

		buf := make([]byte, magma.BlockSize+1)
		copy(buf[1:1+magma.BlockSize], pt)

		// Reference: encrypt buf[1:9] into a separate destination first.
		ref := make([]byte, magma.BlockSize)
		c.Encrypt(ref, buf[1:1+magma.BlockSize])

		c.Encrypt(buf[0:magma.BlockSize], buf[1:1+magma.BlockSize])

		if !bytes.Equal(buf[0:magma.BlockSize], ref) {
			t.Fatalf("Encrypt 1-byte backward shift: got %x, want %x", buf[0:magma.BlockSize], ref)
		}
	})

	// Decrypt with dst = buf[1:9], src = buf[0:8].
	t.Run("Decrypt_1byte_forward_shift", func(t *testing.T) {
		t.Parallel()

		buf := make([]byte, magma.BlockSize+1)
		copy(buf[0:magma.BlockSize], wantCT)

		c.Decrypt(buf[1:1+magma.BlockSize], buf[0:magma.BlockSize])

		if !bytes.Equal(buf[1:1+magma.BlockSize], pt) {
			t.Fatalf("Decrypt 1-byte forward shift: got %x, want %x", buf[1:1+magma.BlockSize], pt)
		}
	})

	// Decrypt with dst = buf[0:8], src = buf[1:9].
	t.Run("Decrypt_1byte_backward_shift", func(t *testing.T) {
		t.Parallel()

		buf := make([]byte, magma.BlockSize+1)
		copy(buf[1:1+magma.BlockSize], wantCT)

		// Reference: decrypt buf[1:9] into a separate destination first.
		ref := make([]byte, magma.BlockSize)
		c.Decrypt(ref, buf[1:1+magma.BlockSize])

		c.Decrypt(buf[0:magma.BlockSize], buf[1:1+magma.BlockSize])

		if !bytes.Equal(buf[0:magma.BlockSize], ref) {
			t.Fatalf("Decrypt 1-byte backward shift: got %x, want %x", buf[0:magma.BlockSize], ref)
		}
	})

	// Encrypt with dst = buf[4:12], src = buf[0:8] (half-block overlap).
	t.Run("Encrypt_half_block_overlap", func(t *testing.T) {
		t.Parallel()

		buf := make([]byte, 2*magma.BlockSize)
		copy(buf[0:magma.BlockSize], pt)

		// Reference: encrypt buf[0:8] into a separate destination.
		ref := make([]byte, magma.BlockSize)
		c.Encrypt(ref, buf[0:magma.BlockSize])

		c.Encrypt(buf[4:4+magma.BlockSize], buf[0:magma.BlockSize])

		if !bytes.Equal(buf[4:4+magma.BlockSize], ref) {
			t.Fatalf("Encrypt half-block overlap: got %x, want %x", buf[4:4+magma.BlockSize], ref)
		}
	})
}
