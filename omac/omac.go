// Package omac implements the GOST R 34.13-2015 MAC mode (OMAC1 / CMAC,
// RFC 4493 / NIST SP 800-38B) over any crypto/cipher.Block.
//
// CMAC is a CBC-MAC variant that fixes CBC-MAC's length-extension weakness
// by XORing the final block with one of two key-derived subkeys: K1 for a
// complete final block, K2 for a padded one. The construction is identical
// for both GOST block ciphers; only the block size, the GF(2^n) reduction
// constant Rb, and the (optionally truncated) tag length differ.
//
// This is a clean-room re-implementation from omac.md plus
// RFC 4493; it imports no GOST backend and carries no build tags.
//
// # References
//
//   - RFC 4493: https://github.com/bigbes/gostcrypto/blob/master/omac/rfc/rfc4493.txt
//   - GOST R 34.13-2015: https://github.com/bigbes/gostcrypto/blob/master/omac/rfc/GOST_R_34.13-2015.pdf
package omac

import (
	"crypto/cipher"
	"io"
)

// Block sizes and their GF(2^n) reduction-polynomial low bytes Rb.
const (
	blockSize128 = 16   // Kuznyechik, 128-bit block.
	blockSize64  = 8    // Magma, 64-bit block.
	rb128        = 0x87 // x^128+x^7+x^2+x+1 (RFC 4493 §2.3).
	rb64         = 0x1b // R_64 = 0^59|11011 (RFC 8645 §6.3.6).

	// msbShift is the bit position of the most-significant bit in a byte.
	msbShift = 7
)

// Compile-time assertions. OMAC is a streaming MAC accumulator: Write makes
// it an io.Writer. It deliberately does NOT implement hash.Hash (no Reset,
// and Sum truncates to tagSize rather than always emitting the full digest),
// nor cipher.Block / cipher.AEAD — those are different abstractions.
var _ io.Writer = (*OMAC)(nil)

// OMAC is a streaming CMAC accumulator over a fixed block cipher.
//
// Sum is non-destructive: it snapshots the running state and may be called
// repeatedly, with further Write calls in between, without corrupting the
// MAC. The receiver is NOT safe for concurrent use.
type OMAC struct {
	block     cipher.Block
	blockSize int
	tagSize   int

	k1 []byte // subkey for a complete final block.
	k2 []byte // subkey for a padded (incomplete/empty) final block.

	state []byte // running CBC chain value X (blockSize bytes).
	buf   []byte // up to blockSize buffered, not-yet-chained bytes.
}

// New constructs an OMAC over b, producing tags truncated to tagSize bytes
// (the leading, most-significant bytes of the full CMAC). The GF reduction
// constant Rb is derived from b.BlockSize(): 0x87 for a 16-byte block
// (Kuznyechik), 0x1b for an 8-byte block (Magma).
//
// New panics if the block size is not 8 or 16, or if tagSize is outside
// [1, blockSize].
func New(b cipher.Block, tagSize int) *OMAC {
	bs := b.BlockSize()
	rb := rbForBlockSize(bs)

	if tagSize < 1 || tagSize > bs {
		panic("omac: tagSize out of range [1, blockSize]")
	}

	k1, k2 := cmacSubkeys(b, rb)

	return &OMAC{
		block:     b,
		blockSize: bs,
		tagSize:   tagSize,
		k1:        k1,
		k2:        k2,
		state:     make([]byte, bs),
		buf:       make([]byte, 0, bs),
	}
}

// rbForBlockSize returns the low byte of the GF(2^n) reduction polynomial.
//
//   - 16-byte block (128-bit, Kuznyechik): 0x87, from x^128+x^7+x^2+x+1
//     (RFC 4493 §2.3).
//   - 8-byte block (64-bit, Magma): 0x1b, from R_64 = 0^59|11011
//     (RFC 8645 §6.3.6).
func rbForBlockSize(bs int) byte {
	switch bs {
	case blockSize128:
		return rb128
	case blockSize64:
		return rb64
	default:
		panic("omac: unsupported block size (want 8 or 16)")
	}
}

// cmacSubkeys derives K1 and K2 per RFC 4493 §2.3:
//
//	L  = E_K(0^n)
//	K1 = shiftLeftXorRb(L,  Rb)
//	K2 = shiftLeftXorRb(K1, Rb)
func cmacSubkeys(b cipher.Block, rb byte) (k1, k2 []byte) {
	bs := b.BlockSize()
	l := make([]byte, bs)
	b.Encrypt(l, l) // L = E_K(0^n); l starts all-zero.

	k1 = shiftLeftXorRb(l, rb)
	k2 = shiftLeftXorRb(k1, rb)

	return k1, k2
}

// shiftLeftXorRb performs the GF(2^n) "multiply by x" used by CMAC: a
// big-endian one-bit left shift of the whole block (byte 0 holds the most
// significant bits; the carry from byte[i] flows into byte[i-1]). If the
// original most-significant bit (in[0]>>7) was set, Rb is XORed into the
// last (lowest-order) byte.
//
// NOTE: this is a BIG-endian shift, contrary to GOST's usual little-endian
// habit elsewhere. A little-endian shift here is the classic CMAC bug.
func shiftLeftXorRb(in []byte, rb byte) []byte {
	n := len(in)
	out := make([]byte, n)
	msb := in[0] >> msbShift

	for i := range n - 1 {
		out[i] = (in[i] << 1) | (in[i+1] >> msbShift)
	}

	out[n-1] = in[n-1] << 1
	if msb == 1 {
		out[n-1] ^= rb
	}

	return out
}

// Write absorbs message bytes. It always returns len(p), nil.
//
// A full block is flushed into the CBC chain only when more data follows;
// up to blockSize bytes (a full block included) are kept buffered so that
// Sum can distinguish "exactly n unprocessed bytes" (the K1 path) from
// "fewer than n" (the K2/padding path). Flushing a full final block early
// would yield a wrong tag on every block-aligned message.
func (o *OMAC) Write(p []byte) (int, error) {
	total := len(p)

	for len(p) > 0 {
		// Fill the buffer up to a full block.
		if len(o.buf) < o.blockSize {
			want := min(o.blockSize-len(o.buf), len(p))

			o.buf = append(o.buf, p[:want]...)
			p = p[want:]
		}

		// Flush a full buffered block ONLY if more data follows; the
		// trailing full block must stay buffered for Sum.
		if len(o.buf) == o.blockSize && len(p) > 0 {
			o.cbcStep(o.buf)

			o.buf = o.buf[:0]
		}
	}

	return total, nil
}

// Sum appends the MAC of the message written so far to b and returns the
// result. It is non-destructive: the running state and buffer are snapshot
// and the receiver is left unchanged, so Write may continue afterward.
//
// The returned tag is the leading tagSize bytes of the full CMAC.
func (o *OMAC) Sum(b []byte) []byte {
	// Snapshot the chain so Sum does not mutate the receiver.
	stateSnap := make([]byte, o.blockSize)
	copy(stateSnap, o.state)

	last := make([]byte, o.blockSize)
	if len(o.buf) == o.blockSize {
		// Complete final block: M_last = M_n XOR K1.
		for i := range o.blockSize {
			last[i] = o.buf[i] ^ o.k1[i]
		}
	} else {
		// Incomplete (or empty) final block: pad with 0x80 then zeros,
		// then M_last = pad XOR K2.
		copy(last, o.buf)

		last[len(o.buf)] = 0x80
		// remaining bytes already zero.
		for i := range o.blockSize {
			last[i] ^= o.k2[i]
		}
	}

	// T = E_K(stateSnap XOR M_last).
	tmp := make([]byte, o.blockSize)
	for i := range o.blockSize {
		tmp[i] = stateSnap[i] ^ last[i]
	}

	t := make([]byte, o.blockSize)
	o.block.Encrypt(t, tmp)

	return append(b, t[:o.tagSize]...)
}

// BlockSize returns the underlying cipher's block size.
func (o *OMAC) BlockSize() int { return o.blockSize }

// Size returns the tag length in bytes.
func (o *OMAC) Size() int { return o.tagSize }

// cbcStep advances the CBC chain by one block: state = E_K(state XOR block).
// The block cipher is always used in the ENCRYPT direction; CMAC never
// decrypts.
func (o *OMAC) cbcStep(blk []byte) {
	tmp := make([]byte, o.blockSize)
	for i := range o.blockSize {
		tmp[i] = o.state[i] ^ blk[i]
	}

	o.block.Encrypt(o.state, tmp)
}
