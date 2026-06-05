// Package gostr341194 is a clean-room, pure-Go implementation of the
// GOST R 34.11-94 legacy hash function (CryptoPro parameter set), built
// strictly from gostr341194.md and RFC 5831 (§3/§5/§6) without
// consulting gogost, gost-engine, or internal/gost implementation source.
//
// It reuses the in-tree clean-room GOST 28147-89 block cipher
// (github.com/bigbes/gostcrypto/gost28147) for the inner ECB encryptions; it
// does NOT reimplement 28147. The hash CryptoPro S-box
// (id-GostR3411-94-CryptoProParamSet, OID 1.2.643.2.2.30.1) is a DIFFERENT
// table from the cipher S-boxes and is transcribed here from the guide.
//
// # Byte-order convention
//
// RFC 5831 §3 numbers symbols right-to-left: the rightmost byte of a 256-bit
// word is byte #1. This implementation stores every block so that array index i
// holds byte #(i+1), i.e. the message bytes are used in their natural order
// (no per-block reversal, no digest reversal). The transforms A, P, ψ and the
// constant C3 are defined directly on this numbering. This matches gogost /
// gost-engine output bit-for-bit on all non-empty inputs.
//
// # Empty-input behavior (guide D1)
//
// For an empty message, gogost and gost-engine DISAGREE. This implementation
// matches the gost-engine / Tarantool result (3f25bc1f…), NOT gogost
// (981e5f3c…): when the total length is zero it inserts an extra compression
// with the all-zero block before the length and checksum blocks.
//
// # References
//
//   - RFC 5831: https://github.com/bigbes/gostcrypto/blob/master/gostr341194/rfc/rfc5831.txt
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/gostr341194/rfc/rfc4357.txt
package gostr341194

import (
	"hash"

	"github.com/bigbes/gostcrypto/gost28147"
)

// Size is the digest length in bytes (256 bits).
const Size = 32

// BlockSize is the message block length in bytes (256 bits).
const BlockSize = 32

const (
	// wordSize is the 64-bit ECB word length in bytes (h1..h4, x1..x4).
	wordSize = 8
	// numWords is the number of 64-bit words per 256-bit block.
	numWords = 4
	// halfWordSize is the 16-bit word length in bytes (ψ operates on η1..η16).
	halfWordSize = 2
	// numHalfWords is the number of 16-bit words per 256-bit block (η1..η16).
	numHalfWords = 16
	// bitsPerByte is the number of bits in a byte (length accounting).
	bitsPerByte = 8
	// psiMixInner is the inner ψ iteration count in the mixing stage (ψ^12).
	psiMixInner = 12
	// psiMixOuter is the outer ψ iteration count in the mixing stage (ψ^61).
	psiMixOuter = 61
	// byteOn is the all-ones byte used in constant C3 (RFC bit pattern 1^8).
	byteOn = 0xff
	// byteOff is the all-zeros byte used in constant C3 (RFC bit pattern 0^8).
	byteOff = 0x00
)

// sboxCryptoProHash is id-GostR3411-94-CryptoProParamSet (OID 1.2.643.2.2.30.1),
// the S-box used by the inner 28147 cipher of this hash. It is a different table
// from the 28147 *cipher* CryptoPro-A S-box. Rows are in natural order (guide
// §"CryptoPro S-box"): row i substitutes nibble i of the 32-bit word.
var sboxCryptoProHash = gost28147.SBox{
	{10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
	{5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
	{7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
	{4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
	{7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
	{7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
	{13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
	{1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12},
}

// c3 is the compression-function constant C3 (RFC 5831 §5.1) in this package's
// from-right byte storage (array index i = byte #(i+1)). RFC bit pattern:
// 1^8 0^8 1^16 0^24 1^16 0^8 (0^8 1^8)^2 1^8 0^8 (0^8 1^8)^4 (1^8 0^8)^4,
// written most-significant byte (#32) first, then reversed into array order.
// C2 and C4 are all-zero, so only C3 is needed.
var c3 = buildC3()

func buildC3() [BlockSize]byte {
	// msb[0] is the most-significant byte (#32); 32 bytes total. Each line below
	// is one 8-bit run from the RFC bit pattern, transcribed MSByte first.
	const on, off = byteOn, byteOff

	msb := []byte{
		on,     // 1^8
		off,    // 0^8
		on, on, // 1^16
		off, off, off, // 0^24
		on, on, // 1^16
		off,              // 0^8
		off, on, off, on, // (0^8 1^8)^2
		on, off, // 1^8 0^8
		off, on, off, on, off, on, off, on, // (0^8 1^8)^4
		on, off, on, off, on, off, on, off, // (1^8 0^8)^4
	}

	var out [BlockSize]byte

	for i := range BlockSize {
		out[i] = msb[BlockSize-1-i]
	}

	return out
}

// fA implements transform A (RFC 5831 §5.1): with X = x4||x3||x2||x1 (x1 the
// rightmost 64-bit word, stored at bytes #1..#8 = array[0:8]),
// A(X) = (x1 ⊕ x2) || x4 || x3 || x2.
// In from-right array order: x2 → [0:8], x3 → [8:16], x4 → [16:24],
// (x1 ⊕ x2) → [24:32].
func fA(in [BlockSize]byte) [BlockSize]byte {
	var out [BlockSize]byte

	copy(out[0:8], in[8:16])    // x2.
	copy(out[8:16], in[16:24])  // x3.
	copy(out[16:24], in[24:32]) // x4.

	for i := range wordSize {
		out[3*wordSize+i] = in[i] ^ in[wordSize+i] // x1 ⊕ x2.
	}

	return out
}

// pPerm[i] holds the input byte index feeding output byte i (0-based). Built
// from φ(i+1+4(k-1)) = 8i+k (RFC 5831 §5.1, 1-based, right-to-left numbering),
// applied as out[j] = in[φ(j)] (empirically the form matching gogost /
// gost-engine; see the differential test). So pPerm[j-1] = φ(j) - 1.
var pPerm = func() [BlockSize]int {
	var p [BlockSize]int

	for i := range numWords {
		for k := 1; k <= wordSize; k++ {
			j := i + 1 + numWords*(k-1) // byte position (1-based).
			phi := wordSize*i + k       // φ(j) (1-based).

			p[j-1] = phi - 1
		}
	}

	return p
}()

func fP(in [BlockSize]byte) [BlockSize]byte {
	var out [BlockSize]byte

	for i := range BlockSize {
		out[i] = in[pPerm[i]]
	}

	return out
}

// psiFoldWords are the 1-based η word indices XOR-folded into the top output
// word of ψ (RFC 5831 §5.3: η1⊕η2⊕η3⊕η4⊕η13⊕η16).
var psiFoldWords = [...]int{1, 2, 3, 4, 13, 16}

// fPsi implements transform ψ (RFC 5831 §5.3) over 16 sixteen-bit words η1..η16
// (η_j at array[2(j-1):2j], η1 rightmost). Output:
// ψ(X) = (η1⊕η2⊕η3⊕η4⊕η13⊕η16) || η16 || η15 || … || η2 — i.e. every word
// shifts down one position (η_{m+1} → slot m), the top slot (#16) receives the
// XOR fold, and η1 is dropped.
func fPsi(in [BlockSize]byte) [BlockSize]byte {
	w := func(j int) uint16 { // η_j, 1-based.
		return uint16(in[halfWordSize*(j-1)]) |
			uint16(in[halfWordSize*(j-1)+1])<<bitsPerByte
	}

	var out [BlockSize]byte

	for m := 1; m <= numHalfWords-1; m++ { // out word #m = η_{m+1}.
		out[halfWordSize*(m-1)] = in[halfWordSize*m]
		out[halfWordSize*(m-1)+1] = in[halfWordSize*m+1]
	}

	var fold uint16

	for _, j := range psiFoldWords {
		fold ^= w(j)
	}

	out[BlockSize-halfWordSize] = byte(fold)
	out[BlockSize-1] = byte(fold >> bitsPerByte)

	return out
}

func fPsiN(in [BlockSize]byte, n int) [BlockSize]byte {
	for range n {
		in = fPsi(in)
	}

	return in
}

func xor32(a, b [BlockSize]byte) [BlockSize]byte {
	var out [BlockSize]byte

	for i := range BlockSize {
		out[i] = a[i] ^ b[i]
	}

	return out
}

// encryptH runs the four ECB encryptions of the compression function (RFC 5831
// §5.2). H is split into four 8-byte words h1..h4 (h1 at array[0:8]); word i is
// encrypted under key Ki, output written to the same slot. No per-word byte
// reversal is needed in this convention.
func encryptH(h [BlockSize]byte, k1, k2, k3, k4 [BlockSize]byte) [BlockSize]byte {
	keys := [4]*[BlockSize]byte{&k1, &k2, &k3, &k4}

	var s [BlockSize]byte

	for i := range 4 {
		c := gost28147.NewCipher(keys[i][:], sboxCryptoProHash)
		c.Encrypt(s[i*8:i*8+8], h[i*8:i*8+8])
	}

	return s
}

// chi is the compression function χ(M, H) (RFC 5831 §5).
func chi(m, h [BlockSize]byte) [BlockSize]byte {
	// Key generation (§5.1): K1..K4 via transforms A and P with C2/C3/C4.
	u := h
	v := m
	k1 := fP(xor32(u, v))

	u = fA(u) // ⊕ C2 (all-zero).
	v = fA(fA(v))

	k2 := fP(xor32(u, v))

	u = xor32(fA(u), c3) // ⊕ C3.
	v = fA(fA(v))

	k3 := fP(xor32(u, v))

	u = fA(u) // ⊕ C4 (all-zero).
	v = fA(fA(v))

	k4 := fP(xor32(u, v))

	// Encryption (§5.2).
	s := encryptH(h, k1, k2, k3, k4)

	// Mixing (§5.3): ψ^61( H ⊕ ψ( M ⊕ ψ^12(S) ) ).
	t := fPsiN(s, psiMixInner)

	t = xor32(m, t)
	t = fPsi(t)
	t = xor32(h, t)
	t = fPsiN(t, psiMixOuter)

	return t
}

// addMod adds the 32-byte block b into acc modulo 2^256 with byte-wise carry
// (RFC 5831 §6 "(+)'", guide D7). Blocks are stored least-significant byte first
// (array[0] = byte #1), so the carry runs from index 0 upward.
func addMod(acc *[BlockSize]byte, b [BlockSize]byte) {
	var carry uint16

	for i := range BlockSize {
		sum := uint16(acc[i]) + uint16(b[i]) + carry

		acc[i] = byte(sum)
		carry = sum >> bitsPerByte
	}
}

// digest implements hash.Hash for GOST R 34.11-94 (CryptoPro param set).
type digest struct {
	h    [BlockSize]byte // chaining value.
	sum  [BlockSize]byte // Σ checksum (mod-2^256 addition).
	len  uint64          // total message length in bits (low 64 bits suffice).
	buf  [BlockSize]byte // partial block buffer.
	nbuf int             // bytes currently in buf.
}

// New returns a new hash.Hash computing the GOST R 34.11-94 digest under the
// CryptoPro parameter set.
func New() hash.Hash {
	return &digest{}
}

func (d *digest) Size() int      { return Size }
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	*d = digest{}
}

func (d *digest) Write(p []byte) (int, error) {
	n := len(p)

	if d.nbuf > 0 {
		take := min(BlockSize-d.nbuf, len(p))

		copy(d.buf[d.nbuf:], p[:take])

		d.nbuf += take

		p = p[take:]

		if d.nbuf == BlockSize {
			d.processBlock(d.buf)

			d.nbuf = 0
		}
	}

	for len(p) >= BlockSize {
		var blk [BlockSize]byte

		copy(blk[:], p[:BlockSize])
		d.processBlock(blk)

		p = p[BlockSize:]
	}

	if len(p) > 0 {
		copy(d.buf[:], p)

		d.nbuf = len(p)
	}

	return n, nil
}

// lenBlock encodes bitLen little-endian into a 32-byte block (array[0] = byte
// #1). Only the low 64 bits are populated; longer messages are out of scope.
func lenBlock(bitLen uint64) [BlockSize]byte {
	var b [BlockSize]byte

	for i := range wordSize {
		b[i] = byte(bitLen >> (bitsPerByte * i))
	}

	return b
}

func (d *digest) Sum(in []byte) []byte {
	// Snapshot state so Sum is non-destructive (guide D8).
	h := d.h
	sum := d.sum
	totalBits := d.len

	if d.nbuf > 0 {
		// Final partial block, left zero-padded: the fragment occupies the low
		// |M| bits, i.e. bytes #1..#nbuf = array[0:nbuf]; higher bytes zero.
		var m [BlockSize]byte

		copy(m[:], d.buf[:d.nbuf])

		totalBits += uint64(d.nbuf) * bitsPerByte

		h = chi(m, h)
		addMod(&sum, m)
	} else if totalBits == 0 {
		// Empty input (guide D1): match gost-engine / Tarantool with an extra
		// zero-block compression before the length and checksum blocks. gogost
		// omits this and yields a different digest.
		var zero [BlockSize]byte

		h = chi(zero, h)
	}

	// Absorb the length block, then the checksum block.
	h = chi(lenBlock(totalBits), h)
	h = chi(sum, h)

	return append(in, h[:]...)
}

// processBlock folds one full 32-byte message block into the state: H via χ,
// bit-length += 256, Σ += M mod 2^256.
func (d *digest) processBlock(m [BlockSize]byte) {
	d.h = chi(m, d.h)

	d.len += BlockSize * bitsPerByte
	addMod(&d.sum, m)
}

// Sum returns the GOST R 34.11-94 (CryptoPro) digest of b.
func Sum(b []byte) [Size]byte {
	d := New()
	d.Write(b)

	var out [Size]byte

	copy(out[:], d.Sum(nil))

	return out
}

var _ hash.Hash = New()
