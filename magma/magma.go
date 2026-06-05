// Package magma is a clean-room implementation of the GOST R 34.12-2015
// 64-bit block cipher "Magma" (RFC 8891), built from the clean-room guide
// (magma-gost34122015.md, colocated in this package) only.
//
// Magma is the GOST 28147-89 core pinned to:
//   - the fixed tc26 param-Z S-box, and
//   - RFC 8891's big-endian (MSB-first) byte/word numbering.
//
// The implementation realises the big-endian numbering exactly as the spec
// guide describes: reverse the four bytes within each key word (M1), reverse
// the whole 8-byte block on input and output (M2), and run an otherwise
// little-endian 28147-89 core with the tc26-Z S-box (M3).
//
// # References
//
//   - RFC 8891: https://github.com/bigbes/gostcrypto/blob/master/magma/rfc/rfc8891.txt
package magma

import "encoding/binary"

const (
	// BlockSize is the Magma block size in bytes (64 bits).
	BlockSize = 8
	// KeySize is the Magma key size in bytes (256 bits).
	KeySize = 32

	// sboxNibbles is the number of 4-bit nibbles (and S-box rows) in a
	// 32-bit word.
	sboxNibbles = 8
	// nibbleBits is the width of one S-box nibble in bits.
	nibbleBits = 4
	// nibbleMask masks off a single 4-bit nibble.
	nibbleMask = 0xF
	// wordBits is the width of the 32-bit half-block in bits (for rotation).
	wordBits = 32
	// rotBits is the round-function cyclic left-rotation amount (RFC 8891 §4).
	rotBits = 11
)

// sboxTC26Z is the fixed tc26 param-Z S-box, in the gogost/engine row
// convention where row s[i] substitutes nibble i counting from the LOW end
// (s[0] = low nibble). Transcribed verbatim from
// magma-gost34122015.md §2 (which states gogost s[i] == RFC
// Pi'_i, no transposition).
var sboxTC26Z = [8][16]uint8{
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1}, // s[0] == Pi'_0.
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15}, // s[1] == Pi'_1.
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0}, // s[2] == Pi'_2.
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11}, // s[3] == Pi'_3.
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12}, // s[4] == Pi'_4.
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0}, // s[5] == Pi'_5.
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7}, // s[6] == Pi'_6.
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}, // s[7] == Pi'_7.
}

// seqEncrypt is the 28147-89 32-round encrypt subkey order: X[0..7] three
// times forward, then X[7..0] reverse (sibling guide §4).
var seqEncrypt = [32]int{
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
}

// seqDecrypt is the 28147-89 32-round decrypt subkey order: X[0..7] once
// forward, then X[7..0] three times reverse (sibling guide §5).
var seqDecrypt = [32]int{
	0, 1, 2, 3, 4, 5, 6, 7,
	7, 6, 5, 4, 3, 2, 1, 0,
	7, 6, 5, 4, 3, 2, 1, 0,
	7, 6, 5, 4, 3, 2, 1, 0,
}

// Cipher is a Magma cipher instance holding the derived 28147-89 subkeys.
type Cipher struct {
	x [8]uint32 // little-endian 28147-89 subkeys derived from the reversed key.
}

// NewCipher returns a Magma cipher for the given 32-byte key. It panics if the
// key is not exactly KeySize bytes.
func NewCipher(key []byte) *Cipher {
	if len(key) != KeySize {
		panic("magma: invalid key size")
	}

	c := &Cipher{}
	// M1: reverse the 4 bytes within each 32-bit key word, then read the
	// 28147-89 subkeys little-endian from the reversed key. A per-word
	// byte-reversal followed by a little-endian read is exactly a big-endian
	// read of the original key word, which is what RFC 8891 §4.3 specifies.
	for i := range 8 {
		c.x[i] = binary.BigEndian.Uint32(key[4*i : 4*i+4])
	}

	return c
}

// rotl11 cyclically rotates a 32-bit value left by 11 bits.
func rotl11(x uint32) uint32 {
	return x<<rotBits | x>>(wordBits-rotBits)
}

// t applies the nibble substitution: row s[i] substitutes nibble i (low
// nibble first), result reassembled at the same positions.
func t(x uint32) uint32 {
	var out uint32

	for i := range sboxNibbles {
		n := (x >> (nibbleBits * i)) & nibbleMask

		out |= uint32(sboxTC26Z[i][n]) << (nibbleBits * i)
	}

	return out
}

// g is the round function: (a + k) mod 2^32 -> substitute -> rotl 11.
func g(a, k uint32) uint32 {
	return rotl11(t(a + k))
}

// Encrypt encrypts one 8-byte block from src into dst.
func (c *Cipher) Encrypt(dst, src []byte) {
	c.crypt(dst, src, &seqEncrypt)
}

// Decrypt decrypts one 8-byte block from src into dst.
func (c *Cipher) Decrypt(dst, src []byte) {
	c.crypt(dst, src, &seqDecrypt)
}

// BlockSize returns the cipher's block size in bytes, satisfying
// crypto/cipher.Block so modes (CTR, OMAC, MGM) can compose on it.
func (c *Cipher) BlockSize() int { return BlockSize }

// xcrypt runs the 32-round Feistel network using the given subkey schedule.
func (c *Cipher) xcrypt(n1, n2 uint32, seq *[32]int) (uint32, uint32) {
	for _, idx := range seq {
		n1, n2 = g(n1, c.x[idx])^n2, n1
	}

	return n1, n2
}

// crypt applies M2 (whole-block byte reversal in and out) around the core.
func (c *Cipher) crypt(dst, src []byte, seq *[32]int) {
	if len(src) < BlockSize {
		panic("magma: input block too small")
	}

	if len(dst) < BlockSize {
		panic("magma: output block too small")
	}

	// M2: reverse all 8 input bytes so the little-endian core read reproduces
	// Magma's big-endian numbering.
	var tmp [BlockSize]byte

	for j := range BlockSize {
		tmp[j] = src[BlockSize-1-j]
	}

	// 28147-89 core: little-endian split into N1 (low) and N2 (high).
	n1 := binary.LittleEndian.Uint32(tmp[0:4])
	n2 := binary.LittleEndian.Uint32(tmp[4:8])

	n1, n2 = c.xcrypt(n1, n2, seq)
	// Output half-swap (sibling D2): N2 to bytes 0-3, N1 to bytes 4-7.
	binary.LittleEndian.PutUint32(tmp[0:4], n2)
	binary.LittleEndian.PutUint32(tmp[4:8], n1)

	// M2: reverse all 8 output bytes back.
	for j := range BlockSize {
		dst[j] = tmp[BlockSize-1-j]
	}
}

// MagmaEncrypt encrypts a single 8-byte block under key and returns the
// ciphertext. It matches the conformance-harness surface in the spec guide.
func MagmaEncrypt(key, pt []byte) []byte {
	dst := make([]byte, BlockSize)
	NewCipher(key).Encrypt(dst, pt)

	return dst
}

// MagmaDecrypt decrypts a single 8-byte block under key and returns the
// plaintext.
func MagmaDecrypt(key, ct []byte) []byte {
	dst := make([]byte, BlockSize)
	NewCipher(key).Decrypt(dst, ct)

	return dst
}
