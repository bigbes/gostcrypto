// Package gost28147 is a clean-room, pure-Go implementation of the GOST
// 28147-89 block cipher core (ECB single-block encrypt/decrypt, 32-round),
// built strictly from gost28147-cipher.md without consulting
// gogost or any GOST implementation source. No build tags, no gogost import.
//
// # References
//
//   - RFC 5830: https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc5830.txt
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/gost28147/rfc/rfc4357.txt
package gost28147

import "encoding/binary"

const (
	// BlockSize is the GOST 28147-89 block size in bytes (64-bit block).
	BlockSize = 8
	// KeySize is the GOST 28147-89 key size in bytes (256-bit key).
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
	// rotBits is the round-function cyclic left-rotation amount (guide §2).
	rotBits = 11
)

// SBox is eight rows of sixteen nibbles. Row s[i] substitutes nibble i of the
// 32-bit word (row 0 = lowest nibble, bits 0..3; row 7 = highest, bits 28..31).
// This is the gogost/engine row convention (no transposition) per the guide §8.
type SBox = [8][16]byte

// SboxCryptoProA is id-Gost28147-89-CryptoPro-A-ParamSet (OID 1.2.643.2.2.31.1).
var SboxCryptoProA = SBox{
	{9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5},
	{3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1},
	{14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9},
	{14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6},
	{11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6},
	{3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6},
	{1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14},
	{11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4},
}

// SboxTC26Z is id-tc26-gost-28147-param-Z (OID 1.2.643.7.1.2.5.1.1).
var SboxTC26Z = SBox{
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
}

// Per-round subkey index schedules (guide §4, §5).
var (
	seqEncrypt = [32]int{
		0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
		0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
	}
	seqDecrypt = [32]int{
		0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
		7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0,
	}
)

// Cipher is a configured GOST 28147-89 block cipher.
type Cipher struct {
	x    [8]uint32 // subkeys X[0..7].
	sbox SBox
}

// NewCipher builds a Cipher from a 32-byte key and an S-box. The key is split
// into eight little-endian 32-bit subkeys (guide §1, step 3).
func NewCipher(key []byte, sbox SBox) *Cipher {
	if len(key) != KeySize {
		panic("gost28147: bad key size")
	}

	c := &Cipher{sbox: sbox}
	for i := range 8 {
		c.x[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}

	return c
}

// Encrypt encrypts one 8-byte block. src is read little-endian into (N1,N2);
// after 32 rounds the halves are written back SWAPPED — N2 to bytes 0..3,
// N1 to bytes 4..7 (guide §1, §6, D2).
func (c *Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("gost28147: short buffer")
	}

	n1 := binary.LittleEndian.Uint32(src[0:4])
	n2 := binary.LittleEndian.Uint32(src[4:8])

	n1, n2 = c.xcrypt(&seqEncrypt, n1, n2)
	binary.LittleEndian.PutUint32(dst[0:4], n2)
	binary.LittleEndian.PutUint32(dst[4:8], n1)
}

// Decrypt decrypts one 8-byte block using the reversed key schedule.
func (c *Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("gost28147: short buffer")
	}

	n1 := binary.LittleEndian.Uint32(src[0:4])
	n2 := binary.LittleEndian.Uint32(src[4:8])

	n1, n2 = c.xcrypt(&seqDecrypt, n1, n2)
	binary.LittleEndian.PutUint32(dst[0:4], n2)
	binary.LittleEndian.PutUint32(dst[4:8], n1)
}

// BlockSize returns the cipher's block size in bytes, satisfying
// crypto/cipher.Block so modes (CNT, CTR, OMAC, IMIT) can compose on it.
func (c *Cipher) BlockSize() int { return BlockSize }

// t applies the eight S-boxes nibble-by-nibble (guide §2):
// t(x) = Σ over i=0..7 of s[i][(x>>4i)&0xF] << 4i.
func (c *Cipher) t(x uint32) uint32 {
	var out uint32

	for i := range uint(sboxNibbles) {
		nib := (x >> (nibbleBits * i)) & nibbleMask

		out |= uint32(c.sbox[i][nib]) << (nibbleBits * i)
	}

	return out
}

// f is the round function: t(x) cyclically left-rotated by 11 bits (guide §2).
func (c *Cipher) f(x uint32) uint32 {
	y := c.t(x)
	return y<<rotBits | y>>(wordBits-rotBits)
}

// xcrypt runs the Feistel network over the given subkey-index schedule.
// Each round: (N1,N2) <- (f(N1 + X[seq[i]]) ^ N2, N1) with add mod 2^32.
func (c *Cipher) xcrypt(seq *[32]int, n1, n2 uint32) (uint32, uint32) {
	for i := range 32 {
		n1, n2 = c.f(n1+c.x[seq[i]])^n2, n1
	}

	return n1, n2
}
