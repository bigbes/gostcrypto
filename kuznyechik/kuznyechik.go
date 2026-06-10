// Package kuznyechik is a clean-room pure-Go implementation of the
// Kuznyechik (GOST R 34.12-2015 / RFC 7801) 128-bit block cipher.
//
// It is derived solely from the specification in
// kuznyechik-gost34122015.md (which republishes RFC 7801)
// and imports no GOST backend.
//
// # Side channels
//
// This implementation is table-driven and NOT constant-time: it indexes lookup
// tables by secret state bytes, exposing cache-timing side channels. This
// matches the gogost/gost-engine references and the software-AES norm. See
// SECURITY.md for the full timing model and why it is accepted for this
// reference cipher.
//
// # References
//
//   - RFC 7801: https://github.com/bigbes/gostcrypto/blob/master/kuznyechik/rfc/rfc7801.txt
package kuznyechik

import (
	"crypto/cipher"
	"encoding/binary"
	"sync"
)

// BlockSize is the Kuznyechik block size in bytes (128 bits).
const BlockSize = 16

// keySize is the Kuznyechik key size in bytes (256 bits).
const keySize = 32

// gfReductionByte is the low byte of the 9-bit reduction polynomial
// x^8+x^7+x^6+x+1 used by the GF(2^8) multiply (RFC 7801 §4.2).
const gfReductionByte = 0xC3

// pi is the nonlinear S-box (π) from RFC 7801 §4.1.
var pi = [256]byte{
	0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
	0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
	0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
	0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
	0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
	0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
	0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
	0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
	0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
	0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
	0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
	0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
	0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
	0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
	0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
	0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
}

// piInv is the inverse S-box (π⁻¹), derived at init: piInv[pi[i]] = i.
var piInv [256]byte

// lc is the 16-coefficient L-transform vector (RFC 7801 §4.2), stored
// MS-first: lc[i] pairs with blk[i] where blk[0] is the most-significant byte.
var lc = [BlockSize]byte{
	0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
	0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01,
}

// cnst holds the 32 round constants C_1..C_32 (cnst[0] == C_1), built at init.
var cnst [32][BlockSize]byte

func init() {
	for i := range 256 {
		piInv[pi[i]] = byte(i)
	}

	// C_i = L(Vec_128(i)): seed the least-significant byte (index 15 in the
	// MS-first numbering) with i, then apply L. Constants are 1-indexed, so
	// cnst[i] carries i+1.
	for i := range 32 {
		var blk [BlockSize]byte

		blk[15] = byte(i + 1)
		l(&blk)

		cnst[i] = blk
	}
}

// gf multiplies a and b in GF(2)[x]/(x^8+x^7+x^6+x+1). The post-shift XOR
// mask is the low byte of the 9-bit polynomial, 0xC3.
func gf(a, b byte) byte {
	var c byte

	for b > 0 {
		if b&1 != 0 {
			c ^= a
		}

		if a&0x80 != 0 {
			a = (a << 1) ^ gfReductionByte
		} else {
			a <<= 1
		}

		b >>= 1
	}

	return c
}

// s applies the π S-box to each byte of the block (forward S transform).
func s(blk *[BlockSize]byte) {
	for i := range blk {
		blk[i] = pi[blk[i]]
	}
}

// sInv applies the inverse S-box to each byte (used only by Decrypt).
func sInv(blk *[BlockSize]byte) {
	for i := range blk {
		blk[i] = piInv[blk[i]]
	}
}

// r performs one LFSR step: the new byte is the GF dot product of the block
// with lc; the block shifts toward higher indices (the LS byte falls off) and
// the new byte enters index 0 (the MS position). RFC 7801 §4.3.
func r(blk *[BlockSize]byte) {
	t := blk[15]
	for i := range 15 {
		t ^= gf(blk[i], lc[i])
	}

	copy(blk[1:], blk[:15])

	blk[0] = t
}

// rInv reverses one r step: recover the byte that fell off index 15, shift the
// block back toward lower indices, and place the recovered byte at index 15.
func rInv(blk *[BlockSize]byte) {
	// After r, blk[0] is the LFSR output t and blk[1..15] are the old
	// blk[0..14]. The byte that fell off (old blk[15]) satisfies
	// t = old_blk[15] XOR sum(gf(old_blk[i], lc[i])) for i in 0..14.
	// Old blk[i] for i in 0..14 are the current blk[1..15].
	t := blk[0]

	var acc byte

	for i := range 15 {
		acc ^= gf(blk[i+1], lc[i])
	}

	old15 := t ^ acc

	copy(blk[:15], blk[1:])

	blk[15] = old15
}

// l applies the linear transform L = R^16 (RFC 7801 §4.3).
func l(blk *[BlockSize]byte) {
	for range 16 {
		r(blk)
	}
}

// lInv applies L^{-1} = (R^{-1})^16.
func lInv(blk *[BlockSize]byte) {
	for range 16 {
		rInv(blk)
	}
}

func xor(blk *[BlockSize]byte, k *[BlockSize]byte) {
	for i := range blk {
		blk[i] ^= k[i]
	}
}

// Fused S∘L lookup tables.
//
// One Kuznyechik round applies S (the π S-box, per byte) then the linear
// transform L. Because L is GF(2)-linear, L(S(x)) decomposes over the 16 byte
// positions:
//
//	L(S(x)) = XOR over pos of L(unit block with byte S(x[pos]) at position pos).
//
// encTable[pos][b] precomputes that single-position contribution: the 16-byte
// result of placing S(b) at position pos in an otherwise-zero block and applying
// L. A combined S+L round then becomes 16 table loads XORed together, replacing
// the per-bit gf() loop on the hot path. Each 16-byte entry is packed into two
// big-endian uint64 words so a round folds with two XORs per position instead of
// sixteen.
//
// Decrypt's round body is "L⁻¹ then S⁻¹" applied to a key-mixed block. S⁻¹ is
// bytewise and cheap; the per-bit gf() cost lived entirely in L⁻¹, so lInvTable
// fuses L⁻¹ alone (no S-box): lInvTable[pos][b] is L⁻¹ of the block holding raw
// byte b at position pos. Decrypt applies it as XOR of per-position lifts, then
// the bytewise sInv, matching the slow lInv/sInv output exactly.
//
// Every entry is derived by calling the verified clean-room s/l/lInv on
// generated unit vectors — no literal tables are introduced. The slow gf()/r()
// path above remains the source of truth and documents the math.
type tableEntry struct{ hi, lo uint64 }

var (
	encTable  [BlockSize][256]tableEntry
	lInvTable [BlockSize][256]tableEntry
	tableOnce sync.Once
)

func packEntry(b *[BlockSize]byte) tableEntry {
	return tableEntry{
		hi: binary.BigEndian.Uint64(b[0:8]),
		lo: binary.BigEndian.Uint64(b[8:16]),
	}
}

func buildTables() {
	for pos := range BlockSize {
		for b := range 256 {
			// encTable: S then L of S(b) at position pos.
			var e [BlockSize]byte

			e[pos] = pi[byte(b)]
			l(&e)

			encTable[pos][b] = packEntry(&e)

			// lInvTable: L⁻¹ of (raw byte b) at position pos. Used by Decrypt
			// to apply L⁻¹ to a full block as XOR of per-position lifts.
			var li [BlockSize]byte

			li[pos] = byte(b)
			lInv(&li)

			lInvTable[pos][b] = packEntry(&li)
		}
	}
}

// slEncrypt applies one S+L round (S then L) to blk using the fused tables.
func slEncrypt(blk *[BlockSize]byte) {
	var hi, lo uint64

	for pos := range BlockSize {
		t := &encTable[pos][blk[pos]]

		hi ^= t.hi
		lo ^= t.lo
	}

	binary.BigEndian.PutUint64(blk[0:8], hi)
	binary.BigEndian.PutUint64(blk[8:16], lo)
}

// lInvFast applies L⁻¹ to blk using the fused table.
func lInvFast(blk *[BlockSize]byte) {
	var hi, lo uint64

	for pos := range BlockSize {
		t := &lInvTable[pos][blk[pos]]

		hi ^= t.hi
		lo ^= t.lo
	}

	binary.BigEndian.PutUint64(blk[0:8], hi)
	binary.BigEndian.PutUint64(blk[8:16], lo)
}

// Cipher is a Kuznyechik block cipher instance holding the 10 expanded round
// keys.
type Cipher struct {
	ks [10][BlockSize]byte
}

var _ cipher.Block = (*Cipher)(nil)

// NewCipher returns a Cipher for the given 32-byte key. It panics if the key
// length is not 32 bytes.
func NewCipher(key []byte) *Cipher {
	if len(key) != keySize {
		panic("kuznyechik: invalid key size, want 32 bytes")
	}

	tableOnce.Do(buildTables)

	c := &Cipher{}
	c.expandKey(key)

	return c
}

// BlockSize returns the cipher block size (16), satisfying cipher.Block.
func (c *Cipher) BlockSize() int { return BlockSize }

// Encrypt encrypts the 16-byte block src into dst (RFC 7801 §4.5.1):
// 9 LSX rounds followed by a final round-key add with K_10.
func (c *Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("kuznyechik: input not full block")
	}

	if len(dst) < BlockSize {
		panic("kuznyechik: output not full block")
	}

	var blk [BlockSize]byte

	copy(blk[:], src)

	for i := range 9 {
		xor(&blk, &c.ks[i])
		slEncrypt(&blk) // fused S then L.
	}

	xor(&blk, &c.ks[9])
	copy(dst, blk[:])
}

// Decrypt decrypts the 16-byte block src into dst (RFC 7801 §4.5.2): the exact
// inverse of Encrypt, using L^{-1} then S^{-1}, final round-key add with K_1.
func (c *Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("kuznyechik: input not full block")
	}

	if len(dst) < BlockSize {
		panic("kuznyechik: output not full block")
	}

	var blk [BlockSize]byte

	copy(blk[:], src)

	for i := 9; i >= 1; i-- {
		xor(&blk, &c.ks[i])
		lInvFast(&blk) // fused L⁻¹ (table-driven; output identical to lInv).
		sInv(&blk)
	}

	xor(&blk, &c.ks[0])
	copy(dst, blk[:])
}

// expandKey derives the 10 round keys via the Feistel key schedule
// (RFC 7801 §4.4): K_1, K_2 are the key halves; then 4 outer iterations of 8
// Feistel rounds each produce the remaining pairs.
func (c *Cipher) expandKey(key []byte) {
	var kr0, kr1 [BlockSize]byte

	copy(kr0[:], key[0:16])
	copy(kr1[:], key[16:32])

	c.ks[0] = kr0
	c.ks[1] = kr1

	for i := range 4 {
		for j := range 8 {
			// F[C]: LSX[C](kr0) XOR kr1, then swap.
			krt := kr0
			xor(&krt, &cnst[8*i+j]) // X[C].
			slEncrypt(&krt)         // S then L (fused).
			xor(&krt, &kr1)         // XOR right half.

			kr1 = kr0 // swap.
			kr0 = krt
		}

		c.ks[2+2*i] = kr0
		c.ks[2+2*i+1] = kr1
	}
}
