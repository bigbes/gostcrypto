// Package ctracpkm implements GOST R 34.13-2015 CTR (gamma counter) mode and
// the RFC 8645 ACPKM intra-record key-meshing layered on top of it.
//
// This is a clean-room re-implementation built strictly from
// ctr-acpkm.md plus the cited RFCs (RFC 8645, GOST R
// 34.13-2015). It imports no gogost and carries no build tags.
//
// CTR turns a block cipher into a stream cipher: each plaintext byte is XORed
// with a keystream ("gamma") byte produced by encrypting a monotonically
// increasing counter block. ACPKM re-derives the cipher key after every
// sectionSize bytes of keystream by encrypting the fixed public constant D
// under the current key. The counter is never reset by ACPKM — only the key
// changes.
//
// # References
//
//   - RFC 8645: https://github.com/bigbes/gostcrypto/blob/master/ctracpkm/rfc/rfc8645.txt
//   - GOST R 34.13-2015: https://github.com/bigbes/gostcrypto/blob/master/ctracpkm/rfc/GOST_R_34.13-2015.pdf
package ctracpkm

import (
	"crypto/cipher"
	"errors"
	"slices"

	"github.com/bigbes/gostcrypto/internal/alias"
)

// acpkmD is the public ACPKM constant D (RFC 8645 §6.2.1). D is the 1024-bit
// string 0x80,0x81,...,0xFE,0xFF; with a 256-bit (32-byte) key only the first
// 32 bytes (0x80..0x9F) are ever used. The same constant is used for both
// Magma and Kuznyechik. Guide: ctr-acpkm.md "ACPKM transformation".
var acpkmD = [32]byte{
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
}

// Default per-suite ACPKM section sizes wired by the RFC 9367 TLS suites.
// Guide §"Where this repo uses it": Kuznyechik 4096, Magma 1024.
const (
	SectionKuznyechik = 4096
	SectionMagma      = 1024
)

// acpkmKeySize is the ACPKM section-key size in bytes (256-bit key). The master
// key and every re-derived section key are exactly this many bytes.
const acpkmKeySize = 32

// CTR is a GOST CTR / CTR-ACPKM keystream generator. It satisfies
// cipher.Stream. Split XORKeyStream calls produce the same output as a single
// one-shot call (the partial-block offset is carried across calls).
type CTR struct {
	newBlock    func([]byte) cipher.Block // re-key factory; nil ⇒ plain CTR.
	block       cipher.Block              // current section key's cipher.
	blockSize   int                       // n.
	iv          []byte                    // running counter (len == blockSize).
	gamma       []byte                    // current keystream block E(counter).
	num         int                       // bytes already consumed from gamma.
	sectionSize int                       // ACPKM section N; 0 ⇒ plain CTR.
	sinceRekey  int                       // keystream bytes under current key.
}

var _ cipher.Stream = (*CTR)(nil)

// NewCTR builds a plain GOST CTR stream over the given block cipher. iv is the
// full n-byte counter, already assembled (high n/2 bytes = nonce, low n/2 =
// zeros). It is copied; the caller's slice is not retained.
//
// Guide §"CTR mode": "the full n-byte counter is supplied to NewCTR already
// assembled".
func NewCTR(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("ctracpkm: IV length must equal block size")
	}

	c := &CTR{
		block:     b,
		blockSize: bs,
		iv:        make([]byte, bs),
		gamma:     make([]byte, bs),
		num:       bs, // force a fresh gamma block on first use.
	}
	copy(c.iv, iv)

	return c
}

// NewCTRACPKM builds a CTR-ACPKM stream. newBlock constructs a cipher.Block
// from a 32-byte key; key is the initial (master) section key; iv is the full
// n-byte counter; sectionSize is the ACPKM section N in bytes.
//
// sectionSize must be a positive multiple of the block size, or zero. A zero
// sectionSize disables ACPKM and degrades to plain CTR (NewCTRACPKM(...,0) ≡
// NewCTR). Guide §"ACPKM re-keying schedule".
func NewCTRACPKM(newBlock func(key []byte) cipher.Block, key, iv []byte, sectionSize int) cipher.Stream {
	if newBlock == nil {
		panic("ctracpkm: newBlock must not be nil")
	}

	if sectionSize < 0 {
		panic("ctracpkm: negative section size")
	}

	if len(key) != acpkmKeySize {
		// ACPKM re-keys by encrypting the 32-byte constant D, so the derived
		// section key is always 32 bytes; the master key must match.
		panic("ctracpkm: ACPKM key must be 32 bytes")
	}

	b := newBlock(key)
	bs := b.BlockSize()

	// The ACPKM rekey iterates in steps of bs over the 32-byte D constant.
	// A block size that does not divide 32 would cause a slice-bounds panic
	// inside rekeyACPKM after a full section has already been emitted. Fail
	// early and descriptively instead.
	if acpkmKeySize%bs != 0 {
		panic("ctracpkm: block size must divide the 32-byte ACPKM key")
	}

	if len(iv) != bs {
		panic("ctracpkm: IV length must equal block size")
	}

	if sectionSize%bs != 0 {
		panic("ctracpkm: section size must be a multiple of the block size")
	}

	c := &CTR{
		newBlock:    newBlock,
		block:       b,
		blockSize:   bs,
		iv:          make([]byte, bs),
		gamma:       make([]byte, bs),
		num:         bs,
		sectionSize: sectionSize,
	}
	copy(c.iv, iv)

	return c
}

// errShortDst is returned conceptually; XORKeyStream panics to match the
// cipher.Stream contract instead.
var errShortDst = errors.New("ctracpkm: output smaller than input")

// XORKeyStream XORs src with the keystream and writes the result to dst.
// dst must be at least len(src). It may be called repeatedly; partial-block
// gamma is carried across calls.
func (c *CTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic(errShortDst)
	}

	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("ctracpkm: invalid buffer overlap")
	}

	for i := range src {
		if c.num == c.blockSize {
			// Need a fresh gamma block. ACPKM rekeys BEFORE generating the
			// first block of a new section: if we have produced >= sectionSize
			// bytes under the current key, advance the key first. The counter
			// is NOT reset. Guide delta #2 / #3.
			if c.sectionSize > 0 && c.sinceRekey >= c.sectionSize {
				c.rekeyACPKM()

				c.sinceRekey = 0
			}

			c.block.Encrypt(c.gamma, c.iv)
			incCounter(c.iv)

			c.num = 0
		}

		dst[i] = src[i] ^ c.gamma[c.num]
		c.num++

		c.sinceRekey++
	}
}

// rekeyACPKM advances the section key: newKey = E_K(D_1) || ... || E_K(D_J)
// where each D_j is the j-th block of D and E uses the ENCRYPT direction of
// the retiring key. Only the block cipher is replaced; the counter is
// untouched. Guide §"ACPKM transformation", deltas #4 and #5.
func (c *CTR) rekeyACPKM() {
	if c.newBlock == nil {
		// Plain CTR has no re-key factory; nothing to do.
		return
	}

	n := c.blockSize
	newKey := make([]byte, len(acpkmD)) // k == 32 == len(D used).

	for off := 0; off < len(newKey); off += n {
		c.block.Encrypt(newKey[off:off+n], acpkmD[off:off+n])
	}

	c.block = c.newBlock(newKey)
}

// incCounter increments the counter block as a single big-endian integer:
// from the last byte upward, ++, stop on no wrap. Guide §"CTR mode"
// (delta #1): the IV sits in the HIGH half, the running counter in the low
// half, incremented big-endian.
func incCounter(ctr []byte) {
	for i := range slices.Backward(ctr) {
		ctr[i]++
		if ctr[i] != 0 {
			return
		}
	}
}
