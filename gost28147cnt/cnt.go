// Package gost28147cnt is a clean-room, pure-Go implementation of the GOST
// 28147-89 CNT (counter / gamma, *gammirovaniye*) stream mode, built strictly
// from gost28147-cnt.md without consulting gogost,
// internal/gost, or tls/internal/record implementation source.
//
// CNT produces a keystream ("gamma") by ECB-encrypting a counter that is
// advanced by two fixed additive constants between blocks; the gamma is XORed
// with the plaintext. Encryption and decryption are the same operation
// (RFC 5830 §6). The underlying single-block ECB transform is reused from the
// sibling gost28147 package — CNT borrows only E_K(block)->block.
//
// This implementation supports arbitrary-length streaming across calls: the
// partial-block gamma tail is carried correctly between XORKeyStream calls,
// which is the whole point (the gogost gost28147.CTR cannot stream — see the
// guide's delta D4). CryptoPro key meshing (RFC 4357 §2.3.2) is applied every
// 1024 bytes of keystream, matching the TLS GOST suites.
//
// # References
//
//   - RFC 5830: https://github.com/bigbes/gostcrypto/blob/master/gost28147cnt/rfc/rfc5830.txt
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/gost28147cnt/rfc/rfc4357.txt
package gost28147cnt

import (
	"encoding/binary"

	"github.com/bigbes/gostcrypto/gost28147"
)

// Counter-step constants (RFC 5830 Appendix A).
const (
	// c2 is added to the lower half (IV bytes [0:4]) modulo 2^32.
	c2 = 0x01010101
	// c1 is added to the upper half (IV bytes [4:8]) modulo 2^32-1
	// (end-around carry).
	c1 = 0x01010104

	// meshThreshold is the CryptoPro key-meshing boundary in keystream bytes
	// (RFC 4357 §2.3.2).
	meshThreshold = 1024
)

// cryptoProKeyMeshingKey is the 32-byte constant decrypted under the current
// key to derive the next key at each meshing boundary
// (RFC 4357 §2.3.2 / gost28147-cnt.md).
var cryptoProKeyMeshingKey = [32]byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

// CNT is a streaming GOST 28147-89 counter-mode keystream generator.
//
// State persists across XORKeyStream calls (matching OpenSSL's
// EVP_CIPHER_CTX reuse and the TLS record layer's per-connection instance):
//   - iv:     the current 8-byte counter state.
//   - count:  processed keystream bytes since the last meshing, for the
//     1024-byte CryptoPro key-meshing boundary.
//   - gamma:  the current gamma block.
//   - num:    offset into gamma already consumed (partial-block carry).
//   - first:  true until the first gamma block is generated (seeds iv via E_K).
type CNT struct {
	c     *gost28147.Cipher
	sbox  gost28147.SBox
	iv    [8]byte
	gamma [8]byte
	num   int
	count int
	first bool
}

// NewCNT builds a CNT keystream generator over the configured block cipher c
// and an 8-byte IV (the synchro value S). The cipher's S-box selection (and
// hence the TLS suite — CryptoPro-A for 0x0081, tc26-Z for 0xFF85 / 0xC102)
// is whatever c was constructed with; CNT itself is S-box-agnostic.
//
// The S-box is captured here (not exposed by *Cipher) so key meshing can
// rebuild the cipher under the derived key.
func NewCNT(c *gost28147.Cipher, iv []byte, sbox gost28147.SBox) *CNT {
	if len(iv) != gost28147.BlockSize {
		panic("gost28147cnt: IV must be 8 bytes")
	}

	s := &CNT{c: c, sbox: sbox, first: true}
	copy(s.iv[:], iv)

	return s
}

// XORKeyStream XORs src into dst using the CNT keystream, advancing the
// generator state. dst may overlap src exactly (or not at all). Output length
// equals input length — CNT is a stream mode with no padding (guide D8).
//
// Partial gamma is carried across calls via s.num, so streaming an arbitrary
// byte sequence in any number of XORKeyStream calls at any boundaries yields
// the same result as a single call (guide D4, step 3).
func (s *CNT) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("gost28147cnt: dst shorter than src")
	}

	for i := range src {
		if s.num == 0 {
			s.nextGamma()
		}

		dst[i] = src[i] ^ s.gamma[s.num]
		s.num = (s.num + 1) % gost28147.BlockSize
	}
}

// meshKey performs one CryptoPro key-meshing step (RFC 4357 §2.3.2):
// derive a new key by ECB-decrypting the meshing constant under the current
// key (four blocks), re-key the cipher, then re-encrypt the current counter
// IV under the new key. count is NOT reset by the caller (guide D6).
func (s *CNT) meshKey() {
	var newKey [32]byte

	for i := range 4 {
		s.c.Decrypt(newKey[i*8:i*8+8], cryptoProKeyMeshingKey[i*8:i*8+8])
	}

	s.c = gost28147.NewCipher(newKey[:], s.sbox)

	var nextIV [8]byte

	s.c.Encrypt(nextIV[:], s.iv[:])

	s.iv = nextIV
}

// nextGamma advances the counter by one block and fills s.gamma with the next
// 8 keystream bytes (RFC 5830 §6.1; guide steps D1–D3, D6).
func (s *CNT) nextGamma() {
	// Key meshing fires at exactly 1024 processed keystream bytes, BEFORE the
	// block, and does not reset count (guide D6).
	if s.count == meshThreshold {
		s.meshKey()

		s.count = 0
	}

	var buf [8]byte

	if s.first {
		// First block: the counter is seeded with E_K(IV) (guide D3).
		s.c.Encrypt(buf[:], s.iv[:])

		s.first = false
	} else {
		// Subsequent blocks: carry the current counter state as-is; do NOT
		// re-encrypt the IV before incrementing (guide D3).
		buf = s.iv
	}

	// Lower half (bytes [0:4]): + C2 mod 2^32 (guide D1, D2).
	lo := binary.LittleEndian.Uint32(buf[0:4])

	lo += c2
	binary.LittleEndian.PutUint32(buf[0:4], lo)

	// Upper half (bytes [4:8]): + C1 mod 2^32-1 via end-around carry
	// (guide D1, D2). 0 is never normalised, matching the engine.
	hi := binary.LittleEndian.Uint32(buf[4:8])
	old := hi

	hi += c1

	if old > hi {
		hi++
	}

	binary.LittleEndian.PutUint32(buf[4:8], hi)

	// Store the incremented counter back, then produce the gamma block.
	s.iv = buf
	s.c.Encrypt(s.gamma[:], buf[:])

	// Advance the meshing byte counter: count = count mod 1024 + 8 (guide D6).
	s.count = s.count%meshThreshold + gost28147.BlockSize
}
