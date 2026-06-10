// Package gost28147imit is a clean-room, pure-Go implementation of the GOST
// 28147-89 IMIT MAC (RFC 5830 §8) with CryptoPro key meshing (RFC 4357
// §2.3.2) and the gost-engine finalization order. It is built strictly from
// gost28147-imit.md (and its sibling cipher doc) without
// consulting gogost or any GOST implementation source.
//
// The IMIT is a CBC-MAC whose per-block transform is the GOST 28147-89
// encryption step truncated to 16 rounds (the SeqMAC schedule), with the
// MAC-specific "natural" octet ordering (no half-swap, unlike the 32-round
// cipher). The S-box constants are reused from the sibling cleanroom
// gost28147 package; the 16-round transform is implemented here directly
// because that package only exposes the 32-round Encrypt/Decrypt.
//
// # References
//
//   - RFC 5830: https://github.com/bigbes/gostcrypto/blob/master/gost28147imit/rfc/rfc5830.txt
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/gost28147imit/rfc/rfc4357.txt
package gost28147imit

import (
	"encoding/binary"

	"github.com/bigbes/gostcrypto/gost28147"
)

const (
	blockSize  = 8
	keySize    = 32
	meshPeriod = 1024
	tlsTagLen  = 4

	// sboxNibbles is the number of 4-bit nibbles (and S-box rows) in a
	// 32-bit word.
	sboxNibbles = 8
	// nibbleBits is the width of one S-box nibble in bits.
	nibbleBits = 4
	// nibbleMask masks off a single 4-bit nibble.
	nibbleMask = 0xF
	// wordBits is the width of the 32-bit half-block in bits (for rotation).
	wordBits = 32
	// rotBits is the round-function cyclic left-rotation amount (cipher doc §2).
	rotBits = 11
)

// cryptoProKeyMeshingKey is the 32-byte CryptoPro key-meshing constant C
// (guide §2.3; RFC 4357 §2.3.2). The new key is the ECB-decryption of these
// four blocks under the current key.
var cryptoProKeyMeshingKey = [32]byte{
	0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23,
	0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4,
	0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12,
	0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B,
}

// macCipher holds the 16-round MAC subkeys and S-box. It is rebuilt on each
// key mesh. The subkey split and S-box layout mirror the cleanroom cipher
// package (little-endian 32-bit subkeys X[0..7]).
type macCipher struct {
	x    [8]uint32
	sbox gost28147.SBox
}

func newMACCipher(key []byte, sbox gost28147.SBox) *macCipher {
	c := &macCipher{sbox: sbox}
	for i := range 8 {
		c.x[i] = binary.LittleEndian.Uint32(key[i*4 : i*4+4])
	}

	return c
}

// t applies the eight S-boxes nibble-by-nibble (cipher doc §2):
// t(x) = Σ over i=0..7 of s[i][(x>>4i)&0xF] << 4i.
func (c *macCipher) t(x uint32) uint32 {
	var out uint32

	for i := range uint(sboxNibbles) {
		nib := (x >> (nibbleBits * i)) & nibbleMask

		out |= uint32(c.sbox[i][nib]) << (nibbleBits * i)
	}

	return out
}

// f is the round function: t(x) cyclically left-rotated by 11 bits.
func (c *macCipher) f(x uint32) uint32 {
	y := c.t(x)
	return y<<rotBits | y>>(wordBits-rotBits)
}

// macBlock runs the 16-round SeqMAC transform in place on the 8-byte state:
// XOR the plaintext block into the state, read (n1=lo, n2=hi) little-endian,
// run 16 Feistel rounds with subkey schedule [0..7, 0..7], then write back in
// NATURAL order (lo=n1, hi=n2) — guide §1 / D2.
func (c *macCipher) macBlock(state, block []byte) {
	for i := range blockSize {
		state[i] ^= block[i]
	}

	n1 := binary.LittleEndian.Uint32(state[0:4])
	n2 := binary.LittleEndian.Uint32(state[4:8])
	// Two forward passes over X[0..7] = 16 rounds; no reverse pass.
	for range 2 {
		for k := range 8 {
			n1, n2 = c.f(n1+c.x[k])^n2, n1
		}
	}

	binary.LittleEndian.PutUint32(state[0:4], n1)
	binary.LittleEndian.PutUint32(state[4:8], n2)
}

// keyBytes serializes the current subkeys back to the 32-byte key form, so
// they can be ECB-decrypted for meshing via the public cipher.
func (c *macCipher) keyBytes() []byte {
	key := make([]byte, keySize)
	for i := range 8 {
		binary.LittleEndian.PutUint32(key[i*4:i*4+4], c.x[i])
	}

	return key
}

// mesh re-derives the key per CryptoPro key meshing (guide §2.3, D6): ECB-
// decrypt the 32-byte constant C with the current key (the 32-round cipher
// decrypt, NOT the 16-round MAC step) and adopt the result as the new key.
// The MAC state buffer is left untouched (iv=NULL on the engine path).
func (c *macCipher) mesh() {
	cur := gost28147.NewCipher(c.keyBytes(), c.sbox)

	var newKey [keySize]byte

	for i := range 4 {
		cur.Decrypt(newKey[i*8:i*8+8], cryptoProKeyMeshingKey[i*8:i*8+8])
	}

	for i := range 8 {
		c.x[i] = binary.LittleEndian.Uint32(newKey[i*4 : i*4+4])
	}
}

// imit computes the full 8-byte IMIT tag of msg under key/sbox, starting from
// an all-zero IV state, applying CryptoPro key meshing. This implements the
// gost-engine finalization order: full blocks first, a trailing partial is
// zero-padded and processed, and for total length 1..8 (count == 0 at
// finalization) one extra all-zero block is appended AFTER the data block
// (guide §2.1 rule 3 / D5).
//
// Non-zero-IV (UKM) IMIT — e.g. the key-transport IMIT over the session key
// (RFC 4357 §6.3, guide D8) — is implemented inline in keywrap.imit4, which
// also needs diversification-keyed rounds this package does not expose.
// See keywrap/keywrap.go and guide §D8 for that path.
func imit(key, msg []byte, sbox gost28147.SBox) []byte {
	c := newMACCipher(key, sbox)

	state := make([]byte, blockSize)

	// count = bytes of full blocks processed, wrapped mod 1024; the mesh
	// fires when count == 1024 BEFORE processing the next block, and the
	// counter advances count = count%1024 + 8 after each block (guide §2.4).
	count := 0
	process := func(block []byte) {
		if count == meshPeriod {
			c.mesh()
		}

		c.macBlock(state, block)

		count = count%meshPeriod + blockSize
	}

	// A trailing 1..8 bytes are deferred to finalization so the short-message
	// (count == 0) rule can fire for exactly-8-byte input too. Callers guard
	// against empty msg (see IMIT); an empty msg here returns the iv state.
	if len(msg) > 0 {
		// Mirror the engine's strict "> 8" deferral: process blocks while more
		// than 8 bytes remain.
		i := 0
		for len(msg)-i > blockSize {
			process(msg[i : i+blockSize])

			i += blockSize
		}

		// remaining = msg[i:], length in [1..8].
		rem := msg[i:]

		var blk [blockSize]byte

		copy(blk[:], rem) // zero-padded if rem < 8.

		dataCountWasZero := count == 0

		process(blk[:])

		// Trailing all-zero block for total length 1..8 (count was 0 before
		// the data block) — guide §2.1 rule 3 / D5.
		if dataCountWasZero {
			var zero [blockSize]byte

			process(zero[:])
		}
	}

	out := make([]byte, blockSize)
	copy(out, state)

	return out
}

// SeqMACBlock runs the 16-round SeqMAC transform of a single 8-byte block under
// the given 32-byte key and S-box, starting from an all-zero state (i.e. the
// per-block step of the GOST 28147-89 IMIT MAC with a zero IV). It returns the
// resulting 8-byte state. This exposes the 16-round schedule — distinct from the
// 32-round Encrypt/Decrypt — that record-layer IMIT construction in callers
// outside this package needs but which gost28147.Cipher does not expose.
//
// key must be 32 bytes; block must be 8 bytes.
// Panics if len(key) != 32 or len(block) != 8.
func SeqMACBlock(key []byte, sbox gost28147.SBox, block []byte) []byte {
	if len(key) != keySize {
		panic("gost28147imit: SeqMACBlock: key must be 32 bytes")
	}

	if len(block) != blockSize {
		panic("gost28147imit: SeqMACBlock: block must be 8 bytes")
	}

	c := newMACCipher(key, sbox)
	state := make([]byte, blockSize)
	c.macBlock(state, block)

	return state
}

// IMIT computes the 4-byte TLS-truncated GOST 28147-89 IMIT tag of msg under
// the given 32-byte key, using the CryptoPro-A S-box and an all-zero IV, with
// CryptoPro key meshing. RFC 9189 §4.2 truncates the 8-byte IMIT to its
// leading 4 bytes for TLS.
func IMIT(key, msg []byte) []byte {
	if len(key) != keySize {
		panic("gost28147imit: bad key size")
	}

	if len(msg) == 0 {
		// An empty message would return the key-independent all-zero IV state
		// (0x0000000000000000), which is not a meaningful MAC. Note: gost-engine
		// succeeds on empty input and returns 0x00000000 (it processes zero
		// blocks and emits the IV state); this package rejects it instead.
		// TODO.md does not list this as a known divergence — TLS framing ensures
		// the MAC input is never empty (the prefix is >= 13 bytes, guide D7), so
		// the divergence is unreachable in practice. We reject loudly rather than
		// emitting a forgeable constant.
		panic("gost28147imit: empty message")
	}

	full := imit(key, msg, gost28147.SboxCryptoProA)

	return full[:tlsTagLen]
}
