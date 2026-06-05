// Package keywrap is a clean-room, pure-Go implementation of the CryptoPro
// KeyWrap algorithm together with the CryptoPro KEK diversification step
// (RFC 4357 §6.3 / §6.5). It is built strictly from
// keywrap-cryptopro.md (and the cited RFCs) without consulting
// gogost, internal/gost, or the TLS record layer implementation.
//
// The wrap encrypts a 32-byte GOST 28147-89 session key (CEK) under a 32-byte
// key-encryption key (KEK) and produces a 44-byte blob laid out as
//
//	UKM(8) | CEK_ENC(32) | CEK_MAC(4)
//
// where CEK_ENC is the ECB encryption of CEK under the UKM-diversified key
// KEK(UKM), and CEK_MAC is the 4-byte GOST 28147-89 IMIT of CEK keyed with
// KEK(UKM) and started from the non-zero chaining state IV = UKM.
//
// The block cipher, its S-boxes, and CFB feedback are reused from / mirror the
// sibling cleanroom gost28147 package; the IMIT here is implemented inline
// because the wrap MAC needs an arbitrary 8-byte initial state (IV = UKM), an
// arbitrary S-box, exactly four full blocks, and NO key meshing or zero
// padding block — none of which the sibling gost28147imit.IMIT entry point
// exposes (guide §D5).
//
// # References
//
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/keywrap/rfc/rfc4357.txt
package keywrap

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bigbes/gostcrypto/gost28147"
)

// Sbox re-exports the cleanroom GOST 28147-89 S-box type so callers select the
// wrap S-box by certificate type (guide "S-box selection rule").
type Sbox = gost28147.SBox

// Compile-time guard: KeyWrapCryptoPro keeps the exact entry-point signature
// the guide specifies (and that the internal/gost oracle mirrors), so the
// differential test calls both through one shape. There is no cipher.Block /
// hash.Hash / cipher.AEAD to assert here — the wrap is a pure function; those
// interfaces belong to the sibling gost28147 / gost28147imit primitives this
// package composes, not to a key-transport wrap.
var _ func(Sbox, []byte, []byte, []byte) ([]byte, error) = KeyWrapCryptoPro

// SboxTC26Z is id-tc26-gost-28147-param-Z (OID 1.2.643.7.1.2.5.1.1), selected
// for GOST R 34.10-2012 certificates (TLS suites 0xFF85 / 0xC102).
var SboxTC26Z = gost28147.SboxTC26Z

// SboxCryptoProA is id-Gost28147-89-CryptoPro-A-ParamSet (OID 1.2.643.2.2.31.1),
// selected for GOST R 34.10-2001 certificates (TLS suite 0x0081).
var SboxCryptoProA = gost28147.SboxCryptoProA

const (
	blockSize = gost28147.BlockSize // 8
	keySize   = gost28147.KeySize   // 32
	ukmSize   = 8
	macSize   = 4
	wrapSize  = ukmSize + keySize + macSize // 44

	// macRotate is the left-rotation amount in the GOST 28147-89 MAC round (11).
	macRotate = 11
	// wordBits is the width in bits of a GOST 28147-89 round word.
	wordBits = 32
	// sboxCount is the number of S-boxes applied nibble-by-nibble in t (8).
	sboxCount = 8
	// nibbleMask masks one 4-bit S-box input nibble.
	nibbleMask = 0xF
	// nibbleBits is the width in bits of one S-box nibble.
	nibbleBits = 4
)

// Static wrap-input validation errors (wrapped with %w by KeyWrapCryptoPro).
var (
	errKEKSize        = errors.New("keywrap: kek has wrong length")
	errUKMSize        = errors.New("keywrap: ukm has wrong length")
	errSessionKeySize = errors.New("keywrap: sessionKey has wrong length")
)

// KeyWrapCryptoPro wraps a 32-byte session key (CEK) under a 32-byte KEK using
// the given S-box and 8-byte UKM, per RFC 4357 §6.3. It returns the 44-byte
// blob UKM(8) | CEK_ENC(32) | CEK_MAC(4).
func KeyWrapCryptoPro(sbox Sbox, kek, ukm, sessionKey []byte) ([]byte, error) {
	if len(kek) != keySize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errKEKSize, keySize, len(kek))
	}

	if len(ukm) != ukmSize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errUKMSize, ukmSize, len(ukm))
	}

	if len(sessionKey) != keySize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errSessionKeySize, keySize, len(sessionKey))
	}

	// Step 2: diversify the KEK with the UKM.
	kekUKM := diversify(sbox, kek, ukm)

	c := gost28147.NewCipher(kekUKM, sbox)

	out := make([]byte, wrapSize)
	// [0:8] verbatim UKM.
	copy(out[0:ukmSize], ukm)

	// Step 4: ECB-encrypt CEK under KEK(UKM) as four independent 8-byte blocks.
	for i := 0; i < keySize; i += blockSize {
		c.Encrypt(out[ukmSize+i:ukmSize+i+blockSize], sessionKey[i:i+blockSize])
	}

	// Step 3: 4-byte IMIT of CEK keyed with KEK(UKM), IV = UKM.
	mac := imit4(sbox, kekUKM, ukm, sessionKey)
	copy(out[ukmSize+keySize:], mac)

	return out, nil
}

// diversify implements the CryptoPro KEK diversification algorithm
// (RFC 4357 §6.5). Given the 32-byte KEK and 8-byte UKM it returns KEK(UKM).
//
// Eight rounds; in each round i the current 32-byte key is read as eight
// little-endian 32-bit words w[0..7] (D1). Bit j of ukm[i] (LSB-first, mask
// 1<<j, D2) routes w[j] into sum S1 (bit set) or S2 (bit clear); both sums are
// uint32 and wrap mod 2^32 (D3). The 8-byte CFB IV is LE32(S1) || LE32(S2),
// and the current key is CFB-encrypted under itself in place (self-keyed, D4).
// Diversify exposes the CryptoPro KEK diversification (RFC 4357 §6.5) so
// callers that need the intermediate diversified key (e.g. test-vector
// cross-checks) can compute it without re-implementing the eight CFB rounds.
// kek must be 32 bytes, ukm 8 bytes; it returns the 32-byte diversified key.
func Diversify(sbox Sbox, kek, ukm []byte) []byte { return diversify(sbox, kek, ukm) }

func diversify(sbox Sbox, kek, ukm []byte) []byte {
	key := make([]byte, keySize)
	copy(key, kek)

	for i := range 8 {
		var s1, s2 uint32

		for j := range 8 {
			w := binary.LittleEndian.Uint32(key[j*4 : j*4+4])
			if ukm[i]&(1<<uint(j)) != 0 {
				s1 += w
			} else {
				s2 += w
			}
		}

		var iv [blockSize]byte

		binary.LittleEndian.PutUint32(iv[0:4], s1)
		binary.LittleEndian.PutUint32(iv[4:8], s2)

		// Self-keyed CFB encrypt of the 32-byte key in place under itself.
		cfbEncrypt(sbox, key, iv[:], key)
	}

	return key
}

// cfbEncrypt performs GOST 28147-89 CFB encryption of src into dst (which may
// alias src), keyed with cipherKey, IV = iv. Matches gost_enc_cfb: for each
// block, gamma = E(feedback); ct = pt XOR gamma; feedback = ct (D4). src must
// be a whole number of 8-byte blocks (the diversification key is 32 bytes).
func cfbEncrypt(sbox Sbox, cipherKey, iv, src []byte) {
	c := gost28147.NewCipher(cipherKey, sbox)

	var feedback [blockSize]byte

	copy(feedback[:], iv)

	var gamma [blockSize]byte

	for off := 0; off < len(src); off += blockSize {
		c.Encrypt(gamma[:], feedback[:])

		for k := range blockSize {
			ct := src[off+k] ^ gamma[k]

			src[off+k] = ct
			feedback[k] = ct
		}
	}
}

// imit4 computes the 4-byte GOST 28147-89 IMIT of msg (a whole number of
// 8-byte blocks; here exactly 32 bytes) keyed by macKey (= KEK(UKM)) under the
// given S-box, starting from the non-zero 8-byte chaining state iv (= UKM).
// The per-block transform is CBC chaining: state = E16(state XOR block), where
// E16 is the 16-round MAC schedule (two forward passes over X[0..7], no
// half-swap on output). The tag is the leading 4 bytes of the 8-byte state,
// LE32(n1) (D5, D6). No padding block, no key meshing (D7) — msg is a whole
// multiple of 8 and only 32 bytes.
func imit4(sbox Sbox, macKey, iv, msg []byte) []byte {
	var x [8]uint32

	for i := range 8 {
		x[i] = binary.LittleEndian.Uint32(macKey[i*4 : i*4+4])
	}

	state := make([]byte, blockSize)
	copy(state, iv)

	for off := 0; off < len(msg); off += blockSize {
		for k := range blockSize {
			state[k] ^= msg[off+k]
		}

		macStep(sbox, &x, state)
	}

	out := make([]byte, macSize)
	copy(out, state[:macSize])

	return out
}

// macStep applies the 16-round GOST 28147-89 MAC transform in place to the
// 8-byte state: two forward passes over X[0..7] (16 rounds) and writes the
// halves back in NATURAL order (n1 low, n2 high) — the IMIT step, distinct
// from the 32-round Encrypt which also half-swaps the output.
func macStep(sbox Sbox, x *[8]uint32, state []byte) {
	n1 := binary.LittleEndian.Uint32(state[0:4])
	n2 := binary.LittleEndian.Uint32(state[4:8])

	const macPasses = 2

	for range macPasses {
		for k := range 8 {
			y := t(sbox, n1+x[k])

			y = y<<macRotate | y>>(wordBits-macRotate)
			n1, n2 = y^n2, n1
		}
	}

	binary.LittleEndian.PutUint32(state[0:4], n1)
	binary.LittleEndian.PutUint32(state[4:8], n2)
}

// t applies the eight S-boxes nibble-by-nibble (cipher doc §2).
func t(sbox Sbox, x uint32) uint32 {
	var out uint32

	for i := range uint(sboxCount) {
		nib := (x >> (nibbleBits * i)) & nibbleMask

		out |= uint32(sbox[i][nib]) << (nibbleBits * i)
	}

	return out
}
