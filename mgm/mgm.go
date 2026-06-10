// Package mgm implements the Multilinear Galois Mode (MGM) AEAD construction
// defined in RFC 9058 (and R 1323565.1.026-2019), the GOST analogue of
// AES-GCM. It works over any cipher.Block with a 64-bit (Magma) or 128-bit
// (Kuznyechik) block size.
//
// This is a clean-room implementation written from the RFC / guide only.
//
// # References
//
//   - RFC 9058: https://github.com/bigbes/gostcrypto/blob/master/mgm/rfc/rfc9058.txt
//   - R 1323565.1.026-2019: https://github.com/bigbes/gostcrypto/blob/master/mgm/rfc/R1323565.1.026-2019.pdf
package mgm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	// blockSize64 / blockSize128 are the two supported cipher block sizes in
	// bytes (Magma = 64-bit, Kuznyechik = 128-bit).
	blockSize64  = 8
	blockSize128 = 16

	// minTagSize is the minimum tag length in bytes (RFC 9058 §4: 32 bits).
	minTagSize = 4

	// reduction64 / reduction128 are the GF(2^n) reduction constants for the
	// 64-bit and 128-bit fields.
	reduction64  = 0x1b
	reduction128 = 0x87

	// bitsPerByte is the number of bits in a byte.
	bitsPerByte = 8

	// halfDivisor splits a block into its two equal halves.
	halfDivisor = 2

	// msbMask selects the most-significant bit of a byte.
	msbMask = 0x80

	// byteBitMask masks a bit index within a byte (bit % 8).
	byteBitMask = 7

	// lengthFieldShiftAdj is the -3 in 2^(n/2-3)-1: a field's BIT length is
	// stored in n/2 bits, so its BYTE length caps at 2^(n/2-3)-1.
	lengthFieldShiftAdj = 3
)

// errBlockSize and errTagSize are the static construction errors returned by
// NewMGM.
var (
	errBlockSize = errors.New("mgm: block size must be 64 or 128 bits")
	errTagSize   = errors.New("mgm: invalid tag size")
)

// MGM is a one-shot AEAD over a cipher.Block. It is not goroutine-safe: the
// same value reuses internal scratch across calls, mirroring gogost.
type MGM struct {
	cipher    cipher.Block
	blockSize int
	tagSize   int

	// reduction is the GF(2^n) reduction constant XORed into the low byte
	// on overflow: 0x1b for n=64, 0x87 for n=128.
	reduction byte

	// scratch.
	icn  []byte // raw nonce copy; domain bit is applied to the m.ek copy inside crypt/auth.
	yi   []byte // encryption counter.
	zi   []byte // MAC counter.
	ek   []byte // E_K output buffer.
	sum  []byte // running GF accumulator.
	pad  []byte // zero-padded partial block buffer.
	mul  []byte // GF multiply result.
	lenB []byte // length block.
}

var errOpen = errors.New("mgm: message authentication failed")

// NewMGM returns an MGM AEAD over the given block cipher with the requested
// tag size in bytes. The block size must be 8 or 16 bytes; the tag size must
// satisfy 4 <= tagSize <= blockSize (RFC 9058 §4: 32 <= S <= n bits).
func NewMGM(c cipher.Block, tagSize int) (*MGM, error) {
	bs := c.BlockSize()
	if bs != blockSize64 && bs != blockSize128 {
		return nil, errBlockSize
	}

	if tagSize < minTagSize || tagSize > bs {
		return nil, errTagSize
	}

	var red byte

	switch bs {
	case blockSize64:
		red = reduction64
	case blockSize128:
		red = reduction128
	}

	return &MGM{
		cipher:    c,
		blockSize: bs,
		tagSize:   tagSize,
		reduction: red,
		icn:       make([]byte, bs),
		yi:        make([]byte, bs),
		zi:        make([]byte, bs),
		ek:        make([]byte, bs),
		sum:       make([]byte, bs),
		pad:       make([]byte, bs),
		mul:       make([]byte, bs),
		lenB:      make([]byte, bs),
	}, nil
}

// NonceSize implements cipher.AEAD; the nonce (ICN) is exactly one block.
func (m *MGM) NonceSize() int { return m.blockSize }

// Overhead implements cipher.AEAD; the tag length.
func (m *MGM) Overhead() int { return m.tagSize }

// Seal encrypts and authenticates plaintext, appending ciphertext||tag to dst
// and returning the result. nonce is the ICN; its top bit must be clear.
func (m *MGM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	m.validateNonce(nonce)

	if len(plaintext) == 0 && len(additionalData) == 0 {
		panic("mgm: at least one of plaintext / additional data must be non-empty")
	}

	if len(plaintext) > m.maxFieldLen() || len(additionalData) > m.maxFieldLen() {
		panic("mgm: field too large for the n/2-bit length block under one nonce")
	}

	// RFC 9058 §4.1 (rfc/rfc9058.txt:281-282): the combined bit-length MUST
	// satisfy 0 < |A| + |P| < 2^(n/2).
	if !m.validateLens(len(additionalData), len(plaintext)) {
		panic("mgm: combined length of additional data and plaintext exceeds 2^(n/2) bits")
	}

	copy(m.icn, nonce)

	ret, out := sliceForAppend(dst, len(plaintext)+m.tagSize)
	ct := out[:len(plaintext)]
	tag := out[len(plaintext):]

	m.crypt(ct, plaintext)
	m.auth(tag, additionalData, ct)

	return ret
}

// Open authenticates and decrypts ciphertext (ciphertext||tag), appending the
// plaintext to dst and returning it. It returns an error if authentication
// fails.
func (m *MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	m.validateNonce(nonce)

	if len(ciphertext) < m.tagSize {
		return nil, errOpen
	}

	ct := ciphertext[:len(ciphertext)-m.tagSize]
	recvTag := ciphertext[len(ciphertext)-m.tagSize:]

	if len(ct) == 0 && len(additionalData) == 0 {
		return nil, errOpen
	}

	if len(ct) > m.maxFieldLen() || len(additionalData) > m.maxFieldLen() {
		// Oversized for the length block — could only ever be a forgery.
		return nil, errOpen
	}

	// RFC 9058 §4.2 (rfc/rfc9058.txt:355-356): the combined bit-length MUST
	// satisfy 0 < |A| + |C| < 2^(n/2).
	if !m.validateLens(len(additionalData), len(ct)) {
		return nil, errOpen
	}

	copy(m.icn, nonce)

	expTag := make([]byte, m.tagSize)
	m.auth(expTag, additionalData, ct)

	if subtle.ConstantTimeCompare(expTag, recvTag) != 1 {
		return nil, errOpen
	}

	ret, out := sliceForAppend(dst, len(ct))
	m.crypt(out, ct)

	return ret, nil
}

// maxFieldLen returns the maximum length in bytes of a single field — the
// additional data OR the payload — under one nonce. RFC 9058 §4.1 encodes each
// field's BIT length in n/2 bits of the length block, so a field may hold at
// most (2^(n/2)-1)/8 = 2^(n/2-3)-1 bytes. For the Magma case (n=64) that is
// only 2^29-1 (512 MiB); exceeding it would silently truncate the length block
// (len*8 stored as uint32) and forge a wrong tag, so Seal/Open reject it. The
// cap is applied to EACH field; see also validateLens for the combined-sum check.
//
// On 32-bit platforms the Kuznyechik shift (n/2-3 = 61) does not fit a platform
// int, so we return maxInt (the practical limit for any in-memory buffer) in that
// case. We detect this by comparing the shift amount against bits.UintSize-1.
func (m *MGM) maxFieldLen() int {
	const maxInt = int(^uint(0) >> 1)

	halfBits := m.blockSize * bitsPerByte / halfDivisor // n/2 bits per length field.
	shift := halfBits - lengthFieldShiftAdj             // n/2 - 3

	if shift >= bits.UintSize-1 {
		// The shift would not fit a signed platform int; cap is effectively ∞.
		return maxInt
	}

	return (1 << uint(shift)) - 1
}

// validateLens checks the RFC 9058 combined-length MUST:
// |A| + |P| < 2^(n/2) bits (rfc/rfc9058.txt:281-282).
// Arithmetic is done in uint64 to avoid overflow on 32-bit platforms.
// Returns true if the combined bit-length is within bounds.
func (m *MGM) validateLens(aLen, pLen int) bool {
	halfBits := uint64(m.blockSize) * bitsPerByte / halfDivisor // n/2
	aBits := uint64(aLen) * bitsPerByte
	pBits := uint64(pLen) * bitsPerByte

	sum := aBits + pBits
	// Check for uint64 overflow (sum wraps); also check against the bound.
	// 2^(n/2) bits: for n=64 that is 2^32; for n=128 that is 2^64 (overflows uint64 → 0).
	if aBits > sum { // overflow
		return false
	}

	if halfBits >= 64 {
		// 2^64 doesn't fit uint64; the only invalid case is overflow (already checked).
		return true
	}

	return sum < (uint64(1) << halfBits)
}

// incrR increments the right (low) half of a in-place, big-endian, carry
// confined to that half. Used for the encryption counter Y.
func (m *MGM) incrR(a []byte) {
	half := m.blockSize / halfDivisor
	for i := m.blockSize - 1; i >= half; i-- {
		a[i]++
		if a[i] != 0 {
			break
		}
	}
}

// incrL increments the left (high) half of a in-place, big-endian, carry
// confined to that half. Used for the MAC counter Z.
func (m *MGM) incrL(a []byte) {
	half := m.blockSize / halfDivisor
	for i := half - 1; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			break
		}
	}
}

// gfMul computes x ⊗ y in GF(2^n) for the field selected by m.blockSize,
// writing the n-byte big-endian result into dst. Operands are big-endian
// byte strings (first byte = most-significant coefficient).
//
// Schoolbook shift-and-XOR: accumulate dst ^= shiftedX wherever a bit of y
// is set (scanned MSB-first), then shift x left by one (toward more-
// significant), reducing with the field polynomial constant on overflow.
func (m *MGM) gfMul(dst, x, y []byte) {
	n := m.blockSize
	// accumulator z = x ⊗ y, computed via Horner over y's bits (MSB-first):
	//   z = 0; for each bit b of y (MSB→LSB): z = z·w; if b: z = z ^ x
	// where multiplying by w is a left-shift (toward more-significant) of the
	// big-endian element, reduced by the field polynomial constant on overflow.
	z := make([]byte, n)

	totalBits := n * bitsPerByte
	for bit := range totalBits {
		// z = z·w  (shift left by 1, big-endian), except before the first add
		// so that the loop is exactly: add, then shift n*8-1 times. We shift
		// at the START of every iteration after the first.
		if bit != 0 {
			overflow := z[0]&msbMask != 0

			var carry byte

			for i := n - 1; i >= 0; i-- {
				nc := (z[i] & msbMask) >> byteBitMask

				z[i] = (z[i] << 1) | carry
				carry = nc
			}

			if overflow {
				z[n-1] ^= m.reduction
			}
		}

		// y bit scanned MSB-first: byte bit/8, mask 0x80>>(bit%8).
		if y[bit/bitsPerByte]&(msbMask>>uint(bit%bitsPerByte)) != 0 {
			for i := range n {
				z[i] ^= x[i]
			}
		}
	}

	copy(dst, z)
}

// crypt performs the CTR-style encryption pass over Y (incr_r). It XORs the
// keystream E_K(Y_i) into in, writing to out. out and in may alias.
func (m *MGM) crypt(out, in []byte) {
	bs := m.blockSize
	// Y_1 = E_K(0¹ || ICN): seed counter with the encrypted nonce.
	copy(m.ek, m.icn)

	m.ek[0] &= 0x7f
	m.cipher.Encrypt(m.yi, m.ek)

	for len(in) > 0 {
		m.cipher.Encrypt(m.ek, m.yi)

		n := min(len(in), bs)

		for i := range n {
			out[i] = in[i] ^ m.ek[i]
		}

		in = in[n:]
		out = out[n:]

		m.incrR(m.yi)
	}
}

// auth computes the MGM tag over additional data and ciphertext, writing the
// truncated tag (m.tagSize bytes) into tag.
func (m *MGM) auth(tag, ad, ct []byte) {
	bs := m.blockSize
	// Z_1 = E_K(1¹ || ICN): seed MAC counter with the encrypted nonce.
	copy(m.ek, m.icn)

	m.ek[0] |= 0x80
	m.cipher.Encrypt(m.zi, m.ek)

	for i := range m.sum {
		m.sum[i] = 0
	}

	process := func(data []byte) {
		for len(data) > 0 {
			n := bs

			var blk []byte

			if len(data) < bs {
				n = len(data)

				for i := range m.pad {
					m.pad[i] = 0
				}

				copy(m.pad, data[:n]) // right-zero-pad (trailing bytes zero).

				blk = m.pad
			} else {
				blk = data[:bs]
			}

			m.cipher.Encrypt(m.ek, m.zi) // H_i = E_K(Z_i).
			m.gfMul(m.mul, m.ek, blk)

			for i := range m.sum {
				m.sum[i] ^= m.mul[i]
			}

			m.incrL(m.zi)

			data = data[n:]
		}
	}

	process(ad)
	process(ct)

	// length block: BigEndian(len(ad)*8) || BigEndian(len(ct)*8), each n/2 bits.
	for i := range m.lenB {
		m.lenB[i] = 0
	}

	half := bs / halfDivisor
	adBits := uint64(len(ad)) * bitsPerByte
	ctBits := uint64(len(ct)) * bitsPerByte

	switch bs {
	case blockSize64:
		binary.BigEndian.PutUint32(m.lenB[:half], uint32(adBits))
		binary.BigEndian.PutUint32(m.lenB[half:], uint32(ctBits))
	case blockSize128:
		binary.BigEndian.PutUint64(m.lenB[:half], adBits)
		binary.BigEndian.PutUint64(m.lenB[half:], ctBits)
	}

	m.cipher.Encrypt(m.ek, m.zi) // H_{h+q+1}.
	m.gfMul(m.mul, m.ek, m.lenB)

	for i := range m.sum {
		m.sum[i] ^= m.mul[i]
	}

	// T = MSB_S(E_K(sum)).
	m.cipher.Encrypt(m.ek, m.sum)
	copy(tag, m.ek[:m.tagSize])
}

func (m *MGM) validateNonce(nonce []byte) {
	if len(nonce) != m.blockSize {
		panic("mgm: incorrect nonce length")
	}

	if nonce[0]&0x80 != 0 {
		panic("mgm: nonce must have its most-significant bit clear")
	}
}

// sliceForAppend extends in by n bytes, returning the grown slice and the
// trailing n-byte region to write into.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}

	tail = head[len(in):]

	return
}

// Compile-time interface assertion.
var _ cipher.AEAD = (*MGM)(nil)
