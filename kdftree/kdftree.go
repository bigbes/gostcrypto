// Package kdftree implements KDF_TREE_GOSTR3411_2012_256, the counter-mode
// key-derivation function defined in RFC 7836 §4.4 (also R 50.1.113-2016 §4.5),
// built on HMAC over Streebog-256 (GOST R 34.11-2012, 256-bit output).
//
// This is a clean-room implementation built strictly from
// kdftree2012-256.md and the cited RFCs. It reuses the
// sibling clean-room Streebog-256 hash (cleanroom/streebog) and the standard
// library crypto/hmac. It contains no GOST-licensed code and no build tags.
//
// # References
//
//   - RFC 7836: https://github.com/bigbes/gostcrypto/blob/master/kdftree/rfc/rfc7836.txt
package kdftree

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/bigbes/gostcrypto/streebog"
)

// KDFTree256 implements KDF_TREE_GOSTR3411_2012_256 (RFC 7836 §4.4).
//
// It derives outLen bytes of keying material from the derivation key, a label
// and a seed. The iteration counter [i]_b is encoded big-endian in r bytes;
// the total bit-length [L]_b = outLen*8 is encoded big-endian with leading
// zero bytes stripped (no leading zeros, per RFC 7836 §4.4).
//
// Per-iteration HMAC message (key = key):
//
//	K(i) = HMAC_Streebog256(key, [i]_b || label || 0x00 || seed || [L]_b)
//
// Output = K(1) || K(2) || ... truncated to outLen bytes. The number of
// iterations is ceil(outLen / 32).
//
// Constraints: r must be in 1..4; outLen must be > 0; outLen must not exceed
// what an r-byte big-endian counter can address (32 * (2^(8r) - 1) bytes).
// Violations panic — callers in this repo always pass r=1 with outLen a
// positive multiple of 32 (see kdftree2012-256.md §"Parameters
// used by this repo").
func KDFTree256(key, label, seed []byte, r, outLen int) []byte {
	if r < 1 || r > 4 {
		panic("kdftree: r must be in 1..4")
	}

	if outLen <= 0 {
		panic("kdftree: outLen must be positive")
	}

	const (
		hashSize    = 32 // Streebog-256 output, bytes.
		bitsPerByte = 8  // bit width of a byte.
		// uint64ShiftSafe bounds r so 8*r stays below 64 and the counter-width
		// shift below cannot overflow uint64 (r<=4 always satisfies this).
		uint64ShiftSafe = 8
	)

	// Number of 32-byte HMAC blocks needed.
	iters := (outLen + hashSize - 1) / hashSize

	// The counter field is r bytes; the maximum representable counter value is
	// 2^(8r)-1. Reject requests that would overflow it.
	if r < uint64ShiftSafe { // guard the shift; r<=4 always satisfies this.
		maxIters := (uint64(1) << (bitsPerByte * uint(r))) - 1
		if uint64(iters) > maxIters {
			panic("kdftree: outLen too large for r-byte counter")
		}
	}

	// [L]_b: total output bit-length, big-endian, no leading zero bytes.
	lBits := uint64(outLen) * bitsPerByte
	lRepr := encodeNoLeadingZeros(lBits)

	out := make([]byte, 0, iters*hashSize)
	for i := 1; i <= iters; i++ {
		h := hmac.New(streebog.New256, key)
		h.Write(counterBytes(uint64(i), r))
		h.Write(label)
		h.Write([]byte{0x00})
		h.Write(seed)
		h.Write(lRepr)

		out = h.Sum(out)
	}

	return out[:outLen]
}

// counterBytes returns the low r bytes of v, big-endian (RFC 7836 §4.4 [i]_b,
// engine gost_keyexpimp.c:234-236 — last r bytes of be32(i)).
func counterBytes(v uint64, r int) []byte {
	var full [8]byte

	binary.BigEndian.PutUint64(full[:], v)

	return full[8-r:]
}

// encodeNoLeadingZeros returns the minimal big-endian byte representation of v
// with no leading zero bytes (RFC 7836 §4.4 [L]_b). v==0 yields a single 0x00
// byte (defensive; not reachable for outLen>0).
func encodeNoLeadingZeros(v uint64) []byte {
	var full [8]byte

	binary.BigEndian.PutUint64(full[:], v)

	i := 0
	for i < 7 && full[i] == 0 {
		i++
	}

	return full[i:]
}
