// Package gost3410sign is a clean-room implementation of the GOST R 34.10-2012
// (and the math-identical 34.10-2001) elliptic-curve digital signature
// algorithm: sign and verify over a short-Weierstrass GOST curve.
//
// It is implemented strictly from gost3410-signature.md and the
// RFCs it cites (RFC 7091 §6.1/§6.2 for the sign/verify equations, §5.3 for the
// big-endian hash-to-integer convention). It reuses the sibling clean-room
// package gost3410curves for all curve arithmetic (Curve, Point,
// ScalarMult, Base, IsOnCurve) and never imports gogost.
//
// Encoding conventions (the part most likely to bite, per the guide):
//
//   - Private key Raw: PointSize bytes, LITTLE-endian, reduced mod q on load.
//   - Public key Raw:  2·PointSize bytes, LE(X) || LE(Y).
//   - Signature Raw:   2·PointSize bytes, pad(s) || pad(r), each BIG-endian
//     within its half. Note: s FIRST, r SECOND (not the RFC's R||S writing).
//   - Digest:          read BIG-endian (big.Int.SetBytes of the bytes as-handed),
//     never byte-reversed.
//
// # References
//
//   - RFC 7091: https://github.com/bigbes/gostcrypto/blob/master/gost3410sign/rfc/rfc7091.txt
//   - RFC 5832: https://github.com/bigbes/gostcrypto/blob/master/gost3410sign/rfc/rfc5832.txt
package gost3410sign

import (
	"math/big"

	curves "github.com/bigbes/gostcrypto/gost3410curves"
)

// coordsPerKey is the number of PointSize-wide coordinates in a raw public key
// (LE(X)||LE(Y)) and in a raw signature (pad(s)||pad(r)).
const coordsPerKey = 2

// SignDigest produces a GOST R 34.10 signature of digest under private key prv,
// using the supplied nonce k. All of prv, digest, k are caller-provided byte
// slices; the result is the 2·PointSize raw signature s||r (big-endian within
// each half).
//
// Encoding of the inputs:
//
//   - prv:    little-endian private key (PointSize bytes; shorter/longer is
//     tolerated — it is byte-reversed then reduced mod q).
//   - digest: read big-endian (RFC 7091 §5.3).
//   - k:      the per-signature nonce, read big-endian, reduced mod q.
//
// Returns nil if the inputs are degenerate in a way the spec rejects: a zero
// private key, a zero nonce (mod q), or a nonce that yields r == 0 or s == 0
// (RFC §6.1 steps 4/5 mandate regenerating k; with a fixed k there is nothing
// to regenerate, so we signal failure with nil). A correct caller retries with
// a fresh k. SignDigest never mutates its arguments.
func SignDigest(c *curves.Curve, prv, digest, k []byte) []byte {
	q := c.Q
	pointSize := c.PointSize()

	// Private key d: byte-reverse the LE input, SetBytes (BE), reduce mod q.
	d := new(big.Int).SetBytes(reverse(prv))
	d.Mod(d, q)

	if d.Sign() == 0 {
		return nil // zero private key is rejected (guide §A.1 / RFC §6.1).
	}

	// e = alpha mod q, where alpha is the digest read big-endian (delta #1).
	e := new(big.Int).SetBytes(digest)
	e.Mod(e, q)

	if e.Sign() == 0 {
		e.SetInt64(1) // §6.1 step 2: "If e = 0, then assign e = 1.".
	}

	// Nonce k: read big-endian, reduce mod q (gogost reduce-then-reject; §6.1
	// step 3 "0 < k < q").
	kk := new(big.Int).SetBytes(k)
	kk.Mod(kk, q)

	if kk.Sign() == 0 {
		return nil
	}

	// C = k·P; r = x_C mod q. If r == 0, the caller must retry with a new k.
	cPoint := c.ScalarMult(kk, c.Base())
	if cPoint.IsInfinity() {
		return nil
	}

	r := new(big.Int).Mod(cPoint.X, q)
	if r.Sign() == 0 {
		return nil // §6.1 step 4.
	}

	// s = (r·d + k·e) mod q. If s == 0, the caller must retry.
	rd := new(big.Int).Mul(r, d)
	ke := new(big.Int).Mul(kk, e)
	s := rd.Add(rd, ke)
	s.Mod(s, q)

	if s.Sign() == 0 {
		return nil // §6.1 step 5.
	}

	// Output zeta = pad(s) || pad(r), big-endian within each PointSize half.
	out := make([]byte, coordsPerKey*pointSize)
	fillBE(out[:pointSize], s)
	fillBE(out[pointSize:], r)

	return out
}

// VerifyDigest reports whether sig is a valid GOST R 34.10 signature of digest
// under the public key pubRaw, on curve c.
//
// Encoding of the inputs:
//
//   - pubRaw: 2·PointSize bytes, LE(X) || LE(Y).
//   - digest: read big-endian (RFC 7091 §5.3).
//   - sig:    2·PointSize bytes, pad(s) || pad(r), big-endian within each half.
//
// It returns false (never panics) on any malformed input: wrong-length pubRaw
// or sig, an off-curve public key, or out-of-range r/s. VerifyDigest never
// mutates its arguments.
func VerifyDigest(c *curves.Curve, pubRaw, digest, sig []byte) bool {
	q := c.Q
	pointSize := c.PointSize()

	if len(sig) != coordsPerKey*pointSize || len(pubRaw) != coordsPerKey*pointSize {
		return false
	}

	// Parse signature as s||r (delta #4: s FIRST), big-endian within each half.
	s := new(big.Int).SetBytes(sig[:pointSize])
	r := new(big.Int).SetBytes(sig[pointSize:])

	// §6.2 step 1: reject unless 0 < r < q and 0 < s < q (strict both ends).
	if r.Sign() <= 0 || r.Cmp(q) >= 0 || s.Sign() <= 0 || s.Cmp(q) >= 0 {
		return false
	}

	// Parse public key: pubRaw = LE(X) || LE(Y); each half is byte-reversed
	// to recover the big-endian integer.
	q_ := pubRaw // alias for clarity.
	x := new(big.Int).SetBytes(reverse(q_[:pointSize]))
	y := new(big.Int).SetBytes(reverse(q_[pointSize:]))
	pub := curves.Point{X: x, Y: y}

	if !c.IsOnCurve(pub) || pub.IsInfinity() {
		return false
	}

	// §6.2 step 3: e = alpha mod q (digest big-endian); if e == 0, e = 1.
	e := new(big.Int).SetBytes(digest)
	e.Mod(e, q)

	if e.Sign() == 0 {
		e.SetInt64(1)
	}

	// §6.2 step 4: v = e⁻¹ mod q.
	v := new(big.Int).ModInverse(e, q)
	if v == nil {
		return false // e not invertible mod q (q prime ⇒ only e≡0, guarded above).
	}

	// §6.2 step 5: z1 = s·v mod q; z2 = (q − r·v) mod q (delta #3: normalize
	// the negation so it stays non-negative).
	z1 := new(big.Int).Mul(s, v)
	z1.Mod(z1, q)

	z2 := new(big.Int).Mul(r, v)
	z2.Mod(z2, q)
	z2.Sub(q, z2)
	z2.Mod(z2, q)

	// §6.2 step 6: C = z1·P + z2·Q; R = x_C mod q.
	p1 := c.ScalarMult(z1, c.Base())
	p2 := c.ScalarMult(z2, pub)
	cPoint := c.Add(p1, p2)

	if cPoint.IsInfinity() {
		return false
	}

	rr := new(big.Int).Mod(cPoint.X, q)

	// §6.2 step 7: valid iff R == r.
	return rr.Cmp(r) == 0
}

// PublicKeyRaw derives the public key raw form (LE(X) || LE(Y), 2·PointSize
// bytes) from the little-endian private key prv on curve c. Returns nil if the
// private key reduces to zero mod q.
func PublicKeyRaw(c *curves.Curve, prv []byte) []byte {
	q := c.Q
	pointSize := c.PointSize()

	d := new(big.Int).SetBytes(reverse(prv))
	d.Mod(d, q)

	if d.Sign() == 0 {
		return nil
	}

	pub := c.ScalarMult(d, c.Base())
	if pub.IsInfinity() {
		return nil
	}

	out := make([]byte, coordsPerKey*pointSize)
	// LE(X) in the first half, LE(Y) in the second half.
	putLE(out[:pointSize], pub.X)
	putLE(out[pointSize:], pub.Y)

	return out
}

// ---------------------------------------------------------------------------
// Byte helpers.
// ---------------------------------------------------------------------------.

// reverse returns a byte-reversed copy of b (LE<->BE conversion). It never
// mutates b.
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}

	return out
}

// fillBE writes n big-endian, right-aligned (zero-padded on the left) into dst.
func fillBE(dst []byte, n *big.Int) {
	b := n.Bytes() // big-endian, no leading zeros.
	if len(b) > len(dst) {
		b = b[len(b)-len(dst):] // defensive truncation; values are < q < 2^bits.
	}

	for i := range dst {
		dst[i] = 0
	}

	copy(dst[len(dst)-len(b):], b)
}

// putLE writes n little-endian, right-aligned in magnitude (zero-padded on the
// high end) into dst.
func putLE(dst []byte, n *big.Int) {
	b := n.Bytes() // big-endian.
	if len(b) > len(dst) {
		b = b[len(b)-len(dst):]
	}

	for i := range dst {
		dst[i] = 0
	}

	// little-endian: least-significant byte (b's last) goes to dst[0].
	for i := range len(b) {
		dst[i] = b[len(b)-1-i]
	}
}
