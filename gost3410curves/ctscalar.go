// ctscalar.go — EXPERIMENT. Constant-time scalar multiplication via a Montgomery
// ladder over the complete projective formulas. Every bit of the scalar drives
// exactly one add + one double + two conditional swaps; the loop runs a fixed
// number of iterations (the bit length of the group order), independent of the
// scalar's value or leading zeros. The scalar is decoded into fixed-width limbs
// so bit access is value-independent.

package gost3410curves

import (
	"encoding/binary"
	"math/big"

	"github.com/bigbes/gostcrypto/internal/ct"
)

// scalarToLimbs decodes k into 4 fixed limbs with a fixed-iteration loop, so the
// decode is oblivious to k's magnitude. feFromBig must NOT be used for the secret
// scalar: its loop length is len(k.Bits()), which leaks how many high words of k
// are zero. We route through a fixed 32-byte big-endian buffer instead.
//
// Residual caveat: big.Int.FillBytes still iterates k's internal words, so a
// fully constant-time entry point must take the scalar as fixed-width bytes
// (which gost3410sign already holds before reducing). This removes the leak from
// THIS package's code; the stdlib residue is the documented boundary.
func scalarToLimbs(k *big.Int) fe {
	var buf [ctLimbs * 8]byte

	k.FillBytes(buf[:]) // fixed 32-byte big-endian; k < Q < 2^256 by contract.

	return scalarBytesToLimbs(buf[:])
}

// scalarBytesToLimbs decodes a fixed-width big-endian scalar (exactly ctLimbs*8
// bytes) into limbs with a fixed loop and NO value- or length-dependent branch —
// the fully constant-time scalar decode. Prefer this over scalarToLimbs for a
// secret scalar: scalarToLimbs routes through big.Int.FillBytes, which branches
// on the secret's words (flagged by ctgrind at nat.go). Callers that already
// hold the secret as bytes (the signer's nonce, the private key) feed it here.
func scalarBytesToLimbs(b []byte) fe {
	var out fe
	for i := range ctLimbs {
		out[i] = binary.BigEndian.Uint64(b[(ctLimbs-1-i)*8:])
	}

	return out
}

// ctWindow is the fixed-window width for scalarMult. 4 divides 64, so a window
// digit never straddles a limb boundary.
const ctWindow = 4

// scalarMult returns k·P. k must be in [0, 2^256). It uses a constant-time
// fixed-window method (window ctWindow): a precomputed table 0·P…15·P, selected
// per window with a branch-free table scan, then folded in with w doublings per
// window. This does ~orderBits doublings + ~orderBits/w additions, versus the
// Montgomery ladder's add-and-double on every bit (scalarMultLadder).
func (cc *ctCurve) scalarMult(k *big.Int, p ctPoint) ctPoint {
	return cc.scalarMultLimbs(scalarToLimbs(k), p)
}

// scalarMultLimbs is the core fixed-window multiply over a pre-decoded scalar.
// It touches no big.Int, so with a constant-time decode (scalarBytesToLimbs) the
// whole secret path is branch-free.
func (cc *ctCurve) scalarMultLimbs(kl fe, p ctPoint) ctPoint {
	// Precompute tbl[i] = i·P (projective). tbl[0] is the identity.
	var tbl [1 << ctWindow]ctPoint

	tbl[0] = cc.identity()
	tbl[1] = p

	for i := 2; i < len(tbl); i++ {
		tbl[i] = cc.add(tbl[i-1], p)
	}

	nWin := (cc.orderBits + ctWindow - 1) / ctWindow

	result := cc.identity()

	for wi := nWin - 1; wi >= 0; wi-- {
		// Shift the accumulator left by one window. On the first (top) window
		// result is the identity, so this is a harmless, branch-free no-op.
		for range ctWindow {
			result = cc.double(result)
		}

		pos := uint(wi * ctWindow)
		digit := (kl[pos>>6] >> (pos & limbBitsMinus1)) & ((1 << ctWindow) - 1)

		result = cc.add(result, cc.selectWindow(&tbl, digit))
	}

	return result
}

// selectWindow returns tbl[digit] in constant time by scanning every entry and
// arithmetic-masking the match — the memory-access pattern is independent of the
// secret digit.
func (cc *ctCurve) selectWindow(tbl *[1 << ctWindow]ctPoint, digit uint64) ctPoint {
	var r ctPoint

	for j := range tbl {
		mask := ct.Eq(uint64(j), digit)

		r.x = cmov(mask, tbl[j].x, r.x)
		r.y = cmov(mask, tbl[j].y, r.y)
		r.z = cmov(mask, tbl[j].z, r.z)
	}

	return r
}

// scalarMultLadder returns k·P using a Montgomery ladder — kept as the simplest
// constant-time reference for the fixed-window scalarMult to validate against.
// Ladder invariant: R1 − R0 = P throughout.
func (cc *ctCurve) scalarMultLadder(k *big.Int, p ctPoint) ctPoint {
	kl := feFromBig(k)

	r0 := cc.identity()
	r1 := p

	for i := cc.orderBits - 1; i >= 0; i-- {
		bit := (kl[uint(i)>>6] >> (uint(i) & limbBitsMinus1)) & 1

		cc.cswap(bit, &r0, &r1)

		r1 = cc.add(r0, r1)
		r0 = cc.double(r0)
		cc.cswap(bit, &r0, &r1)
	}

	return r0
}

// ScalarMultSecret returns k·p for a SECRET scalar, dispatching on the curve's
// ConstantTime flag: the constant-time ScalarMultCT when set, else the
// variable-time reference ScalarMult. This is the selector the signer and VKO
// use for the nonce / private-key multiplies; callers opt in via
// c.ConstantTime = true. (On a curve width the CT backend does not yet cover,
// ScalarMultCT itself falls back to the reference — documented there.)
func (c *Curve) ScalarMultSecret(k *big.Int, p Point) Point {
	if c.ConstantTime {
		return c.ScalarMultCT(k, p)
	}

	return c.ScalarMult(k, p)
}

// ctCurve returns the memoised 4-limb (≤256-bit) constant-time context for c,
// or nil if c is wider than 256 bits.
func (c *Curve) ctCurve() *ctCurve {
	c.ctOnce.Do(func() {
		if c.P.BitLen() <= bits256 {
			c.ctCached = newCTCurve(c)
		}
	})

	return c.ctCached
}

// ctCurve8 returns the memoised 8-limb (257–512-bit) constant-time context for
// c, or nil if c is ≤256-bit (use ctCurve) or wider than 512 bits.
func (c *Curve) ctCurve8() *ctCurve8 {
	c.ctOnce8.Do(func() {
		if n := c.P.BitLen(); n > bits256 && n <= ctLimbs8*64 {
			c.ctCached8 = newCTCurve8(c)
		}
	})

	return c.ctCached8
}

// ScalarMultCT is the constant-time counterpart of ScalarMult (EXPERIMENT). It
// returns k·p with no secret-dependent branch or memory-access pattern in the
// arithmetic. k ≤ 0 or an identity p returns the identity, mirroring ScalarMult.
//
// The Montgomery context is built once per Curve and cached, so repeated calls
// pay only the ladder cost. The two implementations live side by side: callers
// with SECRET scalars (signing nonce, private key) should use ScalarMultCT;
// ScalarMult stays the reference path for public scalars (e.g. verification).
//
// SCOPE: the CT backend covers the 256-bit (4-limb) and 512-bit (8-limb) curves.
// On any wider curve it falls back to the variable-time ScalarMult — correct,
// but NOT constant-time.
func (c *Curve) ScalarMultCT(k *big.Int, p Point) Point {
	if k == nil || k.Sign() <= 0 || p.IsInfinity() {
		return Point{}
	}

	if cc := c.ctCurve(); cc != nil {
		return cc.toAffine(cc.scalarMult(k, cc.fromAffine(p)))
	}

	if cc8 := c.ctCurve8(); cc8 != nil {
		return cc8.toAffine(cc8.scalarMult(k, cc8.fromAffine(p)))
	}

	return c.ScalarMult(k, p) // unsupported width — documented fallback.
}
