// ctfield.go — EXPERIMENT (branch exp/ct-scalarmult).
//
// Constant-time fixed-limb Montgomery arithmetic over GF(p) for the 256-bit
// GOST curves (4 × 64-bit limbs). This is the field layer of the option-C
// constant-time ScalarMult described in SECURITY.md.
//
// Representation: a field element `fe` is 4 little-endian uint64 limbs holding a
// value in the Montgomery domain (i.e. the stored limbs encode a·R mod p, with
// R = 2^256). All hot-path operations are branch-free in the operand *values*;
// loops run a fixed number of iterations determined only by the public limb
// count. math/big is used ONLY at setup (deriving public curve constants), never
// on a secret-dependent path.

package gost3410curves

import (
	"math/big"
	"math/bits"

	"github.com/bigbes/gostcrypto/internal/ct"
)

// ctLimbs is the limb count for the 256-bit curves. 512-bit support (8 limbs)
// is a later increment; see EXPERIMENT-ct.md.
const ctLimbs = 4

// limbBits is the width of a single limb in bits; limbBitsMinus1 masks a bit
// index within a limb (idx & limbBitsMinus1) and feeds the in-limb shift.
const (
	limbBits       = 64
	limbBitsMinus1 = limbBits - 1
)

// fe is a field element: 4 little-endian 64-bit limbs, Montgomery domain.
type fe [ctLimbs]uint64

// ctField holds the modulus and the Montgomery constants derived from it. All
// fields are public curve data (no secrets), computed once at construction.
type ctField struct {
	p   fe     // modulus p (the field prime), little-endian limbs.
	n0  uint64 // -p^{-1} mod 2^64 (Montgomery reduction constant).
	rr  fe     // R^2 mod p, R = 2^256 (to enter the Montgomery domain).
	one fe     // R mod p — the value 1 in the Montgomery domain.
}

// newCTField builds the Montgomery context for prime p. p must be an odd prime
// that fits in 256 bits (the 256-bit GOST field characteristic). Panics if p is
// out of range — this is setup-time, public-input validation.
func newCTField(p *big.Int) *ctField {
	if p.Sign() <= 0 || p.BitLen() > ctLimbs*64 || p.Bit(0) == 0 {
		panic("gost3410curves: ctField needs an odd prime < 2^256")
	}

	f := &ctField{p: feFromBig(p)}

	// n0 = -p^{-1} mod 2^64. Only the low limb of p participates.
	mod64 := new(big.Int).Lsh(big.NewInt(1), limbBits)
	p0 := new(big.Int).SetUint64(f.p[0])
	inv := new(big.Int).ModInverse(p0, mod64) // p0^{-1} mod 2^64.
	neg := new(big.Int).Sub(mod64, inv)       // -p0^{-1} mod 2^64.

	f.n0 = neg.Uint64()

	// R = 2^256; rr = R^2 mod p; one = R mod p.
	r := new(big.Int).Lsh(big.NewInt(1), ctLimbs*limbBits)
	one := new(big.Int).Mod(r, p)
	rr := new(big.Int).Mod(new(big.Int).Mul(r, r), p)

	f.one = feFromBig(one)
	f.rr = feFromBig(rr)

	return f
}

// feFromBig converts a non-negative big.Int (< 2^256) to 4 little-endian limbs.
// Setup-only; not constant-time.
func feFromBig(x *big.Int) fe {
	var out fe

	b := x.Bits() // little-endian machine words.
	for i := 0; i < len(b) && i < ctLimbs; i++ {
		out[i] = uint64(b[i])
	}

	return out
}

// bigFromFe converts limbs back to a big.Int (normal domain value). Test/setup
// helper; not constant-time.
func bigFromFe(a fe) *big.Int {
	out := new(big.Int)
	for i := ctLimbs - 1; i >= 0; i-- {
		out.Lsh(out, limbBits)
		out.Or(out, new(big.Int).SetUint64(a[i]))
	}

	return out
}

// --- limb-level primitives (constant-time) ---.

// mulAddCarry returns the 128-bit value a*b + c + d as (hi, lo).
func mulAddCarry(a, b, c, d uint64) (hi, lo uint64) {
	hi, lo = bits.Mul64(a, b)

	var carry uint64

	lo, carry = bits.Add64(lo, c, 0)

	hi += carry

	lo, carry = bits.Add64(lo, d, 0)

	hi += carry

	return hi, lo
}

// subLimbs returns a-b and the borrow-out (1 if a < b).
func subLimbs(a, b fe) (fe, uint64) {
	var r fe

	var br uint64
	for i := range ctLimbs {
		r[i], br = bits.Sub64(a[i], b[i], br)
	}

	return r, br
}

// cmov returns a if mask is all-ones, b if mask is zero (per-limb, branch-free).
func cmov(mask uint64, a, b fe) fe {
	var r fe
	for i := range ctLimbs {
		r[i] = (a[i] & mask) | (b[i] & ^mask)
	}

	return r
}

// condSubP subtracts p from r when (extra==1) || (r >= p). extra is the optional
// top bit of a 257-bit accumulator (0 or 1). Result is the reduced fe.
func (f *ctField) condSubP(r fe, extra uint64) fe {
	u, br := subLimbs(r, f.p)
	// Select u (the subtracted value) iff extra==1 or there was no borrow (r>=p).
	cond := extra | (1 - br)

	return cmov(ct.Mask(cond), u, r)
}

// --- field operations (Montgomery domain, constant-time) ---.

// add returns (a+b) mod p. Inputs must be reduced (< p). Flattened to register
// locals: a+b then a single masked conditional subtract of p, all in one pass.
func (f *ctField) add(a, b fe) fe {
	s0, c := bits.Add64(a[0], b[0], 0)
	s1, c := bits.Add64(a[1], b[1], c)
	s2, c := bits.Add64(a[2], b[2], c)
	s3, carry := bits.Add64(a[3], b[3], c)

	// u = s - p; select u iff s overflowed (carry) or s >= p (no borrow).
	u0, br := bits.Sub64(s0, f.p[0], 0)
	u1, br := bits.Sub64(s1, f.p[1], br)
	u2, br := bits.Sub64(s2, f.p[2], br)
	u3, br := bits.Sub64(s3, f.p[3], br)

	m := ct.Mask(carry | (1 - br))

	return fe{
		(u0 & m) | (s0 &^ m),
		(u1 & m) | (s1 &^ m),
		(u2 & m) | (s2 &^ m),
		(u3 & m) | (s3 &^ m),
	}
}

// sub returns (a-b) mod p. Inputs must be reduced (< p). Flattened: a-b then add
// p back iff it borrowed, all in register locals.
func (f *ctField) sub(a, b fe) fe {
	d0, br := bits.Sub64(a[0], b[0], 0)
	d1, br := bits.Sub64(a[1], b[1], br)
	d2, br := bits.Sub64(a[2], b[2], br)
	d3, borrow := bits.Sub64(a[3], b[3], br)

	// w = d + p; select w iff a < b (borrow).
	w0, c := bits.Add64(d0, f.p[0], 0)
	w1, c := bits.Add64(d1, f.p[1], c)
	w2, c := bits.Add64(d2, f.p[2], c)
	w3, _ := bits.Add64(d3, f.p[3], c)

	m := ct.Mask(borrow)

	return fe{
		(w0 & m) | (d0 &^ m),
		(w1 & m) | (d1 &^ m),
		(w2 & m) | (d2 &^ m),
		(w3 & m) | (d3 &^ m),
	}
}

// mul returns Montgomery product a·b·R^{-1} mod p via CIOS. Inputs and output
// are in the Montgomery domain, so this realises field multiplication. The
// 4-limb accumulator (t0..t5) is kept in locals rather than an array so it stays
// in registers — no bounds checks, no stack spilling (the hot path; ~half of a
// scalar multiply). The step structure is the textbook CIOS row: multiply-add
// the next limb of b, then reduce one limb.
func (f *ctField) mul(a, b fe) fe {
	a0, a1, a2, a3 := a[0], a[1], a[2], a[3]
	p0, p1, p2, p3 := f.p[0], f.p[1], f.p[2], f.p[3]
	n0 := f.n0

	var t0, t1, t2, t3, t4, t5 uint64

	for i := range ctLimbs {
		bi := b[i]

		var c, cc uint64

		c, t0 = mulAddCarry(a0, bi, t0, 0)
		c, t1 = mulAddCarry(a1, bi, t1, c)
		c, t2 = mulAddCarry(a2, bi, t2, c)
		c, t3 = mulAddCarry(a3, bi, t3, c)
		t4, cc = bits.Add64(t4, c, 0)
		t5 = cc

		// Montgomery reduce one limb: m = t0·n0 mod 2^64; the low word vanishes.
		m := t0 * n0

		c, _ = mulAddCarry(m, p0, t0, 0)
		c, t0 = mulAddCarry(m, p1, t1, c)
		c, t1 = mulAddCarry(m, p2, t2, c)
		c, t2 = mulAddCarry(m, p3, t3, c)
		t3, cc = bits.Add64(t4, c, 0)
		t4 = t5 + cc
	}

	return f.condSubP(fe{t0, t1, t2, t3}, t4)
}

// sqr returns a² in the field.
func (f *ctField) sqr(a fe) fe { return f.mul(a, a) }

// toMont maps a normal-domain element (reduced, < p) into the Montgomery domain.
func (f *ctField) toMont(a fe) fe { return f.mul(a, f.rr) }

// fromMont maps a Montgomery-domain element back to the normal domain.
func (f *ctField) fromMont(a fe) fe {
	var lit fe

	lit[0] = 1 // the literal integer 1.

	return f.mul(a, lit)
}

// inv returns a^{-1} in the field via Fermat: a^(p-2). The exponent is the
// public prime p, so square-and-multiply over its bits is constant-time with
// respect to the (secret) base a. Returns 0 for a == 0 (no inverse); callers
// must avoid that input.
func (f *ctField) inv(a fe) fe {
	// exponent e = p - 2 (Fermat's little theorem: a^(p-2) = a^{-1} mod p).
	e := new(big.Int).Sub(bigFromFe(f.p), big.NewInt(2)) //nolint:mnd // Fermat exponent p-2.

	result := f.one // 1 in Montgomery domain.
	// Square-and-multiply, MSB to LSB. Branch is on e's bits (public).
	for i := e.BitLen() - 1; i >= 0; i-- {
		result = f.sqr(result)
		if e.Bit(i) == 1 {
			result = f.mul(result, a)
		}
	}

	return result
}

// feEqual reports whether a == b (constant-time).
func feEqual(a, b fe) bool {
	var diff uint64
	for i := range ctLimbs {
		diff |= a[i] ^ b[i]
	}

	return diff == 0
}
