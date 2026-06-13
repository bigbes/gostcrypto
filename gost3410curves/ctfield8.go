// ctfield8.go — EXPERIMENT. Constant-time 8-limb (512-bit) Montgomery field, the
// parallel of ctfield.go for the 512-bit GOST curves. Kept separate from the
// 4-limb path so the hot 256-bit code stays flat-unrolled; 512-bit is rare, so
// this uses compact loop-based CIOS (the proven pre-flatten algorithm at s=8).
//
// Shares the limb-level primitives mulAddCarry / maskFromBit / cmov-style masking
// with the 4-limb field; only the width-specific routines are duplicated.

package gost3410curves

import (
	"math/big"
	"math/bits"

	"github.com/bigbes/gostcrypto/internal/ct"
)

const ctLimbs8 = 8

// fe8 is a 512-bit field element: 8 little-endian limbs, Montgomery domain.
type fe8 [ctLimbs8]uint64

// ctField8 is the 8-limb analogue of ctField.
type ctField8 struct {
	p   fe8
	n0  uint64
	rr  fe8
	one fe8
}

func newCTField8(p *big.Int) *ctField8 {
	if p.Sign() <= 0 || p.BitLen() > ctLimbs8*64 || p.Bit(0) == 0 {
		panic("gost3410curves: ctField8 needs an odd prime < 2^512")
	}

	f := &ctField8{p: feFromBig8(p)}

	mod64 := new(big.Int).Lsh(big.NewInt(1), limbBits)
	p0 := new(big.Int).SetUint64(f.p[0])
	inv := new(big.Int).ModInverse(p0, mod64)

	f.n0 = new(big.Int).Sub(mod64, inv).Uint64()

	r := new(big.Int).Lsh(big.NewInt(1), ctLimbs8*limbBits)

	f.one = feFromBig8(new(big.Int).Mod(r, p))
	f.rr = feFromBig8(new(big.Int).Mod(new(big.Int).Mul(r, r), p))

	return f
}

func feFromBig8(x *big.Int) fe8 {
	var out fe8

	b := x.Bits()
	for i := 0; i < len(b) && i < ctLimbs8; i++ {
		out[i] = uint64(b[i])
	}

	return out
}

func bigFromFe8(a fe8) *big.Int {
	out := new(big.Int)
	for i := ctLimbs8 - 1; i >= 0; i-- {
		out.Lsh(out, limbBits)
		out.Or(out, new(big.Int).SetUint64(a[i]))
	}

	return out
}

func cmov8(mask uint64, a, b fe8) fe8 {
	var r fe8
	for i := range ctLimbs8 {
		r[i] = (a[i] & mask) | (b[i] & ^mask)
	}

	return r
}

func (f *ctField8) condSubP(r fe8, extra uint64) fe8 {
	var u fe8

	var br uint64
	for i := range ctLimbs8 {
		u[i], br = bits.Sub64(r[i], f.p[i], br)
	}

	return cmov8(ct.Mask(extra|(1-br)), u, r)
}

func (f *ctField8) add(a, b fe8) fe8 {
	var s fe8

	var c uint64
	for i := range ctLimbs8 {
		s[i], c = bits.Add64(a[i], b[i], c)
	}

	return f.condSubP(s, c)
}

func (f *ctField8) sub(a, b fe8) fe8 {
	var d fe8

	var br uint64
	for i := range ctLimbs8 {
		d[i], br = bits.Sub64(a[i], b[i], br)
	}

	var w fe8

	var c uint64
	for i := range ctLimbs8 {
		w[i], c = bits.Add64(d[i], f.p[i], c)
	}

	return cmov8(ct.Mask(br), w, d)
}

func (f *ctField8) mul(a, b fe8) fe8 {
	const s = ctLimbs8

	var t [s + 2]uint64

	for i := range s {
		var c uint64
		for j := range s {
			c, t[j] = mulAddCarry(a[j], b[i], t[j], c)
		}

		var cc uint64

		t[s], cc = bits.Add64(t[s], c, 0)
		t[s+1] = cc

		m := t[0] * f.n0

		c, _ = mulAddCarry(m, f.p[0], t[0], 0)

		for j := 1; j < s; j++ {
			c, t[j-1] = mulAddCarry(m, f.p[j], t[j], c)
		}

		t[s-1], cc = bits.Add64(t[s], c, 0)
		t[s] = t[s+1] + cc
	}

	var r fe8

	copy(r[:], t[:s])

	return f.condSubP(r, t[s])
}

func (f *ctField8) sqr(a fe8) fe8 { return f.mul(a, a) }

func (f *ctField8) toMont(a fe8) fe8 { return f.mul(a, f.rr) }

func (f *ctField8) fromMont(a fe8) fe8 {
	var lit fe8

	lit[0] = 1

	return f.mul(a, lit)
}

func (f *ctField8) inv(a fe8) fe8 {
	e := new(big.Int).Sub(bigFromFe8(f.p), big.NewInt(2)) //nolint:mnd // Fermat exponent p-2.

	result := f.one
	for i := e.BitLen() - 1; i >= 0; i-- {
		result = f.sqr(result)
		if e.Bit(i) == 1 {
			result = f.mul(result, a)
		}
	}

	return result
}

func feEqual8(a, b fe8) bool {
	var diff uint64
	for i := range ctLimbs8 {
		diff |= a[i] ^ b[i]
	}

	return diff == 0
}
