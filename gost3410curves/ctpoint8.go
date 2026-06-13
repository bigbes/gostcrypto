// ctpoint8.go — EXPERIMENT. 8-limb (512-bit) projective point arithmetic, the
// parallel of ctpoint.go: the same complete RCB formulas (add/dbl-2015-rcb) over
// fe8. See ctpoint.go for the formula provenance and completeness argument.

package gost3410curves

import "math/big"

type ctCurve8 struct {
	f         *ctField8
	a         fe8
	b3        fe8
	orderBits int
}

type ctPoint8 struct {
	x, y, z fe8
}

func newCTCurve8(c *Curve) *ctCurve8 {
	f := newCTField8(c.P)

	aRed := new(big.Int).Mod(c.A, c.P)
	// b3 = 3·b, a precomputed constant of the complete addition formula.
	three := big.NewInt(3) //nolint:mnd // formula coefficient 3 (b3 = 3·b).
	b3big := new(big.Int).Mod(new(big.Int).Mul(c.B, three), c.P)

	return &ctCurve8{
		f:         f,
		a:         f.toMont(feFromBig8(aRed)),
		b3:        f.toMont(feFromBig8(b3big)),
		orderBits: c.Q.BitLen(),
	}
}

func (cc *ctCurve8) identity() ctPoint8 {
	return ctPoint8{x: fe8{}, y: cc.f.one, z: fe8{}}
}

func (cc *ctCurve8) fromAffine(p Point) ctPoint8 {
	if p.IsInfinity() {
		return cc.identity()
	}

	f := cc.f
	mod := bigFromFe8(f.p)
	x := f.toMont(feFromBig8(new(big.Int).Mod(p.X, mod)))
	y := f.toMont(feFromBig8(new(big.Int).Mod(p.Y, mod)))

	return ctPoint8{x: x, y: y, z: f.one}
}

func (cc *ctCurve8) toAffine(p ctPoint8) Point {
	f := cc.f

	if feEqual8(p.z, fe8{}) {
		return Point{}
	}

	zinv := f.inv(p.z)
	x := f.fromMont(f.mul(p.x, zinv))
	y := f.fromMont(f.mul(p.y, zinv))

	return Point{X: bigFromFe8(x), Y: bigFromFe8(y)}
}

func (cc *ctCurve8) add(p, q ctPoint8) ctPoint8 {
	f, a, b3 := cc.f, cc.a, cc.b3
	x1, y1, z1 := p.x, p.y, p.z
	x2, y2, z2 := q.x, q.y, q.z

	t0 := f.mul(x1, x2)
	t1 := f.mul(y1, y2)
	t2 := f.mul(z1, z2)
	t3 := f.add(x1, y1)
	t4 := f.add(x2, y2)

	t3 = f.mul(t3, t4)
	t4 = f.add(t0, t1)
	t3 = f.sub(t3, t4)
	t4 = f.add(x1, z1)

	t5 := f.add(x2, z2)

	t4 = f.mul(t4, t5)
	t5 = f.add(t0, t2)
	t4 = f.sub(t4, t5)
	t5 = f.add(y1, z1)

	x3 := f.add(y2, z2)

	t5 = f.mul(t5, x3)
	x3 = f.add(t1, t2)
	t5 = f.sub(t5, x3)

	z3 := f.mul(a, t4)

	x3 = f.mul(b3, t2)
	z3 = f.add(x3, z3)
	x3 = f.sub(t1, z3)
	z3 = f.add(t1, z3)

	y3 := f.mul(x3, z3)

	t1 = f.add(t0, t0)
	t1 = f.add(t1, t0)
	t2 = f.mul(a, t2)
	t4 = f.mul(b3, t4)
	t1 = f.add(t1, t2)
	t2 = f.sub(t0, t2)
	t2 = f.mul(a, t2)
	t4 = f.add(t4, t2)
	t0 = f.mul(t1, t4)
	y3 = f.add(y3, t0)
	t0 = f.mul(t5, t4)
	x3 = f.mul(t3, x3)
	x3 = f.sub(x3, t0)
	t0 = f.mul(t3, t1)
	z3 = f.mul(t5, z3)
	z3 = f.add(z3, t0)

	return ctPoint8{x: x3, y: y3, z: z3}
}

func (cc *ctCurve8) double(p ctPoint8) ctPoint8 {
	f, a, b3 := cc.f, cc.a, cc.b3
	x1, y1, z1 := p.x, p.y, p.z

	t0 := f.sqr(x1)
	t1 := f.sqr(y1)
	t2 := f.sqr(z1)
	t3 := f.mul(x1, y1)

	t3 = f.add(t3, t3)

	z3 := f.mul(x1, z1)

	z3 = f.add(z3, z3)

	x3 := f.mul(a, z3)
	y3 := f.mul(b3, t2)

	y3 = f.add(x3, y3)
	x3 = f.sub(t1, y3)
	y3 = f.add(t1, y3)
	y3 = f.mul(x3, y3)
	x3 = f.mul(t3, x3)
	z3 = f.mul(b3, z3)
	t2 = f.mul(a, t2)
	t3 = f.sub(t0, t2)
	t3 = f.mul(a, t3)
	t3 = f.add(t3, z3)
	z3 = f.add(t0, t0)
	t0 = f.add(z3, t0)
	t0 = f.add(t0, t2)
	t0 = f.mul(t0, t3)
	y3 = f.add(y3, t0)
	t2 = f.mul(y1, z1)
	t2 = f.add(t2, t2)
	t0 = f.mul(t2, t3)
	x3 = f.sub(x3, t0)
	z3 = f.mul(t2, t1)
	z3 = f.add(z3, z3)
	z3 = f.add(z3, z3)

	return ctPoint8{x: x3, y: y3, z: z3}
}
