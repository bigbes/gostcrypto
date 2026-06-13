// ctpoint_test.go — EXPERIMENT. Validate the complete projective point
// formulas against the trusted affine Add/Double over random points.

package gost3410curves //nolint:testpackage // white-box: uses unexported ctCurve/ctPoint internals.

import (
	"math/big"
	"math/rand"
	"testing"
)

// affineEqual compares two affine points (identity included).
func affineEqual(a, b Point) bool {
	if a.IsInfinity() || b.IsInfinity() {
		return a.IsInfinity() == b.IsInfinity()
	}

	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

// randPoint returns k·G for a random k in [1, Q-1] using the trusted ScalarMult.
func randPoint(t *testing.T, c *Curve, r *rand.Rand) Point {
	t.Helper()

	k := new(big.Int).Add(new(big.Int).Rand(r, new(big.Int).Sub(c.Q, big.NewInt(1))), big.NewInt(1))

	return c.ScalarMult(k, c.Base())
}

// negate returns -P = (x, p-y).
func negate(c *Curve, p Point) Point {
	if p.IsInfinity() {
		return Point{}
	}

	return Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Sub(c.P, p.Y)}
}

func TestCTPoint_AddDoubleVsAffine(t *testing.T) {
	t.Parallel()

	c := curveCryptoProA()
	cc := newCTCurve(c)
	r := rand.New(rand.NewSource(7))

	for i := range 2000 {
		p := randPoint(t, c, r)
		q := randPoint(t, c, r)

		// add.
		wantAdd := c.Add(p, q)

		gotAdd := cc.toAffine(cc.add(cc.fromAffine(p), cc.fromAffine(q)))
		if !affineEqual(gotAdd, wantAdd) {
			t.Fatalf("add mismatch i=%d\n got=%v\nwant=%v", i, gotAdd, wantAdd)
		}

		// double.
		wantDbl := c.Double(p)

		gotDbl := cc.toAffine(cc.double(cc.fromAffine(p)))
		if !affineEqual(gotDbl, wantDbl) {
			t.Fatalf("double mismatch i=%d\n got=%v\nwant=%v", i, gotDbl, wantDbl)
		}
	}
}

// TestCTPoint_CompleteEdgeCases exercises the branches that break incomplete
// affine formulas: P+identity, identity+P, P+P (= double), P+(-P) (= identity),
// double(identity).
func TestCTPoint_CompleteEdgeCases(t *testing.T) {
	t.Parallel()

	c := curveCryptoProA()
	cc := newCTCurve(c)
	r := rand.New(rand.NewSource(11))

	p := randPoint(t, c, r)
	id := cc.identity()
	cp := cc.fromAffine(p)

	cases := []struct {
		name string
		got  Point
		want Point
	}{
		{"P+id", cc.toAffine(cc.add(cp, id)), p},
		{"id+P", cc.toAffine(cc.add(id, cp)), p},
		{"P+P", cc.toAffine(cc.add(cp, cp)), c.Double(p)},
		{"P+(-P)", cc.toAffine(cc.add(cp, cc.fromAffine(negate(c, p)))), Point{}},
		{"2*id", cc.toAffine(cc.double(id)), Point{}},
		{"id->affine", cc.toAffine(id), Point{}},
	}

	for _, tc := range cases {
		if !affineEqual(tc.got, tc.want) {
			t.Fatalf("%s: got=%v want=%v", tc.name, tc.got, tc.want)
		}
	}
}

func TestCTPoint_CswapVsAffine(t *testing.T) {
	t.Parallel()

	c := curveCryptoProA()
	cc := newCTCurve(c)
	r := rand.New(rand.NewSource(13))

	p := cc.fromAffine(randPoint(t, c, r))
	q := cc.fromAffine(randPoint(t, c, r))
	p0, q0 := p, q

	// swap with bit 0 → unchanged.
	cc.cswap(0, &p, &q)

	if !pointEq(p, p0) || !pointEq(q, q0) {
		t.Fatal("cswap(0) altered points")
	}

	// swap with bit 1 → exchanged.
	cc.cswap(1, &p, &q)

	if !pointEq(p, q0) || !pointEq(q, p0) {
		t.Fatal("cswap(1) did not exchange points")
	}
}

func pointEq(a, b ctPoint) bool {
	return feEqual(a.x, b.x) && feEqual(a.y, b.y) && feEqual(a.z, b.z)
}
