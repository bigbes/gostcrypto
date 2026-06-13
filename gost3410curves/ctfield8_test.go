// ctfield8_test.go — EXPERIMENT. Differential validation of the 8-limb (512-bit)
// Montgomery field against math/big, mirroring ctfield_test.go.

package gost3410curves //nolint:testpackage // white-box: uses unexported ctField8 internals.

import (
	"math/big"
	"math/rand"
	"testing"
)

func ctTestPrime512(t *testing.T) *big.Int {
	t.Helper()

	c := curveTc26512A()
	if c.P.BitLen() <= 256 || c.P.BitLen() > 512 {
		t.Fatalf("expected a 512-bit prime, got %d bits", c.P.BitLen())
	}

	return c.P
}

func TestCTField8_AddSubMulInv(t *testing.T) {
	t.Parallel()

	p := ctTestPrime512(t)
	f := newCTField8(p)
	r := rand.New(rand.NewSource(8))

	for range 8000 {
		x := new(big.Int).Rand(r, p)
		y := new(big.Int).Rand(r, p)
		xm := f.toMont(feFromBig8(x))
		ym := f.toMont(feFromBig8(y))

		check := func(name string, got fe8, want *big.Int) {
			if g := bigFromFe8(f.fromMont(got)); g.Cmp(want) != 0 {
				t.Fatalf("%s: x=%x y=%x got=%x want=%x", name, x, y, g, want)
			}
		}

		check("add", f.add(xm, ym), new(big.Int).Mod(new(big.Int).Add(x, y), p))
		check("sub", f.sub(xm, ym), new(big.Int).Mod(new(big.Int).Sub(x, y), p))
		check("mul", f.mul(xm, ym), new(big.Int).Mod(new(big.Int).Mul(x, y), p))
		check("sqr", f.sqr(xm), new(big.Int).Mod(new(big.Int).Mul(x, x), p))

		if x.Sign() != 0 {
			check("inv", f.inv(xm), new(big.Int).ModInverse(x, p))
		}
	}
}

func TestCTField8_RoundTrip(t *testing.T) {
	t.Parallel()

	p := ctTestPrime512(t)
	f := newCTField8(p)
	r := rand.New(rand.NewSource(9))

	for range 3000 {
		x := new(big.Int).Rand(r, p)
		if got := bigFromFe8(f.fromMont(f.toMont(feFromBig8(x)))); got.Cmp(x) != 0 {
			t.Fatalf("round-trip: x=%x got=%x", x, got)
		}
	}
}
