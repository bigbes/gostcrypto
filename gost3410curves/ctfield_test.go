// ctfield_test.go — EXPERIMENT. Differential validation of the constant-time
// Montgomery field against math/big over random inputs. The big.Int arithmetic
// is the trusted oracle (see EXPERIMENT-ct.md).

package gost3410curves //nolint:testpackage // white-box: uses unexported ctField internals.

import (
	"math/big"
	"math/rand"
	"testing"
)

// ctTestPrime returns the 256-bit GOST test-curve field prime P.
func ctTestPrime(t *testing.T) *big.Int {
	t.Helper()

	c := curveCryptoProA()
	if c.P.BitLen() > 256 {
		t.Fatalf("test prime is %d bits, ctfield experiment is 256-bit only", c.P.BitLen())
	}

	return c.P
}

// randMod returns a uniform value in [0, p).
func randMod(r *rand.Rand, p *big.Int) *big.Int {
	return new(big.Int).Rand(r, p)
}

func TestCTField_RoundTripMont(t *testing.T) {
	t.Parallel()

	p := ctTestPrime(t)
	f := newCTField(p)
	r := rand.New(rand.NewSource(1))

	for range 5000 {
		x := randMod(r, p)

		got := bigFromFe(f.fromMont(f.toMont(feFromBig(x))))
		if got.Cmp(x) != 0 {
			t.Fatalf("round-trip mismatch: x=%x got=%x", x, got)
		}
	}
}

func TestCTField_AddSubMulInv(t *testing.T) {
	t.Parallel()

	p := ctTestPrime(t)
	f := newCTField(p)
	r := rand.New(rand.NewSource(2))

	for range 20000 {
		x := randMod(r, p)
		y := randMod(r, p)
		xm := f.toMont(feFromBig(x))
		ym := f.toMont(feFromBig(y))

		// add.
		wantAdd := new(big.Int).Mod(new(big.Int).Add(x, y), p)
		if got := bigFromFe(f.fromMont(f.add(xm, ym))); got.Cmp(wantAdd) != 0 {
			t.Fatalf("add: x=%x y=%x got=%x want=%x", x, y, got, wantAdd)
		}

		// sub.
		wantSub := new(big.Int).Mod(new(big.Int).Sub(x, y), p)
		if got := bigFromFe(f.fromMont(f.sub(xm, ym))); got.Cmp(wantSub) != 0 {
			t.Fatalf("sub: x=%x y=%x got=%x want=%x", x, y, got, wantSub)
		}

		// mul.
		wantMul := new(big.Int).Mod(new(big.Int).Mul(x, y), p)
		if got := bigFromFe(f.fromMont(f.mul(xm, ym))); got.Cmp(wantMul) != 0 {
			t.Fatalf("mul: x=%x y=%x got=%x want=%x", x, y, got, wantMul)
		}

		// sqr.
		wantSqr := new(big.Int).Mod(new(big.Int).Mul(x, x), p)
		if got := bigFromFe(f.fromMont(f.sqr(xm))); got.Cmp(wantSqr) != 0 {
			t.Fatalf("sqr: x=%x got=%x want=%x", x, got, wantSqr)
		}

		// inv (skip x==0).
		if x.Sign() != 0 {
			wantInv := new(big.Int).ModInverse(x, p)
			if got := bigFromFe(f.fromMont(f.inv(xm))); got.Cmp(wantInv) != 0 {
				t.Fatalf("inv: x=%x got=%x want=%x", x, got, wantInv)
			}
		}
	}
}

// TestCTField_Boundaries exercises 0, 1, p-1 explicitly.
func TestCTField_Boundaries(t *testing.T) {
	t.Parallel()

	p := ctTestPrime(t)
	f := newCTField(p)

	vals := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(p, big.NewInt(1)),
	}

	for _, x := range vals {
		for _, y := range vals {
			xm := f.toMont(feFromBig(x))
			ym := f.toMont(feFromBig(y))

			wantMul := new(big.Int).Mod(new(big.Int).Mul(x, y), p)
			if got := bigFromFe(f.fromMont(f.mul(xm, ym))); got.Cmp(wantMul) != 0 {
				t.Fatalf("mul boundary: x=%x y=%x got=%x want=%x", x, y, got, wantMul)
			}
		}
	}
}
