// ctscalar_test.go — EXPERIMENT. The headline check: the constant-time ladder
// must equal the trusted big.Int ScalarMult bit-for-bit on random scalars, for
// every 256-bit curve.

package gost3410curves //nolint:testpackage // white-box: uses unexported ctCurve/scalarMult internals.

import (
	"math/big"
	"math/rand"
	"testing"
)

// ct256Curves returns the 256-bit curves the experiment currently covers.
func ct256Curves() map[string]*Curve {
	return map[string]*Curve{
		"CryptoProA": curveCryptoProA(),
		"CryptoProB": curveCryptoProB(),
		"CryptoProC": curveCryptoProC(),
		"Tc26256A":   curveTc26256A(),
	}
}

func TestScalarMultCT_VsBigInt(t *testing.T) {
	t.Parallel()

	for name, c := range ct256Curves() {
		if c.P.BitLen() > 256 {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cc := newCTCurve(c)
			base := cc.fromAffine(c.Base())
			r := rand.New(rand.NewSource(42))

			for range 600 {
				k := new(big.Int).Add(
					new(big.Int).Rand(r, new(big.Int).Sub(c.Q, big.NewInt(1))),
					big.NewInt(1),
				)

				want := c.ScalarMult(k, c.Base())
				got := cc.toAffine(cc.scalarMult(k, base))

				if !affineEqual(got, want) {
					t.Fatalf("k=%x\n got=%v\nwant=%v", k, got, want)
				}
			}
		})
	}
}

// TestScalarMultCT_WindowVsLadder cross-checks the fixed-window method against
// the Montgomery ladder (both are independently validated vs big.Int, so this
// pins that the faster default did not drift).
func TestScalarMultCT_WindowVsLadder(t *testing.T) {
	t.Parallel()

	for name, c := range ct256Curves() {
		if c.P.BitLen() > 256 {
			continue
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cc := newCTCurve(c)
			base := cc.fromAffine(c.Base())
			r := rand.New(rand.NewSource(123))

			for range 400 {
				k := new(big.Int).Add(
					new(big.Int).Rand(r, new(big.Int).Sub(c.Q, big.NewInt(1))),
					big.NewInt(1),
				)

				win := cc.toAffine(cc.scalarMult(k, base))
				lad := cc.toAffine(cc.scalarMultLadder(k, base))

				if !affineEqual(win, lad) {
					t.Fatalf("window != ladder for k=%x", k)
				}
			}
		})
	}
}

// TestScalarMultCT_Boundaries checks k = 1, 2, Q-1, and a small known multiple.
func TestScalarMultCT_Boundaries(t *testing.T) {
	t.Parallel()

	c := curveCryptoProA()
	cc := newCTCurve(c)
	base := cc.fromAffine(c.Base())

	ks := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Sub(c.Q, big.NewInt(1)),
		new(big.Int).Sub(c.Q, big.NewInt(2)),
	}

	for _, k := range ks {
		want := c.ScalarMult(k, c.Base())
		got := cc.toAffine(cc.scalarMult(k, base))

		if !affineEqual(got, want) {
			t.Fatalf("k=%s: got=%v want=%v", k, got, want)
		}
	}

	// k = Q must give the identity (P has order Q).
	if got := cc.toAffine(cc.scalarMult(c.Q, base)); !got.IsInfinity() {
		t.Fatalf("Q*G expected identity, got %v", got)
	}
}

// TestScalarMultCT_PublicWrapper exercises the Curve.ScalarMultCT entry point
// and its degenerate-input guards.
func TestScalarMultCT_PublicWrapper(t *testing.T) {
	t.Parallel()

	c := curveCryptoProA()
	r := rand.New(rand.NewSource(99))

	for range 50 {
		k := new(big.Int).Add(
			new(big.Int).Rand(r, new(big.Int).Sub(c.Q, big.NewInt(1))),
			big.NewInt(1),
		)
		if !affineEqual(c.ScalarMultCT(k, c.Base()), c.ScalarMult(k, c.Base())) {
			t.Fatalf("ScalarMultCT != ScalarMult for k=%x", k)
		}
	}

	if !c.ScalarMultCT(big.NewInt(0), c.Base()).IsInfinity() {
		t.Fatal("k=0 should return identity")
	}

	if !c.ScalarMultCT(big.NewInt(5), Point{}).IsInfinity() {
		t.Fatal("identity base should return identity")
	}
}
