package gost3410curves_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	gost3410curves "github.com/bigbes/gostcrypto/gost3410curves"
)

// allOIDs lists the ten supported OID arcs and their expected PointSize.
var allOIDs = []struct {
	oid       string
	name      string
	pointSize int
}{
	{"1.2.643.2.2.35.1", "CryptoPro-A", 32},
	{"1.2.643.2.2.35.2", "CryptoPro-B", 32},
	{"1.2.643.2.2.35.3", "CryptoPro-C", 32},
	{"1.2.643.7.1.2.1.1.1", "tc26-256-A", 32},
	{"1.2.643.7.1.2.1.1.2", "tc26-256-B", 32},
	{"1.2.643.7.1.2.1.1.3", "tc26-256-C", 32},
	{"1.2.643.7.1.2.1.1.4", "tc26-256-D", 32},
	{"1.2.643.7.1.2.1.2.1", "tc26-512-A", 64},
	{"1.2.643.7.1.2.1.2.2", "tc26-512-B", 64},
	{"1.2.643.7.1.2.1.2.3", "tc26-512-C", 64},
}

func mustCurve(t *testing.T, oid string) *gost3410curves.Curve {
	t.Helper()

	c, err := gost3410curves.CurveByOID(oid)
	if err != nil {
		t.Fatalf("CurveByOID(%s): %v", oid, err)
	}

	return c
}

// (a) The base point G must satisfy IsOnCurve for every supported OID.
func TestBasePointOnCurve(t *testing.T) {
	t.Parallel()

	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := mustCurve(t, tc.oid)
			if !c.IsOnCurve(c.Base()) {
				t.Fatalf("%s: base point G not on curve", tc.name)
			}
		})
	}
}

// (b) The strong correctness gate: G has order Q, so Q·G == identity.
// A single mistranscribed (p,a,b,q,x,y) byte fails this.
func TestBasePointOrderIsQ(t *testing.T) {
	t.Parallel()

	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := mustCurve(t, tc.oid)
			got := c.ScalarMult(c.Q, c.Base())

			if !got.IsInfinity() {
				t.Fatalf("%s: Q·G != identity (order mismatch) -> got (%X, %X)",
					tc.name, got.X, got.Y)
			}

			// Sanity: (Q-1)·G must NOT be the identity (rules out a trivially
			// wrong Q that happens to clear early).
			qMinus1 := new(big.Int).Sub(c.Q, big.NewInt(1))
			if c.ScalarMult(qMinus1, c.Base()).IsInfinity() {
				t.Fatalf("%s: (Q-1)·G == identity, Q is not the true order", tc.name)
			}
		})
	}
}

// (c) A few random scalars k: k·G must land on the curve.
func TestRandomScalarMultOnCurve(t *testing.T) {
	t.Parallel()

	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := mustCurve(t, tc.oid)
			G := c.Base()

			for range 8 {
				k, err := rand.Int(rand.Reader, c.Q)
				if err != nil {
					t.Fatalf("rand: %v", err)
				}

				if k.Sign() == 0 {
					continue
				}

				P := c.ScalarMult(k, G)
				if P.IsInfinity() {
					t.Fatalf("%s: k·G unexpectedly identity for k=%X", tc.name, k)
				}

				if !c.IsOnCurve(P) {
					t.Fatalf("%s: k·G off curve for k=%X -> (%X, %X)",
						tc.name, k, P.X, P.Y)
				}
			}
		})
	}
}

// TestScalarMultKAT pins Double(G) and k·G for the 256-A and 512-A curves
// against an INDEPENDENT short-Weierstrass implementation (computed offline in
// Python from the same public curve constants). Unlike the order/group-law
// property tests, these static points catch arithmetic bugs that happen to
// preserve on-curve-ness or the subgroup order.
func TestScalarMultKAT(t *testing.T) {
	t.Parallel()

	const k = "0badc0ffee0ddf00ddeadbeefcafef00d0123456789abcdeffedcba9876543210"

	cases := []struct {
		name, oid          string
		double2X, double2Y string
		kX, kY             string
	}{
		{
			name: "tc26-256-A", oid: "1.2.643.7.1.2.1.1.1",
			double2X: "e8c6740e58d616ca220db7da0d9c3e19b53e86e38bf3e8747774631452ec174c",
			double2Y: "0b837a5e560a29a2327b575f29b4be8baef4bc947fcc2ed4f3264bc434309381",
			kX:       "d9328e9d40b6cfeb8cc4ff3330c354b7c44a28e5f3170f9aa70c5d1dc2f531e4",
			kY:       "a1dad70383ecbd6a23430437c7631785855cb2c0c34673efb5d4da82b6ce6b16",
		},
		{
			name: "tc26-512-A", oid: "1.2.643.7.1.2.1.2.1",
			double2X: "3b89dcfc622996ab97a5869dbff15cf51db00954f43a58a5e5f6b0470a132b2f" +
				"4434bbcd405d2a9516151d2a6a04f2e4375bf48de1fdb21fb982afd9d2ea137c",
			double2Y: "c813c4e2e2e0a8a391774c7903da7a6f14686e98e183e670ee6fb784809a3e92" +
				"ca209dc631d85b1c7534ed3b37fddf64d854d7e01f91f18bb3fd307591afc051",
			kX: "0412747e4a266b941e28391723a1d46fd2cdf25db6f120880aaed33ac5382863" +
				"3a5822df6923cc7eef2a00c79c1d2c88834fbbbfaaec9f40db234b83051a069b",
			kY: "c7bbde34937139d855e0b2f01c700b4ab48e393f6258c4f754447a83e9b24c4f" +
				"2740f3a2cc2965b831ba94aaae9a745ef37ea41131789f1edae6cab83d3ff34a",
		},
	}
	mustBig := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			t.Fatalf("bad hex %q", s)
		}

		return n
	}
	eq := func(label string, P gost3410curves.Point, x, y string) {
		if P.X.Cmp(mustBig(x)) != 0 || P.Y.Cmp(mustBig(y)) != 0 {
			t.Fatalf("%s:\n got (%x, %x)\nwant (%s, %s)", label, P.X, P.Y, x, y)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := mustCurve(t, tc.oid)
			eq("Double(G)", c.Double(c.Base()), tc.double2X, tc.double2Y)
			eq("k·G", c.ScalarMult(mustBig(k), c.Base()), tc.kX, tc.kY)
		})
	}
}

// PointSize derives purely from P.BitLen() (§3.2).
func TestPointSize(t *testing.T) {
	t.Parallel()

	for _, tc := range allOIDs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := mustCurve(t, tc.oid)
			if got := c.PointSize(); got != tc.pointSize {
				t.Fatalf("%s: PointSize=%d want %d", tc.name, got, tc.pointSize)
			}
		})
	}
}

func TestCurveByOID_Unknown(t *testing.T) {
	t.Parallel()

	if _, err := gost3410curves.CurveByOID("1.2.3.4.5"); err == nil {
		t.Fatal("expected error for unknown OID")
	}
}

// Group-law spot checks: Add commutativity, associativity, and identity laws.
func TestGroupLaws(t *testing.T) {
	t.Parallel()

	c := mustCurve(t, "1.2.643.7.1.2.1.1.1") // tc26-256-A.
	G := c.Base()

	twoG := c.Double(G)
	threeG := c.Add(twoG, G)

	// G + 2G == 2G + G (commutativity).
	if a, b := c.Add(G, twoG), c.Add(twoG, G); a.X.Cmp(b.X) != 0 || a.Y.Cmp(b.Y) != 0 {
		t.Fatal("Add not commutative")
	}

	// 3G via Add must equal ScalarMult(3, G).
	sm3 := c.ScalarMult(big.NewInt(3), G)
	if sm3.X.Cmp(threeG.X) != 0 || sm3.Y.Cmp(threeG.Y) != 0 {
		t.Fatal("ScalarMult(3,G) != G+G+G")
	}

	// G + (-G) == identity.
	negG := gost3410curves.Point{X: new(big.Int).Set(G.X), Y: new(big.Int).Sub(c.P, G.Y)}
	if !c.Add(G, negG).IsInfinity() {
		t.Fatal("G + (-G) != identity")
	}

	// Double(G) on curve.
	if !c.IsOnCurve(twoG) {
		t.Fatal("2G not on curve")
	}
}

// TestCofactorField pins the Cofactor value for every registered OID.
// Cofactor 4 applies only to tc26-256-A and tc26-512-C (twisted-Edwards derived);
// all other registered sets have Cofactor 1.
func TestCofactorField(t *testing.T) {
	t.Parallel()

	want := map[string]int{
		"1.2.643.2.2.35.1":    1, // CryptoPro-A.
		"1.2.643.2.2.35.2":    1, // CryptoPro-B.
		"1.2.643.2.2.35.3":    1, // CryptoPro-C (NOT 4 — see VKO-63 finding).
		"1.2.643.7.1.2.1.1.1": 4, // tc26-256-A (twisted-Edwards, co=4).
		"1.2.643.7.1.2.1.1.2": 1, // tc26-256-B == CryptoPro-A.
		"1.2.643.7.1.2.1.1.3": 1, // tc26-256-C == CryptoPro-B.
		"1.2.643.7.1.2.1.1.4": 1, // tc26-256-D == CryptoPro-C.
		"1.2.643.7.1.2.1.2.1": 1, // tc26-512-A.
		"1.2.643.7.1.2.1.2.2": 1, // tc26-512-B.
		"1.2.643.7.1.2.1.2.3": 4, // tc26-512-C (twisted-Edwards, co=4).
	}
	for oid, wantCof := range want {
		c := mustCurve(t, oid)
		if c.Cofactor != wantCof {
			t.Errorf("OID %s: Cofactor=%d want %d", oid, c.Cofactor, wantCof)
		}
	}
}

// TestIsOnCurve_Rejects pins the IsOnCurve rejection paths.
// A regression deleting the range check or inverting the equation check
// would pass all positive-only tests but fail these.
func TestIsOnCurve_Rejects(t *testing.T) {
	t.Parallel()

	// Use tc26-256-A; the same logic applies to all curves.
	c := mustCurve(t, "1.2.643.7.1.2.1.1.1")
	G := c.Base()

	cases := []struct {
		name string
		p    gost3410curves.Point
		want bool
	}{
		// Positive: base point must be on curve.
		{"G on curve", G, true},
		// Negative: Y+1 takes the point off the curve.
		{"(G.X, G.Y+1)", gost3410curves.Point{
			X: new(big.Int).Set(G.X),
			Y: new(big.Int).Add(G.Y, big.NewInt(1)),
		}, false},
		// Negative: coordinates congruent-mod-P but unreduced (G.X+P, G.Y+P).
		{"(G.X+P, G.Y+P) unreduced", gost3410curves.Point{
			X: new(big.Int).Add(G.X, c.P),
			Y: new(big.Int).Add(G.Y, c.P),
		}, false},
		// Negative: negative coordinates must be rejected by the range check.
		{"(-1, G.Y) negative X", gost3410curves.Point{
			X: big.NewInt(-1),
			Y: new(big.Int).Set(G.Y),
		}, false},
		// Positive: the identity (infinity) is considered on the curve.
		{"infinity", gost3410curves.Point{}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := c.IsOnCurve(tc.p)
			if got != tc.want {
				t.Fatalf("IsOnCurve = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIdentityEdgePaths pins identity and guard paths of Add, Double, ScalarMult.
func TestIdentityEdgePaths(t *testing.T) {
	t.Parallel()

	c := mustCurve(t, "1.2.643.7.1.2.1.1.1") // tc26-256-A.
	G := c.Base()
	inf := gost3410curves.Point{} // identity.

	t.Run("Add(inf,G)==G", func(t *testing.T) {
		t.Parallel()

		r := c.Add(inf, G)
		if r.X.Cmp(G.X) != 0 || r.Y.Cmp(G.Y) != 0 {
			t.Fatalf("Add(∞,G) = (%x,%x), want G", r.X, r.Y)
		}
	})

	t.Run("Add(G,inf)==G", func(t *testing.T) {
		t.Parallel()

		r := c.Add(G, inf)
		if r.X.Cmp(G.X) != 0 || r.Y.Cmp(G.Y) != 0 {
			t.Fatalf("Add(G,∞) = (%x,%x), want G", r.X, r.Y)
		}
	})

	// Verify Add returns a clone, not a reference, so mutation is safe.
	t.Run("Add(inf,G)_clone", func(t *testing.T) {
		t.Parallel()

		r := c.Add(inf, G)
		origX := new(big.Int).Set(r.X)
		r.X.Add(r.X, big.NewInt(1)) // mutate result.
		// G.X must be unchanged.
		if G.X.Cmp(origX) != 0 {
			t.Fatal("Add returned a reference, not a clone: mutating result changed G")
		}
	})

	t.Run("Add(G,-G)==inf", func(t *testing.T) {
		t.Parallel()

		negG := gost3410curves.Point{
			X: new(big.Int).Set(G.X),
			Y: new(big.Int).Sub(c.P, G.Y),
		}

		r := c.Add(G, negG)
		if !r.IsInfinity() {
			t.Fatalf("Add(G,-G) = (%x,%x), want ∞", r.X, r.Y)
		}
	})

	t.Run("Double(inf)==inf", func(t *testing.T) {
		t.Parallel()

		r := c.Double(inf)
		if !r.IsInfinity() {
			t.Fatalf("Double(∞) = (%x,%x), want ∞", r.X, r.Y)
		}
	})

	t.Run("ScalarMult(nil,G)==inf", func(t *testing.T) {
		t.Parallel()

		r := c.ScalarMult(nil, G)
		if !r.IsInfinity() {
			t.Fatalf("ScalarMult(nil,G) = (%x,%x), want ∞", r.X, r.Y)
		}
	})

	t.Run("ScalarMult(0,G)==inf", func(t *testing.T) {
		t.Parallel()

		r := c.ScalarMult(big.NewInt(0), G)
		if !r.IsInfinity() {
			t.Fatalf("ScalarMult(0,G) = (%x,%x), want ∞", r.X, r.Y)
		}
	})

	t.Run("ScalarMult(-1,G)==inf", func(t *testing.T) {
		t.Parallel()

		r := c.ScalarMult(big.NewInt(-1), G)
		if !r.IsInfinity() {
			t.Fatalf("ScalarMult(-1,G) = (%x,%x), want ∞", r.X, r.Y)
		}
	})

	t.Run("ScalarMult(1,G)==G", func(t *testing.T) {
		t.Parallel()

		r := c.ScalarMult(big.NewInt(1), G)
		if r.X.Cmp(G.X) != 0 || r.Y.Cmp(G.Y) != 0 {
			t.Fatalf("ScalarMult(1,G) = (%x,%x), want G", r.X, r.Y)
		}
	})

	t.Run("ScalarMult(Q,G)==inf", func(t *testing.T) {
		t.Parallel()

		r := c.ScalarMult(c.Q, G)
		if !r.IsInfinity() {
			t.Fatalf("ScalarMult(Q,G) = (%x,%x), want ∞", r.X, r.Y)
		}
	})

	t.Run("ScalarMult(k,inf)==inf", func(t *testing.T) {
		t.Parallel()

		r := c.ScalarMult(big.NewInt(7), inf)
		if !r.IsInfinity() {
			t.Fatalf("ScalarMult(7,∞) = (%x,%x), want ∞", r.X, r.Y)
		}
	})
}

// aliasing: the 2001 CryptoPro 256-bit sets share constants with tc26-256-B/C/D.
func TestAliasing(t *testing.T) {
	t.Parallel()

	pairs := [][2]string{
		{"1.2.643.2.2.35.1", "1.2.643.7.1.2.1.1.2"}, // CryptoPro-A == tc26-256-B.
		{"1.2.643.2.2.35.2", "1.2.643.7.1.2.1.1.3"}, // CryptoPro-B == tc26-256-C.
		{"1.2.643.2.2.35.3", "1.2.643.7.1.2.1.1.4"}, // CryptoPro-C == tc26-256-D.
	}
	for _, p := range pairs {
		a := mustCurve(t, p[0])
		b := mustCurve(t, p[1])

		if a.P.Cmp(b.P) != 0 || a.A.Cmp(b.A) != 0 || a.B.Cmp(b.B) != 0 ||
			a.Q.Cmp(b.Q) != 0 || a.X.Cmp(b.X) != 0 || a.Y.Cmp(b.Y) != 0 {
			t.Fatalf("alias mismatch %s vs %s", p[0], p[1])
		}
	}
}
