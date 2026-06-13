//go:build dudect

// ctdudect_test.go — EXPERIMENT. A dudect-style statistical timing-leak test
// (Reparaz–Balasch–Verbauwhede 2016) with a positive control.
//
// Build-tagged `dudect` so it is EXCLUDED from the default `go test ./...` (and
// from the race step — the race detector both perturbs the timing it measures
// and makes the 40 000-iteration sweep unusably slow). It runs only in its own
// CI job (.github/workflows/dudect.yml): `go test -tags dudect`, no -race.
//
// This is FALSIFICATION, not proof: it can catch a leak, never certify absence
// (see EXPERIMENT-ct.md "Constant-time status"). Real proof needs ctgrind under
// valgrind (unavailable on darwin/arm64) or formal methods. The point of the
// positive control is integrity: the SAME detector is run against the variable
// time big.Int ScalarMult, which MUST be flagged — otherwise a "pass" on the CT
// path is meaningless.
//
// Leak isolated: two fixed scalars of the same bit length but very different
// Hamming weight (HW 2 vs HW ~255). big.Int double-and-add runs one extra Add
// per set bit, so the two classes take different time (leak). The CT fixed
// window does a fixed number of point ops regardless of the digits (no leak).

package gost3410curves //nolint:testpackage // white-box: uses unexported ctCurve/scalarMult internals.

import (
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"
)

// welchT computes Welch's t-statistic between two timing samples.
func welchT(a, b []float64) float64 {
	ma, va := meanVar(a)
	mb, vb := meanVar(b)

	denom := va/float64(len(a)) + vb/float64(len(b))
	if denom <= 0 {
		return 0
	}

	d := ma - mb
	if d < 0 {
		d = -d
	}

	return d / sqrt(denom)
}

func meanVar(x []float64) (mean, variance float64) {
	for _, v := range x {
		mean += v
	}

	mean /= float64(len(x))

	for _, v := range x {
		variance += (v - mean) * (v - mean)
	}

	variance /= float64(len(x) - 1)

	return mean, variance
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}

	z := x
	for range 40 {
		z = (z + x/z) / 2
	}

	return z
}

// maxCroppedT computes Welch t at several upper-percentile crops (dudect crops
// the long right-tail noise) and returns the maximum |t|.
func maxCroppedT(c0, c1 []float64) float64 {
	combined := append(append([]float64{}, c0...), c1...)
	sort.Float64s(combined)

	best := 0.0

	for _, pct := range []float64{0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0} {
		capVal := combined[int(float64(len(combined)-1)*pct)]
		f0 := cropBelow(c0, capVal)
		f1 := cropBelow(c1, capVal)

		if len(f0) < 100 || len(f1) < 100 {
			continue
		}

		if tval := welchT(f0, f1); tval > best {
			best = tval
		}
	}

	return best
}

func cropBelow(x []float64, capVal float64) []float64 {
	out := x[:0:0]
	for _, v := range x {
		if v <= capVal {
			out = append(out, v)
		}
	}

	return out
}

// dudect interleaves two input classes, times each call, and returns max|t|.
func dudect(measure func(class int)) float64 {
	const n = 40000

	r := rand.New(rand.NewSource(0xDEADBEEF))

	// Warm up the clocks/caches.
	for i := range 500 {
		measure(i & 1)
	}

	var c0, c1 []float64

	for range n {
		class := int(r.Uint64() & 1)

		t0 := time.Now()

		measure(class)

		dt := float64(time.Since(t0).Nanoseconds())

		if class == 0 {
			c0 = append(c0, dt)
		} else {
			c1 = append(c1, dt)
		}
	}

	return maxCroppedT(c0, c1)
}

//nolint:paralleltest // dudect timing measurement must run undisturbed.
func TestDudect_CTvsBigInt(t *testing.T) {
	if testing.Short() {
		t.Skip("dudect timing test skipped in -short")
	}

	c := curveCryptoProA()
	cc := newCTCurve(c)
	base := cc.fromAffine(c.Base())
	g := c.Base()

	// Same bit length (~255), very different Hamming weight.
	lowHW := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 254), big.NewInt(1))  // HW 2.
	highHW := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)) // HW 255.
	scalars := [2]*big.Int{lowHW, highHW}

	// Positive control: the variable-time big.Int impl MUST be flagged.
	bigIntT := dudect(func(class int) { _ = c.ScalarMult(scalars[class], g) })

	// Subject: the constant-time fixed-window path.
	ctT := dudect(func(class int) { _ = cc.scalarMult(scalars[class], base) })

	t.Logf("dudect max|t|:  big.Int=%.1f   CT=%.1f   (|t|>4.5 ⇒ leak detected)", bigIntT, ctT)

	if bigIntT < 10 {
		t.Fatalf("positive control FAILED: detector did not flag the known-leaky "+
			"big.Int (t=%.1f); CT result is meaningless", bigIntT)
	}

	if ctT > 10 {
		t.Fatalf("CT path shows a timing leak: max|t|=%.1f (control big.Int=%.1f)", ctT, bigIntT)
	}
}
