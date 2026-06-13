//go:build dudect

// cttiming_test.go — EXPERIMENT. A wall-clock timing-leakage demonstration.
//
// Makes the thesis concrete: the big.Int ScalarMult iterates k.BitLen() times,
// so a tiny scalar runs dramatically faster than a full-width one — a blatant
// timing oracle on the secret. The constant-time ladder runs a fixed number of
// iterations, so both scalars take essentially the same time.
//
// Build-tagged `dudect` (shared with ctdudect_test.go) so it stays out of the
// default `go test ./...` and never runs under -race, which perturbs the
// wall-clock timing it measures. It runs only in the dudect CI job.

package gost3410curves //nolint:testpackage // white-box: uses unexported ctCurve/scalarMult internals.

import (
	"math/big"
	"testing"
	"time"
)

// timingReps is the number of runs minTime averages (min) over.
const timingReps = 1500

// minTime returns the minimum wall-clock duration of fn over timingReps runs.
// min is the cleanest single-shot timing estimator: it is the run least
// perturbed by scheduler preemption and other noise (which only ever adds time).
func minTime(fn func()) time.Duration {
	best := time.Duration(1) << 62

	for range timingReps {
		t0 := time.Now()

		fn()

		if d := time.Since(t0); d < best {
			best = d
		}
	}

	return best
}

// TestTimingLeak_BigIntVsCT demonstrates the side channel and its closure.
//
//nolint:paralleltest // wall-clock timing measurement must run undisturbed.
func TestTimingLeak_BigIntVsCT(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short")
	}

	c := curveCryptoProA()
	cc := newCTCurve(c)
	base := cc.fromAffine(c.Base())
	g := c.Base()

	small := big.NewInt(3)                        // 2-bit scalar.
	large := new(big.Int).Sub(c.Q, big.NewInt(1)) // ~256-bit scalar.

	// Warm up (let the CPU clock and caches settle).
	for range 200 {
		_ = c.ScalarMult(small, g)
		_ = cc.scalarMult(large, base)
	}

	biSmall := minTime(func() { _ = c.ScalarMult(small, g) })
	biLarge := minTime(func() { _ = c.ScalarMult(large, g) })
	ctSmall := minTime(func() { _ = cc.scalarMult(small, base) })
	ctLarge := minTime(func() { _ = cc.scalarMult(large, base) })

	biRatio := float64(biLarge) / float64(biSmall)
	ctRatio := float64(ctLarge) / float64(ctSmall)

	t.Logf("big.Int  small=%v large=%v ratio=%.1fx  (leaks: scales with bit length)", biSmall, biLarge, biRatio)
	t.Logf("ladder   small=%v large=%v ratio=%.2fx  (constant: fixed iterations)", ctSmall, ctLarge, ctRatio)

	// The big.Int version must show a large, scalar-dependent gap...
	if biRatio < 3.0 {
		t.Errorf("expected big.Int ScalarMult to leak (ratio >= 3x), got %.1fx", biRatio)
	}

	// ...while the ladder stays flat. Generous bound to tolerate machine noise.
	if ctRatio > 1.5 || ctRatio < 0.67 {
		t.Errorf("expected ladder to be ~constant-time (0.67..1.5x), got %.2fx", ctRatio)
	}
}
