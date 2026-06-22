//go:build dudect && goexperiment.simd && amd64

// simd_dudect_test.go — EXPERIMENT. dudect-style timing-leak test for the SIMD
// batch encrypt (EncryptBlocks), with a positive control.
//
// Build-tagged `dudect` (excluded from the default `go test ./...` and from the
// race step) and `goexperiment.simd` amd64-only. It runs in its own CI job
// (.github/workflows/simd.yml): `GOEXPERIMENT=simd go test -tags dudect`.
//
// FALSIFICATION, not proof. The positive control is the table cipher: its 64 KB
// fused tables exceed L1, so secret-indexed loads make fixed vs random input
// timing diverge — it MUST be flagged, else a "pass" on the SIMD path is
// meaningless. The SIMD path uses only data-oblivious VPSHUFB/arithmetic, so it
// must show vastly less timing dependence.
//
// The assertion is a RATIO (SIMD |t| far below the control's), not an absolute
// |t|<4.5: each encrypt is only ~µs, so on a shared CI runner without core
// pinning the noise floor alone reaches |t|~4–6 for truly constant-time code
// (pin with `taskset -c` for an absolute reading — see EXPERIMENT-simd.md).

package kuznyechik

import (
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func welchTSimd(a, b []float64) float64 {
	ma, va := meanVarSimd(a)
	mb, vb := meanVarSimd(b)
	return (ma - mb) / math.Sqrt(va/float64(len(a))+vb/float64(len(b)))
}

func meanVarSimd(x []float64) (mean, variance float64) {
	for _, v := range x {
		mean += v
	}
	mean /= float64(len(x))
	for _, v := range x {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(x) - 1)
	return
}

func cropTailSimd(x []float64, frac float64) []float64 {
	c := append([]float64(nil), x...)
	sort.Float64s(c)
	return c[:int(float64(len(c))*frac)]
}

// leakMaxT measures op timing for class 0 (fixed input) vs class 1 (random
// input), staging each pre-built input into one working buffer untimed, and
// returns the max |Welch t| over a few tail crops.
func leakMaxT(prep func(p int), op func(), class []int, iters int) float64 {
	pool := len(class)
	var s [2][]float64
	for i := 0; i < 2000; i++ { // warmup
		prep(i % pool)
		op()
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < iters; i++ {
		p := rng.Intn(pool)
		prep(p)
		t0 := time.Now()
		op()
		s[class[p]] = append(s[class[p]], float64(time.Since(t0).Nanoseconds()))
	}
	maxT := 0.0
	for _, crop := range []float64{1.0, 0.95, 0.9} {
		t := welchTSimd(cropTailSimd(s[0], crop), cropTailSimd(s[1], crop))
		if math.Abs(t) > math.Abs(maxT) {
			maxT = t
		}
	}
	return maxT
}

func TestSimdDudect_vsTable(t *testing.T) {
	if !simdEncryptAvailable() {
		t.Skip("AVX2 unavailable")
	}
	const (
		iters = 400000
		pool  = 512
	)
	key := make([]byte, keySize)
	rng := rand.New(rand.NewSource(7))
	rng.Read(key)

	// pre-build classified inputs: class 0 = all-zero blocks, class 1 = random.
	src := make([][]byte, pool)
	class := make([]int, pool)
	for p := 0; p < pool; p++ {
		b := make([]byte, simdBatch*BlockSize)
		class[p] = p & 1
		if class[p] == 1 {
			rng.Read(b)
		}
		src[p] = b
	}

	c := NewCipher(key)
	dst := make([]byte, simdBatch*BlockSize)
	var work []byte

	simdT := leakMaxT(
		func(p int) { work = src[p] },
		func() { simdBulkEncrypt(c, dst, work) },
		class, iters,
	)
	tableT := leakMaxT(
		func(p int) { work = src[p] },
		func() {
			for b := 0; b < simdBatch; b++ {
				c.Encrypt(dst[b*BlockSize:], work[b*BlockSize:])
			}
		},
		class, iters,
	)

	t.Logf("dudect max|t|:  SIMD=%.1f   table(control)=%.1f", simdT, tableT)

	if math.Abs(tableT) < 4.5 {
		t.Fatalf("positive control FAILED: table cipher not flagged (|t|=%.1f) — detector inert", tableT)
	}
	if math.Abs(simdT) > math.Abs(tableT)/50 {
		t.Fatalf("SIMD path timing too close to the leaky control: SIMD=%.1f control=%.1f", simdT, tableT)
	}
}
