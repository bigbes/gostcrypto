// ctbench_test.go — EXPERIMENT. Performance benchmarks for ScalarMult.
//
// The wall-clock timing-leak demonstration moved to cttiming_test.go (build tag
// `dudect`); these benchmarks stay in the default build so `go test -bench` can
// discover them without a tag.

package gost3410curves //nolint:testpackage // white-box: uses unexported ctCurve/scalarMult internals.

import (
	"math/big"
	"testing"
)

func BenchmarkScalarMult_BigInt(b *testing.B) {
	c := curveCryptoProA()
	g := c.Base()
	k := new(big.Int).Sub(c.Q, big.NewInt(1))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.ScalarMult(k, g)
	}
}

func BenchmarkScalarMult_CT(b *testing.B) {
	c := curveCryptoProA()
	cc := newCTCurve(c)
	base := cc.fromAffine(c.Base())
	k := new(big.Int).Sub(c.Q, big.NewInt(1))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = cc.scalarMult(k, base)
	}
}

// BenchmarkScalarMultCT_Public times the public cached method end-to-end
// (affine in, affine out). With the per-Curve cache, it should track the hot
// path plus one inversion for the final toAffine — proving the context is built
// once, not per call.
func BenchmarkScalarMultCT_Public(b *testing.B) {
	c := curveCryptoProA()
	g := c.Base()
	k := new(big.Int).Sub(c.Q, big.NewInt(1))

	_ = c.ScalarMultCT(big.NewInt(1), g) // prime the cache.

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = c.ScalarMultCT(k, g)
	}
}
