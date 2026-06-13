// ctscalar_fuzz_test.go — EXPERIMENT. Differential fuzz: the constant-time
// ScalarMultCT must equal the trusted variable-time ScalarMult for every
// scalar, on every supported curve. ScalarMult is itself parity-verified against
// gogost/gost-engine, so equality with it is the correctness oracle.
//
// Range note: for the 256-bit curves orderBits == 256, so the ladder/window
// reads the full 256-bit scalar — the two impls agree for any k in [0, 2^256).
// The fuzzer's bytes are therefore truncated to 32 bytes (no mod needed).

package gost3410curves //nolint:testpackage // white-box: uses unexported curve constructors.

import (
	"math/big"
	"testing"
)

func FuzzScalarMult_CTvsRef(f *testing.F) {
	curves := []*Curve{
		curveCryptoProA(), // 256-bit, a ≡ −3, cofactor 1.
		curveCryptoProC(), // 256-bit, a ≡ −3.
		curveTc26256A(),   // 256-bit, a ≢ −3, cofactor 4 — general path.
		curveTc26512A(),   // 512-bit (8-limb path), cofactor 1.
		curveTc26512C(),   // 512-bit, cofactor 4.
	}

	// Seeds: boundaries that have bitten EC code before.
	f.Add([]byte{0})                                            // k = 0 → identity.
	f.Add([]byte{1})                                            // k = 1 → base point.
	f.Add([]byte{2})                                            // k = 2 → a doubling.
	f.Add(curves[0].Q.Bytes())                                  // k = Q → identity.
	f.Add(new(big.Int).Sub(curves[0].Q, big.NewInt(1)).Bytes()) // k = Q−1.
	f.Add(make([]byte, 32))                                     // 32 zero bytes.

	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) > 64 {
			in = in[:64] // up to 512 bits.
		}

		k := new(big.Int).SetBytes(in)

		for _, c := range curves {
			// The CT window reads exactly orderBits of the scalar, so reduce k
			// to [0, 2^orderBits) — the range where it must match ScalarMult.
			kc := new(big.Int).Mod(k, new(big.Int).Lsh(big.NewInt(1), uint(c.Q.BitLen())))

			ref := c.ScalarMult(kc, c.Base())
			ct := c.ScalarMultCT(kc, c.Base())

			if !affineEqual(ref, ct) {
				t.Fatalf("curve=%s k=%x\n ref=%v\n  ct=%v", c.Name, kc, ref, ct)
			}
		}
	})
}
