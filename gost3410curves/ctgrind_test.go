//go:build ctgrind

// ctgrind_test.go — EXPERIMENT, build tag `ctgrind`. The in-process ctgrind
// check: the constant-time scalar mult runs IN this process (so Go's fuzzer sees
// its coverage and can mutate toward new paths), and per input we read valgrind's
// error count before/after a poisoned call — if it rose, that input drove a
// secret-dependent branch/access, so we fail and the fuzzer records it as a
// crasher in testdata/fuzz/.
//
// Run under valgrind: `valgrind <pkg>.test -test.run=FuzzScalarMultCTLeak`
// replays the seed corpus; add -test.fuzz for active coverage-guided fuzzing
// (valgrind --trace-children=yes so the fuzz workers are traced too). Without
// valgrind the client requests return 0, so it is a harmless no-op that still
// exercises the code.
package gost3410curves

import (
	"math/big"
	"os"
	"runtime/debug"
	"testing"
	"unsafe"
)

// ctgCalibrate is set for a no-poison "calibration" run whose only memcheck
// errors are Go-runtime noise; valgrind --gen-suppressions on that run yields a
// suppression file so the real (poison) run's VALGRIND_COUNT_ERRORS counts only
// poison-induced errors. (Go's runtime trips memcheck; without this the count is
// dominated by runtime noise, not the secret.)
var ctgCalibrate = os.Getenv("CTG_CALIBRATE") != ""

// TestScalarMultCTLeak_Control is the integrity check: under valgrind, poisoning
// the scalar and running the VARIABLE-TIME ScalarMult MUST raise the error count
// (it branches on the secret). If it doesn't, the detector is broken and the
// fuzz check below would be a silent no-op — so fail loudly.
func TestScalarMultCTLeak_Control(t *testing.T) {
	if !ctgUnderValgrind() {
		t.Skip("not running under valgrind")
	}

	debug.SetGCPercent(-1)

	c := curveCryptoProA()
	k := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 254), big.NewInt(1))

	before := ctgErrors()
	ctgPoison(k)
	_ = c.ScalarMult(k, c.Base()) // variable-time: `if k.Bit(i)==1` on the poison.
	after := ctgErrors()

	if after <= before {
		t.Fatalf("control: variable-time ScalarMult was NOT flagged (errors %d→%d); detector broken", before, after)
	}
}

// FuzzScalarMultCTLeak runs the constant-time path on the fuzzer's scalar,
// poisoned, and fails if valgrind reports any new error for that input.
func FuzzScalarMultCTLeak(f *testing.F) {
	f.Add([]byte{1})
	f.Add([]byte{0})
	f.Add(make([]byte, 32))
	f.Add(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 254), big.NewInt(1)).Bytes())

	debug.SetGCPercent(-1)

	c := curveCryptoProA()
	cc := c.ctCurve()
	base := cc.fromAffine(c.Base())

	f.Fuzz(func(t *testing.T, in []byte) {
		var kb [ctLimbs * 8]byte
		copy(kb[:], in) // up to 32 bytes of the fuzzer input as the secret scalar.

		before := ctgErrors()

		if !ctgCalibrate {
			ctgPoisonBytes(kb[:])
		}

		r := cc.scalarMultLimbs(scalarBytesToLimbs(kb[:]), base)
		ctgUnpoison(unsafe.Pointer(&r), unsafe.Sizeof(r)) // release result.
		ctgUnpoisonBytes(kb[:])                           // release input (GC won't scan poison).

		if after := ctgErrors(); after > before {
			t.Fatalf("ctgrind: %d new memcheck error(s) — constant-time leak for scalar %x", after-before, kb)
		}
	})
}
