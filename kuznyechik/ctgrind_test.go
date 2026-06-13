//go:build ctgrind

// ctgrind_test.go — EXPERIMENT, build tag `ctgrind`. In-process ctgrind check:
// the constant-time cipher runs in this process (Go's fuzzer sees its coverage),
// and per input we read VALGRIND_COUNT_ERRORS before/after a poisoned Encrypt —
// a rise means a secret-dependent memory access (the table-lookup channel) for
// that input, recorded as a crasher. Run under valgrind; harmless no-op without.
package kuznyechik

import (
	"os"
	"runtime/debug"
	"testing"
)

// ctgCalibrate: a no-poison run whose only memcheck errors are Go-runtime noise;
// --gen-suppressions on it yields the suppression file so COUNT_ERRORS counts
// only poison-induced errors. See gost3410curves/ctgrind_test.go.
var ctgCalibrate = os.Getenv("CTG_CALIBRATE") != ""

// TestKuzCTLeak_Control: under valgrind, poisoning the plaintext and running the
// TABLE Encrypt MUST raise the error count (secret-indexed table loads). If not,
// the detector is broken and the fuzz check is a silent no-op.
func TestKuzCTLeak_Control(t *testing.T) {
	if !ctgUnderValgrind() {
		t.Skip("not running under valgrind")
	}

	debug.SetGCPercent(-1)

	c := NewCipher(make([]byte, keySize))

	var pt, out [BlockSize]byte
	for i := range pt {
		pt[i] = byte(i*13 + 1)
	}

	before := ctgErrors()
	ctgPoisonBytes(pt[:])
	c.Encrypt(out[:], pt[:]) // table path: encTable[pos][pt[pos]] secret-indexed.
	after := ctgErrors()

	if after <= before {
		t.Fatalf("control: table Encrypt was NOT flagged (errors %d→%d); detector broken", before, after)
	}
}

// FuzzKuzCTLeak runs the constant-time Encrypt on the fuzzer's plaintext,
// poisoned, and fails if valgrind reports any new error for that input.
func FuzzKuzCTLeak(f *testing.F) {
	f.Add(make([]byte, BlockSize))
	f.Add([]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80})

	debug.SetGCPercent(-1)

	c := NewCipherCT(make([]byte, keySize))

	f.Fuzz(func(t *testing.T, in []byte) {
		var pt, out [BlockSize]byte
		copy(pt[:], in)

		before := ctgErrors()

		if !ctgCalibrate {
			ctgPoisonBytes(pt[:])
		}

		c.Encrypt(out[:], pt[:])
		ctgUnpoisonBytes(out[:]) // release ciphertext (the intended output).
		ctgUnpoisonBytes(pt[:])  // release input (GC won't scan poison).

		if after := ctgErrors(); after > before {
			t.Fatalf("ctgrind: %d new memcheck error(s) — constant-time leak for plaintext %x", after-before, pt)
		}
	})
}
