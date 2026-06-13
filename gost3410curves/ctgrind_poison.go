//go:build ctgrind

// ctgrind_poison.go — EXPERIMENT, build tag `ctgrind` (excluded from normal
// CGO_ENABLED=0 builds). The cgo bridge to valgrind's client requests, used by
// the in-process ctgrind constant-time check (ctgrind_test.go).
//
// Go forbids `import "C"` in *_test.go, so the cgo lives here.
package gost3410curves

/*
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>
static void ctg_poison(void *p, unsigned long n)   { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }
static void ctg_unpoison(void *p, unsigned long n)  { VALGRIND_MAKE_MEM_DEFINED(p, n); }
static unsigned long ctg_errors(void)               { return VALGRIND_COUNT_ERRORS; }
static unsigned long ctg_on_valgrind(void)          { return RUNNING_ON_VALGRIND; }
*/
import "C"

import (
	"math/big"
	"unsafe"
)

// ctgPoison marks the backing words of k as uninitialised, so memcheck flags any
// branch or memory address that depends on the secret scalar's value.
func ctgPoison(k *big.Int) {
	w := k.Bits()
	if len(w) == 0 {
		return
	}
	C.ctg_poison(unsafe.Pointer(&w[0]), C.ulong(uintptr(len(w))*unsafe.Sizeof(w[0])))
}

// ctgPoisonBytes / ctgUnpoisonBytes (un)poison a byte slice (the secret scalar).
func ctgPoisonBytes(b []byte) {
	if len(b) != 0 {
		C.ctg_poison(unsafe.Pointer(&b[0]), C.ulong(len(b)))
	}
}

func ctgUnpoisonBytes(b []byte) {
	if len(b) != 0 {
		C.ctg_unpoison(unsafe.Pointer(&b[0]), C.ulong(len(b)))
	}
}

// ctgUnpoison re-marks a region defined — used to "release" the result before
// serialisation so its taint doesn't mask whether the arithmetic branched.
func ctgUnpoison(p unsafe.Pointer, n uintptr) { C.ctg_unpoison(p, C.ulong(n)) }

// ctgErrors returns valgrind's cumulative (non-suppressed) error count, or 0 when
// not running under valgrind. A before/after delta around a poisoned call is how
// the in-process fuzz check detects a secret-dependent branch/access for that
// input.
func ctgErrors() uint64 { return uint64(C.ctg_errors()) }

// ctgUnderValgrind reports whether the process is running under valgrind.
func ctgUnderValgrind() bool { return C.ctg_on_valgrind() != 0 }
