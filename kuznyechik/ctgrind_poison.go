//go:build ctgrind

// ctgrind_poison.go — EXPERIMENT, build tag `ctgrind`. cgo bridge to valgrind's
// client requests for the in-process constant-time check (excluded from normal
// CGO_ENABLED=0 builds).
package kuznyechik

/*
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>
static void ctg_poison(void *p, unsigned long n)   { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }
static void ctg_unpoison(void *p, unsigned long n)  { VALGRIND_MAKE_MEM_DEFINED(p, n); }
static unsigned long ctg_errors(void)               { return VALGRIND_COUNT_ERRORS; }
static unsigned long ctg_on_valgrind(void)          { return RUNNING_ON_VALGRIND; }
*/
import "C"

import "unsafe"

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

// ctgErrors returns valgrind's cumulative (non-suppressed) error count, or 0 when
// not under valgrind. A before/after delta around a poisoned call detects a
// secret-dependent branch/access for that input.
func ctgErrors() uint64 { return uint64(C.ctg_errors()) }

func ctgUnderValgrind() bool { return C.ctg_on_valgrind() != 0 }
