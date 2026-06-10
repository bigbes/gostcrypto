// Package alias provides dst/src overlap checks for streaming primitives.
package alias

import "unsafe"

// AnyOverlap reports whether x and y share any memory.
func AnyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// InexactOverlap reports whether x and y overlap without x[0] == y[0].
// cipher.Stream/Block implementations must panic on inexact overlap.
func InexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}

	return AnyOverlap(x, y)
}
