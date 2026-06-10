package alias_test

import (
	"testing"

	"github.com/bigbes/gostcrypto/internal/alias"
)

func TestAnyOverlap(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 16)

	// Exact overlap (same pointer, same length) — overlaps.
	if !alias.AnyOverlap(buf, buf) {
		t.Fatal("AnyOverlap: exact overlap must return true")
	}

	// Shifted overlap: buf[0:8] and buf[4:12] share bytes 4..7.
	if !alias.AnyOverlap(buf[0:8], buf[4:12]) {
		t.Fatal("AnyOverlap: shifted overlap must return true")
	}

	// Disjoint slices.
	a := make([]byte, 8)

	b := make([]byte, 8)
	if alias.AnyOverlap(a, b) {
		t.Fatal("AnyOverlap: disjoint slices must return false")
	}

	// Empty slices never overlap.
	if alias.AnyOverlap(nil, buf) || alias.AnyOverlap(buf, nil) || alias.AnyOverlap(nil, nil) {
		t.Fatal("AnyOverlap: empty slice must return false")
	}
}

func TestInexactOverlap(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 16)

	// Exact overlap (same start) — NOT inexact.
	if alias.InexactOverlap(buf, buf) {
		t.Fatal("InexactOverlap: exact overlap must return false")
	}

	// Shifted overlap: buf[0:8] and buf[1:9] — inexact.
	if !alias.InexactOverlap(buf[0:8], buf[1:9]) {
		t.Fatal("InexactOverlap: shifted overlap must return true")
	}

	// Disjoint slices.
	a := make([]byte, 8)

	b := make([]byte, 8)
	if alias.InexactOverlap(a, b) {
		t.Fatal("InexactOverlap: disjoint slices must return false")
	}

	// Empty slices.
	if alias.InexactOverlap(nil, buf) || alias.InexactOverlap(buf, nil) {
		t.Fatal("InexactOverlap: empty slice must return false")
	}
}
