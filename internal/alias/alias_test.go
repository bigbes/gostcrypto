package alias

import "testing"

func TestAnyOverlap(t *testing.T) {
	buf := make([]byte, 16)

	// Exact overlap (same pointer, same length) — overlaps.
	if !AnyOverlap(buf, buf) {
		t.Fatal("AnyOverlap: exact overlap must return true")
	}

	// Shifted overlap: buf[0:8] and buf[4:12] share bytes 4..7.
	if !AnyOverlap(buf[0:8], buf[4:12]) {
		t.Fatal("AnyOverlap: shifted overlap must return true")
	}

	// Disjoint slices.
	a := make([]byte, 8)
	b := make([]byte, 8)
	if AnyOverlap(a, b) {
		t.Fatal("AnyOverlap: disjoint slices must return false")
	}

	// Empty slices never overlap.
	if AnyOverlap(nil, buf) || AnyOverlap(buf, nil) || AnyOverlap(nil, nil) {
		t.Fatal("AnyOverlap: empty slice must return false")
	}
}

func TestInexactOverlap(t *testing.T) {
	buf := make([]byte, 16)

	// Exact overlap (same start) — NOT inexact.
	if InexactOverlap(buf, buf) {
		t.Fatal("InexactOverlap: exact overlap must return false")
	}

	// Shifted overlap: buf[0:8] and buf[1:9] — inexact.
	if !InexactOverlap(buf[0:8], buf[1:9]) {
		t.Fatal("InexactOverlap: shifted overlap must return true")
	}

	// Disjoint slices.
	a := make([]byte, 8)
	b := make([]byte, 8)
	if InexactOverlap(a, b) {
		t.Fatal("InexactOverlap: disjoint slices must return false")
	}

	// Empty slices.
	if InexactOverlap(nil, buf) || InexactOverlap(buf, nil) {
		t.Fatal("InexactOverlap: empty slice must return false")
	}
}
