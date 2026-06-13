package ct //nolint:testpackage // white-box style: kept in-package with the other ct unit tests.

import "testing"

func TestMask(t *testing.T) {
	t.Parallel()

	if Mask(0) != 0 {
		t.Fatalf("Mask(0) = %#x, want 0", Mask(0))
	}

	if Mask(1) != ^uint64(0) {
		t.Fatalf("Mask(1) = %#x, want all-ones", Mask(1))
	}

	if Mask(0xFE) != 0 { // only the low bit counts.
		t.Fatalf("Mask(0xFE) = %#x, want 0", Mask(0xFE))
	}

	if Mask(0xFF) != ^uint64(0) {
		t.Fatalf("Mask(0xFF) = %#x, want all-ones", Mask(0xFF))
	}
}

func TestEqAndByteEq(t *testing.T) {
	t.Parallel()

	for a := range 256 {
		for b := range 256 {
			want := uint64(0)
			if a == b {
				want = ^uint64(0)
			}

			if got := Eq(uint64(a), uint64(b)); got != want {
				t.Fatalf("Eq(%d,%d) = %#x, want %#x", a, b, got, want)
			}

			if got := ByteEq(byte(a), byte(b)); got != want {
				t.Fatalf("ByteEq(%d,%d) = %#x, want %#x", a, b, got, want)
			}
		}
	}

	// A wide pair that differs only in the top bit.
	if Eq(1<<63, 0) != 0 {
		t.Fatal("Eq(2^63, 0) should be 0")
	}

	if Eq(1<<63, 1<<63) != ^uint64(0) {
		t.Fatal("Eq(2^63, 2^63) should be all-ones")
	}
}

func TestSelectByte(t *testing.T) {
	t.Parallel()

	if got := SelectByte(0xFF, 0xAB, 0xCD); got != 0xAB {
		t.Fatalf("SelectByte(0xFF,...) = %#x, want 0xAB", got)
	}

	if got := SelectByte(0x00, 0xAB, 0xCD); got != 0xCD {
		t.Fatalf("SelectByte(0x00,...) = %#x, want 0xCD", got)
	}
}
