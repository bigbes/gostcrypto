// Package ct holds the small constant-time masking primitives shared by the
// clean-room constant-time code (the GOST EC scalar multiply, the Kuznyechik
// constant-time block path, …). Everything here is branch-free in its operand
// values: a mask is all-ones or all-zeros, and callers combine it with AND/OR
// instead of branching. These compile to data-independent instructions on
// amd64/arm64 (no division, no value-dependent jumps).
//
// This is the masking vocabulary the full-table-scan pattern is built on: to
// read table[secret] without leaking the index, scan EVERY entry and select the
// match with Eq/ByteEq + Mask, so the memory-access pattern is independent of
// the secret.
package ct

// wordTopBit is the index of the most significant bit of a uint64; shifting a
// value right by it isolates that top bit (1 when the value is nonzero-derived).
const wordTopBit = 63

// Mask turns a 0/1 selector into a full word mask: 0 → 0x0000…0, 1 → 0xFFFF…F.
// Only the low bit of sel is consulted.
func Mask(sel uint64) uint64 { return uint64(0) - (sel & 1) }

// Eq returns all-ones when a == b and all-zeros otherwise (constant-time).
func Eq(a, b uint64) uint64 {
	d := a ^ b
	// (d | -d) has its top bit set iff d != 0; >>63 is then 1 (≠) or 0 (=).
	nz := (d | (0 - d)) >> wordTopBit

	return nz - 1 // d==0 → 0-1 = all-ones; d!=0 → 1-1 = 0.
}

// ByteEq returns a full word mask (all-ones / all-zeros) for whether the two
// bytes are equal — the workhorse for a constant-time 256-entry table scan.
func ByteEq(a, b byte) uint64 { return Eq(uint64(a), uint64(b)) }

// SelectByte returns a if mask is all-ones, b if mask is all-zeros (branch-free).
// mask must be 0x00 or 0xFF (a byte-wide mask).
func SelectByte(mask, a, b byte) byte { return (a & mask) | (b &^ mask) }
