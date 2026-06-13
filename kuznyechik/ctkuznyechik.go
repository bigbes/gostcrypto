// ctkuznyechik.go — EXPERIMENT. Constant-time Kuznyechik.
//
// The table-driven path leaks the key/plaintext through cache timing: every
// round does secret-indexed loads (encTable[pos][blk[pos]], lInvTable[...],
// piInv[blk[i]]) — exactly the AES table-lookup channel (see SECURITY.md). The
// constant-time path removes every secret-dependent address by splitting each
// round into its nonlinear and linear halves and treating each branch-free:
//
//   - S-box (the only nonlinear step): a SWAR full scan. For each PUBLIC table
//     index b it tests all 16 secret bytes at once (two uint64 lanes) with a
//     borrow-safe byte-zero compare and ORs in the broadcast table value. Every
//     entry is read at a public index; the access pattern is secret-independent.
//   - L / L⁻¹ (linear): not a table lookup at all. Because L is GF(2)-linear,
//     L(x) is the XOR of precomputed per-bit columns selected by x's bits with a
//     branch-free mask. Decrypt's L⁻¹ therefore needs no S-box and no scan.
//
// Same outputs as the table path (the parity-verified oracle), validated by
// fuzzing (FuzzCT_vs_Table); ctgrind confirms it instruction-level clean. It is
// ~36× slower than the table path (≈111 ns → ≈4 µs/block) — far better than a
// naive 256-entry full scan, though a bitsliced core would be faster still
// (see SECURITY.md).

package kuznyechik

import (
	"encoding/binary"
	"sync"

	"github.com/bigbes/gostcrypto/internal/ct"
)

// NewCipherCT returns a Kuznyechik cipher whose Encrypt/Decrypt and key schedule
// are constant-time (no secret-dependent memory access). It panics on a key
// whose length is not 32 bytes. Unlike NewCipher it never builds (or pays the
// 64 KiB for) the fused encTable/lInvTable: the constant-time path needs only the
// 256-byte pi/piInv and the 2 KiB of per-bit L columns.
func NewCipherCT(key []byte) *Cipher {
	if len(key) != keySize {
		panic("kuznyechik: invalid key size, want 32 bytes")
	}

	ctColumnsOnce.Do(buildCTColumns)

	c := &Cipher{constantTime: true}
	c.expandKey(key) // uses the constant-time round via c.sl (flag is set).

	return c
}

// Per-bit columns of the linear transforms. L is GF(2)-linear, so L(x) is the XOR
// over the set bits (pos, j) of x of L(unit block holding bit j at byte pos).
// These 16*8 = 128 columns (2 KiB) replace the fused 64 KiB tables' secret-indexed
// scan with 128 branch-free masked XORs. Built from the verified clean-room l/lInv
// on unit-bit blocks (same provenance as encTable) — no literal tables introduced.
var (
	lCol          [BlockSize][8]tableEntry // forward L of bit j at position pos.
	lInvCol       [BlockSize][8]tableEntry // L⁻¹ of bit j at position pos.
	ctColumnsOnce sync.Once
)

func buildCTColumns() {
	for pos := range BlockSize {
		for j := range 8 {
			var e [BlockSize]byte

			e[pos] = 1 << uint(j)
			l(&e)

			lCol[pos][j] = packEntry(&e)

			var d [BlockSize]byte

			d[pos] = 1 << uint(j)
			lInv(&d)

			lInvCol[pos][j] = packEntry(&d)
		}
	}
}

// sl / linv / sinv dispatch the per-round transforms on the (public) constantTime
// flag — the table path by default, the SWAR + bit-combine path when constant-time.

func (c *Cipher) sl(blk *[BlockSize]byte) {
	if c.constantTime {
		ctSLEncrypt(blk)

		return
	}

	slEncrypt(blk)
}

func (c *Cipher) linv(blk *[BlockSize]byte) {
	if c.constantTime {
		ctLInvFast(blk)

		return
	}

	lInvFast(blk)
}

func (c *Cipher) sinv(blk *[BlockSize]byte) {
	if c.constantTime {
		ctSInv(blk)

		return
	}

	sInv(blk)
}

// SWAR broadcast constants for the constant-time byte S-box scan.
const (
	ctBcast01 uint64 = 0x0101010101010101 // 0x01 in every byte lane.
	ctLo7     uint64 = 0x7f7f7f7f7f7f7f7f // low 7 bits of every lane.
	ctHi1     uint64 = 0x8080808080808080 // high bit of every lane.
)

// ctSbox applies an 8-bit S-box table (pi or piInv) to all 16 packed bytes with a
// SWAR full scan. For each PUBLIC index b it forms, per byte lane, an all-ones
// mask iff the (secret) lane equals b, then ORs in the broadcast table value.
// Equality is a borrow-safe byte-zero test: masking off each lane's top bit before
// the add keeps the carry inside the lane, so (((d&Lo7)+Lo7)|d)'s top bit is 0
// exactly when the lane is zero; complement-and-mask leaves 0x80 in matching lanes,
// and the shift-fill expands it to 0xff. Every entry is read at a public index and
// nothing branches on or indexes by the secret. Whole block in 256 iterations.
func ctSbox(hi, lo uint64, tbl *[256]byte) (uint64, uint64) {
	var ah, al uint64

	for b := range 256 {
		bb := ctBcast01 * uint64(b)
		tv := ctBcast01 * uint64(tbl[b])

		dh := hi ^ bb
		mh := ^(((dh & ctLo7) + ctLo7) | dh) & ctHi1 // 0x80 in lanes == b.

		mh >>= 7 // 0x01 in matching lanes.

		// SWAR bit-fill: spread a set bit across all 8 bits of each matching lane.
		mh |= mh << 1
		mh |= mh << 2 //nolint:mnd // SWAR bit-fill shift.
		mh |= mh << 4 //nolint:mnd // 0xff in matching lanes.
		ah |= tv & mh

		dl := lo ^ bb
		ml := ^(((dl & ctLo7) + ctLo7) | dl) & ctHi1

		ml >>= 7

		ml |= ml << 1
		ml |= ml << 2 //nolint:mnd // SWAR bit-fill shift.
		ml |= ml << 4 //nolint:mnd // 0xff in matching lanes.
		al |= tv & ml
	}

	return ah, al
}

// ctLinear applies a linear transform (forward L via lCol, inverse L⁻¹ via
// lInvCol) to the packed block by XOR-accumulating its per-bit columns, each
// gated by a branch-free mask of the corresponding secret bit. No secret-indexed
// access: every column is touched, selected only by ct.Mask of the bit.
func ctLinear(hi, lo uint64, col *[BlockSize][8]tableEntry) (uint64, uint64) {
	var t [BlockSize]byte

	binary.BigEndian.PutUint64(t[0:8], hi)
	binary.BigEndian.PutUint64(t[8:16], lo)

	var rh, rl uint64

	for pos := range BlockSize {
		bv := t[pos]
		for j := range 8 {
			m := ct.Mask(uint64(bv >> uint(j)))

			rh ^= col[pos][j].hi & m
			rl ^= col[pos][j].lo & m
		}
	}

	return rh, rl
}

// ctSLEncrypt is the constant-time fused S∘L round (Encrypt / key schedule):
// SWAR S-box then the linear bit-combine of L.
func ctSLEncrypt(blk *[BlockSize]byte) {
	hi := binary.BigEndian.Uint64(blk[0:8])
	lo := binary.BigEndian.Uint64(blk[8:16])

	hi, lo = ctSbox(hi, lo, &pi)
	hi, lo = ctLinear(hi, lo, &lCol)

	binary.BigEndian.PutUint64(blk[0:8], hi)
	binary.BigEndian.PutUint64(blk[8:16], lo)
}

// ctLInvFast is the constant-time L⁻¹ round (Decrypt): the linear bit-combine
// alone — no S-box, no scan (S⁻¹ is applied separately by ctSInv).
func ctLInvFast(blk *[BlockSize]byte) {
	hi := binary.BigEndian.Uint64(blk[0:8])
	lo := binary.BigEndian.Uint64(blk[8:16])

	hi, lo = ctLinear(hi, lo, &lInvCol)

	binary.BigEndian.PutUint64(blk[0:8], hi)
	binary.BigEndian.PutUint64(blk[8:16], lo)
}

// ctSInv is the constant-time inverse S-box: a SWAR full scan of piInv.
func ctSInv(blk *[BlockSize]byte) {
	hi := binary.BigEndian.Uint64(blk[0:8])
	lo := binary.BigEndian.Uint64(blk[8:16])

	hi, lo = ctSbox(hi, lo, &piInv)

	binary.BigEndian.PutUint64(blk[0:8], hi)
	binary.BigEndian.PutUint64(blk[8:16], lo)
}
