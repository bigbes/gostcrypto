//go:build goexperiment.simd && amd64

// simd_amd64.go — EXPERIMENT, build tag `goexperiment.simd` (amd64 only).
//
// A constant-time, byte-sliced Kuznyechik that encrypts a batch of 32 blocks in
// parallel with Go 1.26's experimental SIMD intrinsics (simd/archsimd, AVX2).
// It is the bulk engine behind Cipher.EncryptBlocks; it is the only path here
// that touches archsimd, and it is excluded from every default build (the
// experiment is off, and the file is amd64-only). EXPERIMENT-simd.md documents
// the design, performance and the archsimd gotchas.
//
// # Layout and transforms
//
// 32 blocks are transposed into 16 "byte-sliced" registers: register i holds
// byte i of all 32 blocks (a Uint8x32). The block transforms then act on whole
// registers with no secret-dependent addressing:
//
//   - S (π): a generic 256-entry VPSHUFB lookup. VPSHUFB indexes 16 entries per
//     128-bit lane, so π is split into 16 sub-tables keyed by the high nibble;
//     for each high-nibble value the low nibble is shuffled and blended in.
//   - L: the GF(2^8)-linear transform as a 16×16 matrix multiply-accumulate
//     (simdMatM[j][i] = l(e_i)[j]); each multiply by a constant is two VPSHUFB
//     (low/high nibble product tables) XORed.
//
// Both are data-oblivious, so the batch path is constant-time by construction
// (validated by FuzzEncryptBlocks_vs_Table and the dudect timing test).
//
// # archsimd gotcha
//
// archsimd's right shift (VPSRLW, Uint16x16.ShiftAllRight) is not lowered to
// hardware on Go 1.26 (~50× slower than a real shift); a left shift is fine.
// The high nibble (x>>4) needed for the GF high-nibble index is therefore taken
// via VPMULHUW: MulHigh(x, 0x1000) divides each 16-bit lane by 16, landing both
// bytes' high nibbles in place (simdHi4). VPSHUFB, And/Xor and the emulated
// Merge blend are all fast.
package kuznyechik

import "simd/archsimd"

// simdBatch is the number of blocks processed per byte-sliced batch — one
// Uint8x32 (256-bit) lane per block.
const simdBatch = 32

var (
	simdMaskLow = archsimd.BroadcastUint8x32(0x0f)
	simdMaskHi  = archsimd.BroadcastUint8x32(0xf0)
	simdSub     [16]archsimd.Uint8x32  // π sub-table h, replicated into both 128-bit lanes
	simdHiConst [16]archsimd.Uint8x32  // broadcast(h<<4), for high-nibble selection
	simdMatM    [16][16]byte           // L as a GF(2^8) matrix: simdMatM[j][i] = l(e_i)[j]
	simdGfLo    [256]archsimd.Uint8x32 // gfLo[c][n] = gf(c, n)      (low-nibble product)
	simdGfHi    [256]archsimd.Uint8x32 // gfHi[c][n] = gf(c, n<<4)   (high-nibble product)
	simdC1000   archsimd.Uint16x16     // 0x1000 per u16 lane, for the MulHigh-based x>>4
)

func init() {
	// π split into 16 low-nibble sub-tables, each replicated into both lanes.
	for h := 0; h < 16; h++ {
		var t [32]byte
		copy(t[0:16], pi[h*16:h*16+16])
		copy(t[16:32], pi[h*16:h*16+16])
		simdSub[h] = archsimd.LoadUint8x32Slice(t[:])
		simdHiConst[h] = archsimd.BroadcastUint8x32(byte(h << 4))
	}

	// L matrix: column i is L applied to the i-th unit block (L is linear, so
	// the input byte 0x01 yields exactly the coefficient).
	for i := 0; i < BlockSize; i++ {
		var e [BlockSize]byte
		e[i] = 0x01
		l(&e)
		for j := 0; j < BlockSize; j++ {
			simdMatM[j][i] = e[j]
		}
	}

	// Per-constant nibble product tables for GF multiply-by-constant.
	for c := 0; c < 256; c++ {
		var lo, hi [32]byte
		for n := 0; n < 16; n++ {
			lo[n] = gf(byte(c), byte(n))
			lo[n+16] = lo[n]
			hi[n] = gf(byte(c), byte(n<<4))
			hi[n+16] = hi[n]
		}
		simdGfLo[c] = archsimd.LoadUint8x32Slice(lo[:])
		simdGfHi[c] = archsimd.LoadUint8x32Slice(hi[:])
	}

	var cb [32]byte
	for i := 0; i < 32; i += 2 {
		cb[i+1] = 0x10 // little-endian 0x1000 per uint16 lane
	}
	simdC1000 = archsimd.LoadUint8x32Slice(cb[:]).AsUint16x16()
}

// simdEncryptAvailable reports whether the SIMD batch path can run on this CPU.
func simdEncryptAvailable() bool { return archsimd.X86.AVX2() }

// simdHi4 returns per-byte (x>>4). archsimd's VPSRLW is not lowered on Go 1.26,
// so MulHigh(x, 0x1000) (VPMULHUW, lane/16) is used to place both bytes' high
// nibbles, then masked to the low nibble.
func simdHi4(x archsimd.Uint8x32) archsimd.Uint8x32 {
	return x.AsUint16x16().MulHigh(simdC1000).AsUint8x32().And(simdMaskLow)
}

// simdS applies π to each of the 16 byte-sliced registers.
func simdS(in, out *[16]archsimd.Uint8x32) {
	zero := archsimd.BroadcastUint8x32(0)
	for r := 0; r < 16; r++ {
		v := in[r]
		lo := v.And(simdMaskLow).AsInt8x32()
		hi := v.And(simdMaskHi)
		res := zero
		for h := 0; h < 16; h++ {
			res = simdSub[h].PermuteOrZeroGrouped(lo).Merge(res, hi.Equal(simdHiConst[h]))
		}
		out[r] = res
	}
}

// simdL applies L = the GF(2^8) matrix multiply-accumulate over the 16 registers.
func simdL(in, out *[16]archsimd.Uint8x32) {
	var lo, hi [16]archsimd.Int8x32
	for i := 0; i < 16; i++ {
		lo[i] = in[i].And(simdMaskLow).AsInt8x32()
		hi[i] = simdHi4(in[i]).AsInt8x32()
	}
	for j := 0; j < 16; j++ {
		acc := archsimd.BroadcastUint8x32(0)
		for i := 0; i < 16; i++ {
			c := simdMatM[j][i]
			if c == 0 {
				continue
			}
			acc = acc.Xor(simdGfLo[c].PermuteOrZeroGrouped(lo[i]).Xor(simdGfHi[c].PermuteOrZeroGrouped(hi[i])))
		}
		out[j] = acc
	}
}

// simdBulkEncrypt encrypts whole 32-block chunks of src into dst, producing each
// block identically to Cipher.Encrypt, and returns the number of bytes handled
// (a multiple of simdBatch*BlockSize). Any trailing partial chunk is left for
// the scalar path. It is constant-time and returns 0 when AVX2 is unavailable.
func simdBulkEncrypt(c *Cipher, dst, src []byte) int {
	if !archsimd.X86.AVX2() {
		return 0
	}

	var ks [10][16]archsimd.Uint8x32
	for r := 0; r < 10; r++ {
		for j := 0; j < BlockSize; j++ {
			ks[r][j] = archsimd.BroadcastUint8x32(c.ks[r][j])
		}
	}

	const chunk = simdBatch * BlockSize
	var tmp [simdBatch]byte
	n := 0
	for n+chunk <= len(src) {
		// transpose 32 blocks → 16 byte-sliced registers
		var a, b [16]archsimd.Uint8x32
		for i := 0; i < BlockSize; i++ {
			for bl := 0; bl < simdBatch; bl++ {
				tmp[bl] = src[n+bl*BlockSize+i]
			}
			a[i] = archsimd.LoadUint8x32Slice(tmp[:])
		}

		// 9 LSX rounds (X then S then L) + final round-key add.
		for r := 0; r < 9; r++ {
			for j := 0; j < BlockSize; j++ {
				a[j] = a[j].Xor(ks[r][j])
			}
			simdS(&a, &b)
			simdL(&b, &a)
		}
		for j := 0; j < BlockSize; j++ {
			a[j] = a[j].Xor(ks[9][j])
		}

		// transpose back → contiguous ciphertext
		for i := 0; i < BlockSize; i++ {
			a[i].StoreSlice(tmp[:])
			for bl := 0; bl < simdBatch; bl++ {
				dst[n+bl*BlockSize+i] = tmp[bl]
			}
		}
		n += chunk
	}
	return n
}
