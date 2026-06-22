//go:build goexperiment.simd && amd64

// simd_ctr_amd64.go — EXPERIMENT (goexperiment.simd, amd64). The fully-SIMD CTR
// keystream used by ctracpkm for Kuznyechik.
//
// Unlike EncryptBlocks there is no input transpose and no per-block counter
// materialisation: in CTR the "plaintext" is the counter sequence, which is
// generated directly byte-sliced with a SIMD ramp + carry (slicedCounters), and
// the keystream XOR is fused into the output transpose. This is the one place
// the block cipher knows the CTR counter convention (16-byte big-endian,
// incremented from the last byte) — a deliberate layering trade for throughput;
// ctracpkm dispatches to CTRXORBlocks via an optional interface and otherwise
// uses the generic EncryptBlocks batch path.
package kuznyechik

import "simd/archsimd"

// simdCTRRamp = {0,1,2,…,31}: the per-block offset added to the counter's least
// significant byte across the 32 byte-sliced lanes.
var simdCTRRamp = func() archsimd.Uint8x32 {
	var r [simdBatch]byte
	for i := range r {
		r[i] = byte(i)
	}

	return archsimd.LoadUint8x32Slice(r[:])
}()

// slicedCounters builds the 16 byte-sliced registers for the 32 consecutive
// counters ctr+0 … ctr+31, with full big-endian carry propagation, using only
// SIMD ops — no transpose. reg[j] holds byte j of every counter.
func slicedCounters(ctr *[BlockSize]byte) [16]archsimd.Uint8x32 {
	one := archsimd.BroadcastUint8x32(1)

	var reg [16]archsimd.Uint8x32

	// least significant byte: base + {0..31}; carry where the add wrapped.
	b := archsimd.BroadcastUint8x32(ctr[15])
	reg[15] = b.Add(simdCTRRamp)
	carry := one.Masked(reg[15].Less(b)) // 1 where wrapped, else 0

	for j := 14; j >= 0; j-- {
		b = archsimd.BroadcastUint8x32(ctr[j])
		reg[j] = b.Add(carry)
		carry = one.Masked(reg[j].Less(b))
	}

	return reg
}

// addCounter adds k (0 ≤ k ≤ simdBatch) to the 16-byte big-endian counter,
// from the last byte upward.
func addCounter(ctr *[BlockSize]byte, k int) {
	v := int(ctr[BlockSize-1]) + k
	ctr[BlockSize-1] = byte(v)

	carry := v >> 8
	for j := BlockSize - 2; j >= 0 && carry != 0; j-- {
		v = int(ctr[j]) + carry
		ctr[j] = byte(v)
		carry = v >> 8
	}
}

// CTRXORBlocks XORs len(src) bytes — a whole number of blocks — of src into dst
// using the Kuznyechik-CTR keystream E(iv), E(iv+1), …, where iv is the full
// 16-byte big-endian counter. iv is advanced in place by len(src)/BlockSize
// blocks. dst and src must be the same length; they may coincide exactly. It is
// constant-time: counters are generated and encrypted data-obliviously.
func (c *Cipher) CTRXORBlocks(dst, src, iv []byte) {
	var ks [10][16]archsimd.Uint8x32
	for r := 0; r < 10; r++ {
		for j := 0; j < BlockSize; j++ {
			ks[r][j] = archsimd.BroadcastUint8x32(c.ks[r][j])
		}
	}

	var ctr [BlockSize]byte
	copy(ctr[:], iv)

	total := len(src) / BlockSize

	var tmp [simdBatch]byte
	for done := 0; done < total; {
		k := simdBatch
		if rem := total - done; rem < k {
			k = rem
		}

		a := slicedCounters(&ctr)

		var b [16]archsimd.Uint8x32
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

		// fused: XOR the keystream into dst during the output transpose, storing
		// only the k valid blocks of this (possibly partial) chunk.
		base := done * BlockSize
		for i := 0; i < BlockSize; i++ {
			a[i].StoreSlice(tmp[:])

			for bl := 0; bl < k; bl++ {
				off := base + bl*BlockSize + i
				dst[off] = src[off] ^ tmp[bl]
			}
		}

		addCounter(&ctr, k)
		done += k
	}

	copy(iv, ctr[:])
}
