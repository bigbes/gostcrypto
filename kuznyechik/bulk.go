// bulk.go — multi-block encryption. EncryptBlocks is a portable API whose
// output always equals successive Encrypt calls; it merely lets the
// experimental SIMD batch path (simd_amd64.go) accelerate full 32-block chunks
// when available. The dispatch lives here so the public surface and the
// per-block fallback compile on every platform and build.
package kuznyechik

import "github.com/bigbes/gostcrypto/internal/alias"

// EncryptBlocks encrypts one or more consecutive BlockSize-byte blocks of src
// into dst, producing output identical to len(src)/BlockSize successive Encrypt
// calls. len(src) must be a positive multiple of BlockSize and len(dst) must be
// at least len(src). dst and src must either not overlap or overlap exactly.
//
// When the package is built with GOEXPERIMENT=simd on amd64 and the CPU has
// AVX2, full 32-block chunks are encrypted by a constant-time SIMD batch engine
// (see simd_amd64.go); the trailing partial chunk, and every other build, use
// the per-block path. The ciphertext is identical in all cases.
func (c *Cipher) EncryptBlocks(dst, src []byte) {
	if len(src) == 0 || len(src)%BlockSize != 0 {
		panic("kuznyechik: EncryptBlocks input not a whole number of blocks")
	}

	if len(dst) < len(src) {
		panic("kuznyechik: EncryptBlocks output smaller than input")
	}

	if alias.InexactOverlap(dst[:len(src)], src) {
		panic("kuznyechik: invalid buffer overlap")
	}

	n := simdBulkEncrypt(c, dst, src)

	for ; n < len(src); n += BlockSize {
		c.Encrypt(dst[n:n+BlockSize], src[n:n+BlockSize])
	}
}
