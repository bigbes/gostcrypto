//go:build goexperiment.simd && amd64

package kuznyechik

import (
	"bytes"
	"math/rand"
	"testing"
)

// scalar CTR keystream oracle: E(iv), E(iv+1), … with the same big-endian,
// byte-15-LSB counter layout used by ctracpkm and slicedCounters.
func scalarCTRKeystream(c *Cipher, iv []byte, nblk int) []byte {
	var ctr [BlockSize]byte
	copy(ctr[:], iv)

	out := make([]byte, nblk*BlockSize)
	for k := 0; k < nblk; k++ {
		c.Encrypt(out[k*BlockSize:], ctr[:])

		for j := BlockSize - 1; j >= 0; j-- {
			ctr[j]++
			if ctr[j] != 0 {
				break
			}
		}
	}

	return out
}

func advanceCounter(iv []byte, nblk int) []byte {
	out := append([]byte(nil), iv...)
	for range nblk {
		for j := BlockSize - 1; j >= 0; j-- {
			out[j]++
			if out[j] != 0 {
				break
			}
		}
	}

	return out
}

// CTRXORBlocks must equal "scalar keystream XOR src", and advance iv by exactly
// the block count, for block counts that straddle the 32-block chunk (including
// partial final chunks) and for carry-rippling IVs.
func TestCTRXORBlocks_vsScalar(t *testing.T) {
	if !simdEncryptAvailable() {
		t.Skip("AVX2 unavailable")
	}

	key := make([]byte, keySize)
	rng := rand.New(rand.NewSource(42))
	rng.Read(key)

	c := NewCipher(key)

	ivs := [][]byte{
		mustHexBytes("00000000000000000000000000000000"),
		mustHexBytes("000000000000000000000000000000f0"), // +31 wraps byte 15
		mustHexBytes("0000000000000000000000000000ffff"), // ripples into byte 13
		mustHexBytes("112233445566778899aabbccddeeff00"),
	}
	counts := []int{1, 31, 32, 33, 50, 64, 100}

	for _, ivBase := range ivs {
		for _, nblk := range counts {
			n := nblk * BlockSize
			src := make([]byte, n)
			rng.Read(src)

			ks := scalarCTRKeystream(c, ivBase, nblk)

			want := make([]byte, n)
			for i := range want {
				want[i] = src[i] ^ ks[i]
			}

			iv := append([]byte(nil), ivBase...)
			got := make([]byte, n)
			c.CTRXORBlocks(got, src, iv)

			if !bytes.Equal(got, want) {
				t.Fatalf("iv=%x nblk=%d: CTRXORBlocks output wrong", ivBase, nblk)
			}

			if wantIV := advanceCounter(ivBase, nblk); !bytes.Equal(iv, wantIV) {
				t.Fatalf("iv=%x nblk=%d: iv advanced to %x, want %x", ivBase, nblk, iv, wantIV)
			}
		}
	}
}

func mustHexBytes(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		hi := fromHex(s[2*i])
		lo := fromHex(s[2*i+1])
		b[i] = hi<<4 | lo
	}

	return b
}

func fromHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return 0
	}
}

// Fused CTR keystream (sliced counters, fused XOR) vs the EncryptBlocks batch at
// the same block count.
func BenchmarkCTRXORBlocks(b *testing.B) {
	if !simdEncryptAvailable() {
		b.Skip("AVX2 unavailable")
	}

	c := NewCipher(make([]byte, keySize))
	iv := make([]byte, BlockSize)

	const nblk = simdBatch * 4

	src := make([]byte, nblk*BlockSize)
	dst := make([]byte, nblk*BlockSize)

	b.SetBytes(int64(len(dst)))
	b.ResetTimer()

	for range b.N {
		c.CTRXORBlocks(dst, src, iv) // iv drifts across iterations; irrelevant to timing
	}
}

func BenchmarkEncryptBlocks_sameSize(b *testing.B) {
	if !simdEncryptAvailable() {
		b.Skip("AVX2 unavailable")
	}

	c := NewCipher(make([]byte, keySize))

	const nblk = simdBatch * 4

	src := make([]byte, nblk*BlockSize)
	dst := make([]byte, nblk*BlockSize)

	b.SetBytes(int64(len(dst)))
	b.ResetTimer()

	for range b.N {
		c.EncryptBlocks(dst, src)
	}
}
