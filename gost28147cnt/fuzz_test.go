package gost28147cnt_test

// fuzz_test.go contains oracle-free fuzz targets for gost28147cnt.

import (
	"bytes"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147cnt"
)

// FuzzSplitInvariance checks the split-streaming invariant: XORing the same
// plaintext through a single CNT instance in multiple non-block-aligned calls
// must equal the output of a fresh instance doing it in one shot. This is
// oracle-free — it only requires the output to be consistent with itself.
//
// The fuzz corpus includes lengths past 2 KiB so the fuzzer exercises the
// 1024-byte CryptoPro meshing boundary (triggered at byte 1024 and 2048).
// A bug in partial-gamma carry (num), counter end-around carry, or key
// meshing will be detected because it produces different bytes depending on
// how the input is split — a deterministic single-shot call cannot mask it.
func FuzzSplitInvariance(f *testing.F) {
	// Seed corpus: various lengths and S-box choices, including meshing-crossing.
	f.Add(make([]byte, 32), make([]byte, gost28147.KeySize), make([]byte, gost28147.BlockSize), true, uint8(3))
	f.Add(make([]byte, 1040), make([]byte, gost28147.KeySize), make([]byte, gost28147.BlockSize), false, uint8(7))
	f.Add(make([]byte, 2100), make([]byte, gost28147.KeySize), make([]byte, gost28147.BlockSize), true, uint8(13))
	f.Add([]byte("short"), make([]byte, gost28147.KeySize), make([]byte, gost28147.BlockSize), false, uint8(1))

	f.Fuzz(func(t *testing.T, pt []byte, rawKey []byte, rawIV []byte, cryptoPro bool, chunkSeed uint8) {
		// Normalize key and IV to the required sizes.
		key := make([]byte, gost28147.KeySize)
		iv := make([]byte, gost28147.BlockSize)

		copy(key, rawKey)
		copy(iv, rawIV)

		// Ensure the plaintext is at least 2 KiB so meshing is exercised when
		// the fuzzer generates long inputs. Shorter inputs are still accepted —
		// they exercise the no-mesh and partial-block paths.
		if len(pt) > 4096 {
			pt = pt[:4096]
		}

		sbox := gost28147.SboxCryptoProA
		if !cryptoPro {
			sbox = gost28147.SboxTC26Z
		}

		n := len(pt)

		// One-shot reference.
		oneShot := make([]byte, n)
		gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv).XORKeyStream(oneShot, pt)

		// Chunked streaming: split the input at fuzzer-chosen boundaries.
		got := make([]byte, n)
		s := gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv)
		off := 0

		step := chunkSeed
		for off < n {
			chunk := 1 + int(step%17)
			if off+chunk > n {
				chunk = n - off
			}

			s.XORKeyStream(got[off:off+chunk], pt[off:off+chunk])

			off += chunk

			step = step*31 + 7
		}

		if !bytes.Equal(got, oneShot) {
			t.Fatalf("split mismatch at offset %d (n=%d, chunkSeed=%d)",
				firstDiff(got, oneShot), n, chunkSeed)
		}
	})
}
