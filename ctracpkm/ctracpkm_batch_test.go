package ctracpkm_test

import (
	"bytes"
	"crypto/cipher"
	"math/rand"
	"testing"

	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
)

// noBulkBlock wraps a cipher.Block so it does NOT expose EncryptBlocks; the
// embedded interface promotes only the cipher.Block methods. A CTR over it
// therefore takes the per-block path, giving a reference to test the batched
// path against.
type noBulkBlock struct{ cipher.Block }

func newKuzNoBulk(k []byte) cipher.Block { return noBulkBlock{kuznyechik.NewCipher(k)} }

func newStream(newBlock func([]byte) cipher.Block, key, iv []byte, section int) cipher.Stream {
	if section == 0 {
		return ctracpkm.NewCTR(newBlock(key), iv)
	}

	return ctracpkm.NewCTRACPKM(newBlock, key, iv, section)
}

func runStream(newBlock func([]byte) cipher.Block, key, iv []byte, section int, plain []byte, chunks []int) []byte {
	s := newStream(newBlock, key, iv, section)
	out := make([]byte, len(plain))

	off := 0

	for _, n := range chunks {
		if off+n > len(plain) {
			n = len(plain) - off
		}

		s.XORKeyStream(out[off:off+n], plain[off:off+n])

		off += n
	}

	if off < len(plain) {
		s.XORKeyStream(out[off:], plain[off:])
	}

	return out
}

// The batched keystream (raw kuznyechik.Cipher, which exposes EncryptBlocks)
// must equal the per-block keystream (the same cipher wrapped to hide it) for
// every input length, ACPKM section size, and split pattern — including runs
// that cross the 32-block batch boundary and the rekey boundary.
func TestBatch_EquivalentToPerBlock(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(1))
	key := make([]byte, 32)
	iv := make([]byte, 16)

	rng.Read(key)
	rng.Read(iv)

	plain := make([]byte, 20000) // > 4 Kuznyechik sections, many 32-block batches.

	rng.Read(plain)

	sections := []int{0, 512, 4096} // plain CTR, section==batch boundary, default.
	splits := map[string][]int{
		"one-shot":      nil,
		"mid-block":     {1, 7, 1000, 17},
		"block-aligned": {512, 4096, 16},
		"section-edge":  {4095, 1, 512, 4097},
		"tiny":          {3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
	}

	for _, section := range sections {
		want := runStream(newKuzNoBulk, key, iv, section, plain, nil) // per-block, one-shot.

		for name, chunks := range splits {
			got := runStream(newKuz, key, iv, section, plain, chunks) // batched.
			if !bytes.Equal(got, want) {
				t.Fatalf("section=%d split=%q: batched != per-block", section, name)
			}
		}
	}
}

func benchCTR(b *testing.B, newBlock func([]byte) cipher.Block, section int) {
	b.Helper()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	plain := make([]byte, 16384) // one TLS record.
	dst := make([]byte, len(plain))

	// Build the stream once: measure steady-state keystream throughput, not the
	// one-time key schedule. The counter advances freely across iterations.
	s := newStream(newBlock, key, iv, section)

	b.SetBytes(int64(len(plain)))
	b.ResetTimer()

	for range b.N {
		s.XORKeyStream(dst, plain)
	}
}

func BenchmarkCTR_Kuz_Batched(b *testing.B)  { benchCTR(b, newKuz, 0) }
func BenchmarkCTR_Kuz_PerBlock(b *testing.B) { benchCTR(b, newKuzNoBulk, 0) }

func BenchmarkACPKM_Kuz_Batched(b *testing.B) {
	benchCTR(b, newKuz, ctracpkm.SectionKuznyechik)
}

func BenchmarkACPKM_Kuz_PerBlock(b *testing.B) {
	benchCTR(b, newKuzNoBulk, ctracpkm.SectionKuznyechik)
}
