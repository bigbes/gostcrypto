// ctkuznyechik_test.go — EXPERIMENT. The constant-time cipher must be a
// byte-for-byte drop-in for the table-driven one. The table path is itself
// parity-verified against gogost/gost-engine, so equality with it is the oracle.

package kuznyechik //nolint:testpackage // white-box: uses unexported keySize.

import (
	"bytes"
	"math/rand"
	"testing"
)

// FuzzCT_vs_Table: for any key+block, NewCipherCT encrypts/decrypts identically
// to NewCipher, and decrypt inverts encrypt.
func FuzzCT_vs_Table(f *testing.F) {
	seed := make([]byte, keySize+BlockSize)
	f.Add(seed)

	for i := range seed {
		seed[i] = byte(i * 7)
	}

	f.Add(seed)

	f.Fuzz(func(t *testing.T, in []byte) {
		if len(in) < keySize+BlockSize {
			return
		}

		key := in[:keySize]
		pt := in[keySize : keySize+BlockSize]

		ref := NewCipher(key)
		ctc := NewCipherCT(key)

		var encRef, encCT [BlockSize]byte
		ref.Encrypt(encRef[:], pt)
		ctc.Encrypt(encCT[:], pt)

		if !bytes.Equal(encRef[:], encCT[:]) {
			t.Fatalf("encrypt mismatch\nkey=%x pt=%x\n ref=%x\n  ct=%x", key, pt, encRef, encCT)
		}

		var decRef, decCT [BlockSize]byte
		ref.Decrypt(decRef[:], encRef[:])
		ctc.Decrypt(decCT[:], encCT[:])

		if !bytes.Equal(decRef[:], decCT[:]) {
			t.Fatalf("decrypt mismatch\nkey=%x\n ref=%x\n  ct=%x", key, decRef, decCT)
		}

		// Round-trip through the constant-time path.
		if !bytes.Equal(decCT[:], pt) {
			t.Fatalf("CT round-trip failed: pt=%x got=%x", pt, decCT)
		}
	})
}

// TestCT_MatchesTable_Random covers many random key/block pairs directly.
func TestCT_MatchesTable_Random(t *testing.T) {
	t.Parallel()

	r := rand.New(rand.NewSource(1))
	key := make([]byte, keySize)
	pt := make([]byte, BlockSize)

	for i := range 2000 {
		r.Read(key)
		r.Read(pt)

		ref := NewCipher(key)
		ctc := NewCipherCT(key)

		var a, b [BlockSize]byte
		ref.Encrypt(a[:], pt)
		ctc.Encrypt(b[:], pt)

		if !bytes.Equal(a[:], b[:]) {
			t.Fatalf("encrypt mismatch i=%d key=%x pt=%x", i, key, pt)
		}

		var da, db [BlockSize]byte
		ref.Decrypt(da[:], a[:])
		ctc.Decrypt(db[:], b[:])

		if !bytes.Equal(da[:], db[:]) || !bytes.Equal(db[:], pt) {
			t.Fatalf("decrypt/round-trip mismatch i=%d key=%x", i, key)
		}
	}
}

func BenchmarkEncrypt_Table(b *testing.B) {
	c := NewCipher(make([]byte, keySize))

	var pt, ct [BlockSize]byte

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Encrypt(ct[:], pt[:])
	}
}

func BenchmarkEncrypt_CT(b *testing.B) {
	c := NewCipherCT(make([]byte, keySize))

	var pt, ct [BlockSize]byte

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Encrypt(ct[:], pt[:])
	}
}

func BenchmarkDecrypt_CT(b *testing.B) {
	c := NewCipherCT(make([]byte, keySize))

	var pt, ct [BlockSize]byte

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Decrypt(pt[:], ct[:])
	}
}
