package mgm_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	"github.com/bigbes/gostcrypto/mgm"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}

	return b
}

// Pinned RFC 9058 / R 1323565.1.026-2019 §A worked-example vectors, taken
// verbatim from mgm-aead.md "Test vectors".
var katCases = []struct {
	name            string
	newBlk          func(key []byte) cipher.Block
	key, nonce      string
	aad, plain      string
	wantCT, wantTag string
}{
	{
		name:   "Kuznyechik",
		newBlk: func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
		key:    "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
		nonce:  "1122334455667700ffeeddccbbaa9988",
		aad:    "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505",
		plain: "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a" +
			"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
		wantCT: "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39" +
			"497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552",
		wantTag: "cf5d656f40c34f5c46e8bb0e29fcdb4c",
	},
	{
		name:   "Magma",
		newBlk: func(k []byte) cipher.Block { return magma.NewCipher(k) },
		key:    "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		nonce:  "12def06b3c130a59",
		aad: "0101010101010101020202020202020203030303030303030404040404040404" +
			"0505050505050505ea",
		plain: "ffeeddccbbaa998811223344556677008899aabbcceeff0a0011223344556677" +
			"99aabbcceeff0a001122334455667788aabbcceeff0a00112233445566778899aabbcc",
		wantCT: "c795066c5f9ea03b85113342459185ae1f2e00d6bf2b785d940470b8bb9c8e7d" +
			"9a5dd3731f7ddc70ec27cb0ace6fa57670f65c646abb75d547aa37c3bcb5c34e03bb9c",
		wantTag: "a7928069aa10fd10",
	},
}

func TestMGM_KAT(t *testing.T) {
	t.Parallel()

	for _, tc := range katCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := unhex(t, tc.key)
			nonce := unhex(t, tc.nonce)
			aad := unhex(t, tc.aad)
			plain := unhex(t, tc.plain)
			wantCT := unhex(t, tc.wantCT)
			wantTag := unhex(t, tc.wantTag)
			want := append(append([]byte{}, wantCT...), wantTag...)
			tagSize := len(wantTag)

			aead, err := mgm.NewMGM(tc.newBlk(key), tagSize)
			if err != nil {
				t.Fatalf("NewMGM: %v", err)
			}

			got := aead.Seal(nil, nonce, plain, aad)
			if !bytes.Equal(got, want) {
				t.Fatalf("Seal mismatch:\n got  %x\n want %x", got, want)
			}

			back, err := aead.Open(nil, nonce, got, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}

			if !bytes.Equal(back, plain) {
				t.Fatalf("round-trip:\n got  %x\n want %x", back, plain)
			}

			// Tamper: flip one ciphertext byte → must fail.
			bad := append([]byte{}, got...)

			bad[0] ^= 0x01

			if _, err := aead.Open(nil, nonce, bad, aad); err == nil {
				t.Fatalf("Open accepted tampered ciphertext")
			}

			// Tamper: flip one tag byte → must fail.
			bad2 := append([]byte{}, got...)

			bad2[len(bad2)-1] ^= 0x01

			if _, err := aead.Open(nil, nonce, bad2, aad); err == nil {
				t.Fatalf("Open accepted tampered tag")
			}
		})
	}
}

func TestMGM_SealAppends(t *testing.T) {
	t.Parallel()

	tc := katCases[0]
	key := unhex(t, tc.key)
	nonce := unhex(t, tc.nonce)
	aad := unhex(t, tc.aad)
	plain := unhex(t, tc.plain)
	want := append(unhex(t, tc.wantCT), unhex(t, tc.wantTag)...)

	aead, err := mgm.NewMGM(tc.newBlk(key), 16)
	if err != nil {
		t.Fatal(err)
	}

	prefix := []byte("PREFIX")
	out := aead.Seal(append([]byte{}, prefix...), nonce, plain, aad)

	if !bytes.HasPrefix(out, prefix) {
		t.Fatalf("Seal did not preserve dst prefix")
	}

	if !bytes.Equal(out[len(prefix):], want) {
		t.Fatalf("appended bytes wrong:\n got  %x\n want %x", out[len(prefix):], want)
	}
}

func TestMGM_NonceRules(t *testing.T) {
	t.Parallel()

	aead, err := mgm.NewMGM(kuznyechik.NewCipher(make([]byte, 32)), 16)
	if err != nil {
		t.Fatal(err)
	}

	mustPanic := func(name string, fn func()) {
		t.Helper()

		defer func() {
			if recover() == nil {
				t.Fatalf("%s: expected panic", name)
			}
		}()

		fn()
	}
	mustPanic("top-bit-set nonce", func() {
		n := make([]byte, 16)

		n[0] = 0x80
		aead.Seal(nil, n, []byte("x"), nil)
	})
	mustPanic("wrong nonce length", func() {
		aead.Seal(nil, make([]byte, 8), []byte("x"), nil)
	})
	mustPanic("empty text and aad", func() {
		aead.Seal(nil, make([]byte, 16), nil, nil)
	})
}

func TestMGM_TagSizeBounds(t *testing.T) {
	t.Parallel()

	blk := magma.NewCipher(make([]byte, 32))
	if _, err := mgm.NewMGM(blk, 3); err == nil {
		t.Fatalf("expected error for tagSize 3")
	}

	if _, err := mgm.NewMGM(blk, 9); err == nil {
		t.Fatalf("expected error for tagSize 9 (>blockSize 8)")
	}

	if _, err := mgm.NewMGM(blk, 4); err != nil {
		t.Fatalf("tagSize 4 should be valid: %v", err)
	}

	if _, err := mgm.NewMGM(blk, 8); err != nil {
		t.Fatalf("tagSize 8 should be valid: %v", err)
	}
}
