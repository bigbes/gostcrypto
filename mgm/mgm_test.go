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

	// Kuznyechik bounds.
	kblk := kuznyechik.NewCipher(make([]byte, 32))
	if _, err := mgm.NewMGM(kblk, 3); err == nil {
		t.Fatalf("Kuznyechik: expected error for tagSize 3")
	}

	if _, err := mgm.NewMGM(kblk, 17); err == nil {
		t.Fatalf("Kuznyechik: expected error for tagSize 17 (>blockSize 16)")
	}

	if _, err := mgm.NewMGM(kblk, 4); err != nil {
		t.Fatalf("Kuznyechik: tagSize 4 should be valid: %v", err)
	}

	if _, err := mgm.NewMGM(kblk, 16); err != nil {
		t.Fatalf("Kuznyechik: tagSize 16 should be valid: %v", err)
	}
}

// TestMGM_RFC9058_Example2 ports RFC 9058 Appendix A Example 2 vectors
// (MGM-52): A.1.2 (Kuznyechik, AAD-only / empty plaintext) and A.2.2
// (Magma, empty AAD / exact-one-block plaintext).
//
// Vectors from mgm/rfc/rfc9058.txt:647-697 (A.1.2) and :919-978 (A.2.2).
func TestMGM_RFC9058_Example2(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		newBlk          func(key []byte) cipher.Block
		key, nonce      string
		aad, plain      string
		wantCT, wantTag string
	}{
		{
			// rfc/rfc9058.txt:647-697 (A.1.2): Kuznyechik, AAD-only, empty plaintext.
			name:    "Kuznyechik_A1.2_AAD_only",
			newBlk:  func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
			key:     "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88",
			nonce:   "1122334455667700ffeeddccbbaa9988",
			aad:     "01010101010101010101010101010101",
			plain:   "",
			wantCT:  "",
			wantTag: "7901e9ea2085cd247ed249695f9f8a85",
		},
		{
			// rfc/rfc9058.txt:919-978 (A.2.2): Magma, empty AAD, exact-one-block plaintext.
			name:    "Magma_A2.2_empty_AAD",
			newBlk:  func(k []byte) cipher.Block { return magma.NewCipher(k) },
			key:     "99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88",
			nonce:   "0077665544332211",
			aad:     "",
			plain:   "22334455667700ff",
			wantCT:  "6a95e1426b259d4e",
			wantTag: "334ee270450bec9e",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := unhex(t, tc.key)
			nonce := unhex(t, tc.nonce)
			aad := unhex(t, tc.aad)
			plain := unhex(t, tc.plain)
			wantCT := unhex(t, tc.wantCT)
			wantTag := unhex(t, tc.wantTag)
			want := append(append([]byte{}, wantCT...), wantTag...)

			aead, err := mgm.NewMGM(tc.newBlk(key), len(wantTag))
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

			// Tamper: flip last tag byte → must fail.
			bad := append([]byte{}, got...)

			bad[len(bad)-1] ^= 0x01

			if _, err := aead.Open(nil, nonce, bad, aad); err == nil {
				t.Fatalf("Open accepted tampered tag")
			}
		})
	}
}

// TestMGM_TruncatedTags exercises end-to-end Seal/Open with truncated tag sizes
// (MGM-53). It verifies: Seal/Open round-trip succeeds, corrupted tag fails,
// and the truncated tag equals the MSB prefix of the full-size tag.
func TestMGM_TruncatedTags(t *testing.T) {
	t.Parallel()

	kuznKey := unhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	kuznNonce := unhex(t, "1122334455667700ffeeddccbbaa9988")
	kuznAAD := unhex(t, "0202020202020202")
	kuznPlain := unhex(t, "0011223344556677")

	magmaKey := unhex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	magmaNonce := unhex(t, "12def06b3c130a59")
	magmaAAD := unhex(t, "0101010101010101")
	magmaPlain := unhex(t, "ffeeddccbbaa9988")

	type caseT struct {
		name    string
		newBlk  func() cipher.Block
		fullTag int
		nonce   []byte
		aad     []byte
		plain   []byte
	}

	cases := []caseT{
		{
			name:    "Kuznyechik/S=4",
			newBlk:  func() cipher.Block { return kuznyechik.NewCipher(kuznKey) },
			fullTag: 16, nonce: kuznNonce, aad: kuznAAD, plain: kuznPlain,
		},
		{
			name:    "Kuznyechik/S=8",
			newBlk:  func() cipher.Block { return kuznyechik.NewCipher(kuznKey) },
			fullTag: 16, nonce: kuznNonce, aad: kuznAAD, plain: kuznPlain,
		},
		{
			name:    "Kuznyechik/S=12",
			newBlk:  func() cipher.Block { return kuznyechik.NewCipher(kuznKey) },
			fullTag: 16, nonce: kuznNonce, aad: kuznAAD, plain: kuznPlain,
		},
		{
			name:    "Magma/S=4",
			newBlk:  func() cipher.Block { return magma.NewCipher(magmaKey) },
			fullTag: 8, nonce: magmaNonce, aad: magmaAAD, plain: magmaPlain,
		},
		{
			name:    "Magma/S=6",
			newBlk:  func() cipher.Block { return magma.NewCipher(magmaKey) },
			fullTag: 8, nonce: magmaNonce, aad: magmaAAD, plain: magmaPlain,
		},
	}

	tagSizes := map[string]int{
		"Kuznyechik/S=4":  4,
		"Kuznyechik/S=8":  8,
		"Kuznyechik/S=12": 12,
		"Magma/S=4":       4,
		"Magma/S=6":       6,
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tagSize := tagSizes[tc.name]

			// Full-tag AEAD.
			fullAEAD, err := mgm.NewMGM(tc.newBlk(), tc.fullTag)
			if err != nil {
				t.Fatalf("NewMGM full: %v", err)
			}

			// Truncated-tag AEAD.
			truncAEAD, err := mgm.NewMGM(tc.newBlk(), tagSize)
			if err != nil {
				t.Fatalf("NewMGM trunc: %v", err)
			}

			fullOut := fullAEAD.Seal(nil, tc.nonce, tc.plain, tc.aad)
			truncOut := truncAEAD.Seal(nil, tc.nonce, tc.plain, tc.aad)

			// Truncated ciphertext equals full ciphertext.
			if !bytes.Equal(truncOut[:len(tc.plain)], fullOut[:len(tc.plain)]) {
				t.Fatalf("ciphertext mismatch: trunc %x vs full %x", truncOut[:len(tc.plain)], fullOut[:len(tc.plain)])
			}

			// Truncated tag equals MSB prefix of full tag (RFC 9058 MSB_S truncation).
			fullTag := fullOut[len(tc.plain):]
			truncTag := truncOut[len(tc.plain):]

			if !bytes.Equal(truncTag, fullTag[:tagSize]) {
				t.Fatalf("truncated tag %x is not prefix of full tag %x", truncTag, fullTag)
			}

			// Round-trip: Open must succeed.
			back, err := truncAEAD.Open(nil, tc.nonce, truncOut, tc.aad)
			if err != nil {
				t.Fatalf("Open round-trip: %v", err)
			}

			if !bytes.Equal(back, tc.plain) {
				t.Fatalf("round-trip: got %x want %x", back, tc.plain)
			}

			// Tamper: flip last tag byte → must fail.
			bad := append([]byte{}, truncOut...)

			bad[len(bad)-1] ^= 0x01

			if _, err := truncAEAD.Open(nil, tc.nonce, bad, tc.aad); err == nil {
				t.Fatalf("Open accepted tampered tag")
			}

			// Short ciphertext (fewer bytes than tag) → must fail.
			tooShort := make([]byte, tagSize-1)
			if _, err := truncAEAD.Open(nil, tc.nonce, tooShort, tc.aad); err == nil {
				t.Fatalf("Open accepted ciphertext shorter than tag")
			}
		})
	}
}

// TestMGM_InPlaceAliasing verifies that Seal with dst=plaintext[:0] (in-place
// aliasing) produces the same result as non-aliased Seal (MGM-54).
func TestMGM_InPlaceAliasing(t *testing.T) {
	t.Parallel()

	key := unhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	nonce := unhex(t, "1122334455667700ffeeddccbbaa9988")
	aad := unhex(t, "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505")
	plain := unhex(t,
		"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
	)

	aead, err := mgm.NewMGM(kuznyechik.NewCipher(key), 16)
	if err != nil {
		t.Fatal(err)
	}

	// Normal Seal.
	want := aead.Seal(nil, nonce, plain, aad)

	// In-place: dst shares the same backing array as plain, starting before it.
	inPlace := make([]byte, 0, len(plain)+16)

	inPlace = append(inPlace, plain...)

	got := aead.Seal(inPlace[:0], nonce, inPlace[:len(plain)], aad)

	if !bytes.Equal(got, want) {
		t.Fatalf("in-place Seal mismatch:\n got  %x\n want %x", got, want)
	}
}

// FuzzSealOpenRoundTrip is a fuzz target for MGM's Seal/Open contract (MGM-54).
// It verifies: Open(Seal(pt)) == pt; a single byte mutation in ct||tag causes Open to fail.
// Seeds are derived from the four RFC Appendix A vectors.
func FuzzSealOpenRoundTrip(f *testing.F) {
	// Seed from Example 1 Kuznyechik.
	f.Add(
		unhexF("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		unhexF("1122334455667700ffeeddccbbaa9988"),
		unhexF("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505"),
		unhexF(
			"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"+
				"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
		),
		byte(0), // sel=0: Kuznyechik, full tag.
	)
	// Seed from Example 1 Magma.
	f.Add(
		unhexF("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		unhexF("12def06b3c130a59"),
		unhexF("0101010101010101020202020202020203030303030303030404040404040404050505050505050505"),
		unhexF("ffeeddccbbaa998811223344556677008899aabbcceeff0a0011223344556677"),
		byte(1), // sel=1: Magma, full tag.
	)

	f.Fuzz(func(t *testing.T, key, nonce, aad, plain []byte, sel byte) {
		var (
			newBlk  func([]byte) cipher.Block
			blockSz int
		)

		if sel&1 == 0 {
			blockSz = 16

			if len(key) < 32 {
				key = append(key, make([]byte, 32-len(key))...)
			}

			key = key[:32]
			newBlk = func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) }
		} else {
			blockSz = 8

			if len(key) < 32 {
				key = append(key, make([]byte, 32-len(key))...)
			}

			key = key[:32]
			newBlk = func(k []byte) cipher.Block { return magma.NewCipher(k) }
		}

		// Tag size: 4..blockSz, derived from sel.
		tagSize := 4 + int(sel>>2)%(blockSz-4+1)

		// Nonce: exactly blockSz bytes, top bit clear.
		if len(nonce) < blockSz {
			nonce = append(nonce, make([]byte, blockSz-len(nonce))...)
		}

		nonce = nonce[:blockSz]

		nonce[0] &= 0x7f

		// At least one of aad/plain must be non-empty.
		if len(aad) == 0 && len(plain) == 0 {
			plain = []byte{0x00}
		}

		aead, err := mgm.NewMGM(newBlk(key), tagSize)
		if err != nil {
			return
		}

		ct := aead.Seal(nil, nonce, plain, aad)

		got, err := aead.Open(nil, nonce, ct, aad)
		if err != nil {
			t.Fatalf("Open(Seal(pt)) failed: %v", err)
		}

		if !bytes.Equal(got, plain) {
			t.Fatalf("round-trip mismatch: got %x want %x", got, plain)
		}

		if len(ct) == 0 {
			return
		}

		// Mutate one byte in ct||tag → Open must fail.
		mutIdx := int(sel) % len(ct)
		bad := append([]byte{}, ct...)

		bad[mutIdx] ^= 0x01

		if _, err := aead.Open(nil, nonce, bad, aad); err == nil {
			t.Fatalf("Open accepted ciphertext with flipped byte at index %d", mutIdx)
		}
	})
}

// unhexF decodes a hex string, panicking on error. Used to seed fuzz corpora.
func unhexF(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return b
}
