package gost28147cnt_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147cnt"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// keystream returns the first n bytes of the CNT keystream for the given
// S-box, all-zero 32-byte key and all-zero 8-byte IV (XOR over zero plaintext).
func keystream(sbox gost28147.SBox, n int) []byte {
	key := make([]byte, gost28147.KeySize)
	iv := make([]byte, gost28147.BlockSize)
	s := gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox)
	out := make([]byte, n)
	s.XORKeyStream(out, out) // src is zero → out becomes the raw gamma.

	return out
}

// TestKAT_FirstBlocks pins the guide's first-32-byte keystream vectors for
// both S-boxes (zero key, zero IV). G0 is the headline first-gamma-block
// vector: 8671cdbf3c1aae3f (tc26-Z) and 7f775ae1edb7082b (CryptoPro-A).
func TestKAT_FirstBlocks(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		sbox gost28147.SBox
		g0   string
		want string
	}{
		{
			name: "tc26-Z",
			sbox: gost28147.SboxTC26Z,
			g0:   "8671cdbf3c1aae3f",
			want: "8671cdbf3c1aae3f637fa5cfaa0cb42fa5a47a133d73b9f2c0b04f8ca25552f8",
		},
		{
			name: "CryptoPro-A",
			sbox: gost28147.SboxCryptoProA,
			g0:   "7f775ae1edb7082b",
			want: "7f775ae1edb7082b95a46f38e46d4026d74593cd0a8874dc202d705df54f7899",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := keystream(tc.sbox, 32)
			if g0 := hex.EncodeToString(got[0:8]); g0 != tc.g0 {
				t.Errorf("G0 = %s, want %s", g0, tc.g0)
			}

			if want := mustHex(t, tc.want); !bytes.Equal(got, want) {
				t.Errorf("first 32 bytes = %x, want %x", got, want)
			}
		})
	}
}

// TestKAT_KeyMeshing pins the guide's >1024-byte keystream straddling the
// CryptoPro key-meshing boundary (D6): bytes [1016:1024] are pre-mesh and
// [1024:1040] are post-mesh for both S-boxes.
func TestKAT_KeyMeshing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		sbox              gost28147.SBox
		pre, post0, post1 string
	}{
		{
			name:  "tc26-Z",
			sbox:  gost28147.SboxTC26Z,
			pre:   "d0db6a6941467fc7",
			post0: "5184cd1d30f1544d",
			post1: "3d115a61239b6d9c",
		},
		{
			name:  "CryptoPro-A",
			sbox:  gost28147.SboxCryptoProA,
			pre:   "7b9ef231641fa725",
			post0: "56f45eab8381b608",
			post1: "4399badbc168977d",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ks := keystream(tc.sbox, 1040)
			if got := hex.EncodeToString(ks[1016:1024]); got != tc.pre {
				t.Errorf("pre-mesh [1016:1024] = %s, want %s", got, tc.pre)
			}

			if got := hex.EncodeToString(ks[1024:1032]); got != tc.post0 {
				t.Errorf("post-mesh [1024:1032] = %s, want %s", got, tc.post0)
			}

			if got := hex.EncodeToString(ks[1032:1040]); got != tc.post1 {
				t.Errorf("post-mesh [1032:1040] = %s, want %s", got, tc.post1)
			}
		})
	}
}

// TestKAT_EngineEncTry pins the gost-engine tcl etalon-file CNT encryption
// (tmp/engine/tcl_tests/enc.try:54, "Encrypting etalon file with GOST89-CNT
// mode"):
//
//	openssl enc -gost89-cnt -in plain.enc -out cnt1.enc \
//	    -K EF164FDF5B1128DE44AFCC00A0323DC1090EC99DE9C6B085B0D2550AB9F1AF47 \
//	    -iv 9AF32B4E2FB1DF3D -p
//
// The S-box is CryptoPro-A: the script sets
// CRYPT_PARAMS=id-tc26-gost-28147-param-Z (tmp/engine/tcl_tests/enc.try:26),
// but the gost89-cnt EVP cipher ignores it — its init hook is
// gost_cipher_init_cpa, which hardcodes Gost28147_CryptoProParamSetA
// (tmp/engine/gost_crypt.c:180, :458-462; only gost89-cnt-12 uses tc26-Z).
// The plaintext is the 21-byte ASCII file
// tmp/engine/tcl_tests/plain.enc ("Test data to encrypt "), the expected
// ciphertext is the 21-byte binary etalon tmp/engine/tcl_tests/cnt1.enc
// (inlined below as hex). Because -K/-iv are given explicitly, OpenSSL writes
// raw ciphertext with no Salted__ header.
//
// The same ciphertext also appears as the payload of the decryption etalon
// tmp/engine/tcl_tests/cnt0.enc (enc.try:33), which prepends an OpenSSL
// "Salted__" + 8-byte-salt header: the password-derived key/IV
// (EVP_BytesToKey, md5, -k 1234567890) coincide with the explicit -K/-iv
// above, so this KAT covers both etalon files. The decrypt direction is
// exercised for free since CNT is an involution.
func TestKAT_EngineEncTry(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "ef164fdf5b1128de44afcc00a0323dc1090ec99de9c6b085b0d2550ab9f1af47")
	iv := mustHex(t, "9af32b4e2fb1df3d")
	pt := []byte("Test data to encrypt ")
	wantCT := mustHex(t, "1be52c139e7e6ab38844b1a40f7567bc5d1e175f27")

	sbox := gost28147.SboxCryptoProA

	ct := make([]byte, len(pt))
	gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox).XORKeyStream(ct, pt)

	if !bytes.Equal(ct, wantCT) {
		t.Errorf("encrypt: got %x, want %x", ct, wantCT)
	}

	back := make([]byte, len(wantCT))
	gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox).XORKeyStream(back, wantCT)

	if !bytes.Equal(back, pt) {
		t.Errorf("decrypt: got %q, want %q", back, pt)
	}
}

// TestInvolution verifies XOR is its own inverse: encrypting then decrypting
// with the same key/IV (two fresh CNT instances) recovers the plaintext.
func TestInvolution(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1")
	iv := mustHex(t, "0123456789abcdef")

	for _, sbox := range []gost28147.SBox{gost28147.SboxCryptoProA, gost28147.SboxTC26Z} {
		for _, n := range []int{0, 1, 7, 8, 9, 15, 16, 17, 100, 1024, 1040, 3000} {
			pt := make([]byte, n)
			for i := range pt {
				pt[i] = byte(i*7 + 3)
			}

			ct := make([]byte, n)
			gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox).XORKeyStream(ct, pt)

			back := make([]byte, n)
			gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox).XORKeyStream(back, ct)

			if !bytes.Equal(back, pt) {
				t.Fatalf("n=%d: involution failed", n)
			}

			if n > 0 && bytes.Equal(ct, pt) {
				t.Fatalf("n=%d: ciphertext equals plaintext (no encryption?)", n)
			}
		}
	}
}

// TestStreamingEqualsOneShot checks that splitting the input across multiple
// XORKeyStream calls at non-block-aligned boundaries equals a single call.
func TestStreamingEqualsOneShot(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1")
	iv := mustHex(t, "fedcba9876543210")
	sbox := gost28147.SboxTC26Z

	const n = 1100 // crosses the meshing boundary.

	pt := make([]byte, n)

	for i := range pt {
		pt[i] = byte(i)
	}

	oneShot := make([]byte, n)
	gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox).XORKeyStream(oneShot, pt)

	// Split at several awkward boundaries.
	for _, splits := range [][]int{{1}, {7}, {8}, {9}, {3, 5, 13, 64, 511, 513}, {1023, 1024, 1025}} {
		s := gost28147cnt.NewCNT(gost28147.NewCipher(key, sbox), iv, sbox)
		got := make([]byte, n)
		off := 0

		for _, sp := range splits {
			if sp > off {
				s.XORKeyStream(got[off:sp], pt[off:sp])

				off = sp
			}
		}

		s.XORKeyStream(got[off:], pt[off:])

		if !bytes.Equal(got, oneShot) {
			t.Fatalf("splits %v: streaming != one-shot", splits)
		}
	}
}
