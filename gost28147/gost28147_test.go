package gost28147_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// TestECB_KAT checks the pinned single-block ECB vector from the guide §V1
// (CryptoPro-A S-box) and the inverse round-trip.
func TestECB_KAT(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		sbox          gost28147.SBox
		key, in, want string
	}{
		{
			name: "V1/CryptoProA",
			sbox: gost28147.SboxCryptoProA,
			key:  "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1",
			in:   "1020304050607080",
			want: "2685b30ddb497d05",
		},
		{
			name: "V1b/TC26Z",
			sbox: gost28147.SboxTC26Z,
			key:  "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1",
			in:   "1020304050607080",
			want: "9810491f00ca7be0",
		},
		// Additional TC26-Z ECB blocks re-derived against gost-engine 3.0.3:
		//   openssl enc -gost89-cbc -K <key> -iv 0..0 -nopad   (one block, IV=0
		// makes CBC degenerate to ECB; the engine's default gost89 S-box is
		// TC26-Z, confirmed by V1b above).
		{
			name: "TC26Z/key-ff/pt-00",
			sbox: gost28147.SboxTC26Z,
			key:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			in:   "0000000000000000",
			want: "40531adb91bb60fe",
		},
		{
			name: "TC26Z/key-00/pt-ff",
			sbox: gost28147.SboxTC26Z,
			key:  "0000000000000000000000000000000000000000000000000000000000000000",
			in:   "ffffffffffffffff",
			want: "6c2daf00dfeeb00b",
		},
		{
			name: "TC26Z/seq-key",
			sbox: gost28147.SboxTC26Z,
			key:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			in:   "fedcba9876543210",
			want: "1d1784cbba12a4fd",
		},
		{
			name: "TC26Z/std-key/pt-0123",
			sbox: gost28147.SboxTC26Z,
			key:  "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1",
			in:   "0123456789abcdef",
			want: "3ee43a4da8beba38",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, in, want := mustHex(t, tc.key), mustHex(t, tc.in), mustHex(t, tc.want)

			c := gost28147.NewCipher(key, tc.sbox)
			got := make([]byte, gost28147.BlockSize)
			c.Encrypt(got, in)

			if !bytes.Equal(got, want) {
				t.Fatalf("Encrypt: got %x want %x", got, want)
			}

			back := make([]byte, gost28147.BlockSize)
			c.Decrypt(back, got)

			if !bytes.Equal(back, in) {
				t.Fatalf("Decrypt(Encrypt): got %x want %x", back, in)
			}
		})
	}
}

// TestRoundTrip exercises Decrypt(Encrypt(p)) == p across both S-boxes and a
// spread of deterministic inputs.
func TestRoundTrip(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1")
	for _, sbox := range []gost28147.SBox{gost28147.SboxCryptoProA, gost28147.SboxTC26Z} {
		c := gost28147.NewCipher(key, sbox)

		for seed := range 256 {
			var p [gost28147.BlockSize]byte

			x := uint64(seed)*0x9E3779B97F4A7C15 + 0x123456789ABCDEF

			for i := range gost28147.BlockSize {
				p[i] = byte(x >> (8 * i))
			}

			var ct, back [gost28147.BlockSize]byte

			c.Encrypt(ct[:], p[:])
			c.Decrypt(back[:], ct[:])

			if !bytes.Equal(back[:], p[:]) {
				t.Fatalf("seed %d: round-trip %x != %x", seed, back[:], p[:])
			}
		}
	}
}

// TestSBoxesArePermutations sanity-checks each transcribed S-box row.
func TestSBoxesArePermutations(t *testing.T) {
	t.Parallel()

	check := func(name string, s gost28147.SBox) {
		for i, row := range s {
			var seen [16]bool

			for _, v := range row {
				if v > 15 {
					t.Fatalf("%s row %d: nibble %d out of range", name, i, v)
				}

				if seen[v] {
					t.Fatalf("%s row %d: duplicate nibble %d", name, i, v)
				}

				seen[v] = true
			}
		}
	}
	check("CryptoProA", gost28147.SboxCryptoProA)
	check("TC26Z", gost28147.SboxTC26Z)
}
