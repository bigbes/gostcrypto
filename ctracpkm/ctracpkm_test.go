package ctracpkm_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

func newKuz(k []byte) cipher.Block   { return kuznyechik.NewCipher(k) }
func newMagma(k []byte) cipher.Block { return magma.NewCipher(k) }

// Plain Kuznyechik CTR, GOST R 34.13-2015 A.1.2 (ctr-acpkm.md §"Plain CTR
// KATs"). First 32 bytes f195d8be...3c45dee4 also anchor the ACPKM vector.
func TestCTR_Kuznyechik_KAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "1234567890abcef00000000000000000") // 8B nonce zero-padded to 16.
	plain := mustHex(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011")
	// 64-byte expected ciphertext from GOST R 34.13-2015 Table A.2 (all four
	// blocks f195d8be...20bdba73 appear verbatim in the standard).
	// Source: ctracpkm/rfc/GOST_R_34.13-2015.pdf, Table A.2, pp. 25-26.
	want := mustHex(t,
		"f195d8bec10ed1dbd57b5fa240bda1b8"+
			"85eee733f6a13e5df33ce4b33c45dee4"+
			"a5eae88be6356ed3d5e877f13564a3a5"+
			"cb91fab1f20cbab6d1c6d15820bdba73")
	got := make([]byte, len(plain))
	ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv).XORKeyStream(got, plain)

	if !bytes.HasSuffix(got, []byte{0x20, 0xbd, 0xba, 0x73}) {
		t.Fatalf("Kuznyechik CTR KAT end anchor: got tail %x", got[len(got)-4:])
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("Kuznyechik CTR KAT full:\n got  %x\n want %x", got, want)
	}
}

// Plain Magma CTR, GOST R 34.13-2015 A.2.2 (ctr-acpkm.md §"Plain CTR KATs").
func TestCTR_Magma_KAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	iv := mustHex(t, "1234567800000000") // 4B nonce zero-padded to 8.
	plain := mustHex(t, "92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41")
	want := mustHex(t, "4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d")
	got := make([]byte, len(plain))
	ctracpkm.NewCTR(magma.NewCipher(key), iv).XORKeyStream(got, plain)

	if !bytes.Equal(got, want) {
		t.Fatalf("Magma CTR KAT:\n got  %x\n want %x", got, want)
	}
}

// TestCTR_Magma_EngineTclKAT ports the gost-engine tcl magma-ctr vector
// (tmp/engine/tcl_tests/enc.try:215-217):
//
//	openssl enc -magma-ctr -K ffee...feff -iv 1234567800000000 \
//	    -in magma_plain.enc -out magma1.enc
//
// -K is the hex key, and the engine's 8-byte -iv carries the 4-byte Magma CTR
// nonce 12345678 in its high half with a zero low half — exactly the
// fully-assembled counter our NewCTR takes. The plaintext is the 32-byte
// etalon file tmp/engine/tcl_tests/magma_plain.enc and the expected
// ciphertext the 32-byte etalon tmp/engine/tcl_tests/magma1.enc, both inlined
// in full below (extracted via xxd). The data coincides with the GOST R
// 34.13-2015 A.2.2 example (TestCTR_Magma_KAT above), but this pins the
// engine's own etalon files and its IV encoding independently. The decrypt
// direction is asserted too (CTR is an involution).
func TestCTR_Magma_EngineTclKAT(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	iv := mustHex(t, "1234567800000000") // engine -iv, verbatim.
	plain := mustHex(t,                  // tmp/engine/tcl_tests/magma_plain.enc.
		"92def06b3c130a59db54c704f8189d20"+
			"4a98fb2e67a8024c8912409b17b57e41")
	cipherText := mustHex(t, // tmp/engine/tcl_tests/magma1.enc.
		"4e98110c97b7b93c3e250d93d6e85d69"+
			"136d868807b2dbef568eb680ab52a12d")

	got := make([]byte, len(plain))
	ctracpkm.NewCTR(magma.NewCipher(key), iv).XORKeyStream(got, plain)

	if !bytes.Equal(got, cipherText) {
		t.Fatalf("magma-ctr encrypt (enc.try:215):\n got  %x\n want %x", got, cipherText)
	}

	back := make([]byte, len(cipherText))
	ctracpkm.NewCTR(magma.NewCipher(key), iv).XORKeyStream(back, cipherText)

	if !bytes.Equal(back, plain) {
		t.Fatalf("magma-ctr decrypt (enc.try:215):\n got  %x\n want %x", back, plain)
	}
}

// Kuznyechik CTR-ACPKM, section size 32, 112 bytes = 3.5 sections.
// ctr-acpkm.md §"Inline runnable vector".
func TestCTRACPKM_Kuznyechik_Section32(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "1234567890abcef00000000000000000")
	plain := mustHex(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899aabbcceeff0a0011"+
			"33445566778899aabbcceeff0a001122"+
			"445566778899aabbcceeff0a00112233"+
			"5566778899aabbcceeff0a0011223344")
	want := mustHex(t,
		"f195d8bec10ed1dbd57b5fa240bda1b8"+
			"85eee733f6a13e5df33ce4b33c45dee4"+
			"4bceeb8f646f4c55001706275e85e800"+
			"587c4df568d094393e4834afd0805046"+
			"cf30f57686aeece11cfc6c316b8a896e"+
			"dffd07ec813636460c4f3b743423163e"+
			"6409a9c282fac8d469d221e7fbd6de5d")
	got := make([]byte, len(plain))
	ctracpkm.NewCTRACPKM(newKuz, key, iv, 32).XORKeyStream(got, plain)

	if !bytes.Equal(got, want) {
		t.Fatalf("Kuznyechik CTR-ACPKM-32:\n got  %x\n want %x", got, want)
	}

	// Round-trip: decrypt = same gamma.
	back := make([]byte, len(got))
	ctracpkm.NewCTRACPKM(newKuz, key, iv, 32).XORKeyStream(back, got)

	if !bytes.Equal(back, plain) {
		t.Fatalf("ACPKM round-trip mismatch:\n got  %x\n want %x", back, plain)
	}
}

// Kuznyechik CTR-ACPKM-Master, section size 96 (768 bits), encrypting 144 zero
// bytes under the master IV 0xFF*8. Key/IV/expected are the ACPKM-Master vector
// from R 1323565.1.017-2018 A.4.2, taken verbatim from gost-engine 3.0.3
// test_ciphers.c (P_acpkm_master / E_acpkm_master / iv_acpkm_m). This is the key
// material that feeds OMAC-ACPKM.
func TestCTRACPKM_Kuznyechik_Master768(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "ffffffffffffffff0000000000000000") // 8B master IV zero-padded to 16.
	want := mustHex(t,
		"0cabf1f2efbc4ac16048df1a24c605b2"+
			"c0d1673d7586a8ec0dd42c45a4f95bae"+
			"0f2e2617e47148680fc3e6178df2c137"+
			"c9dda89cffa491feadd9b3eab703bb31"+
			"bc7e927f0494729f51b49d3df9c94608"+
			"00fbbcf5edee610ea02f01093c7bc742"+
			"d7d6271501b177775263c2a3495a8318"+
			"a81c79a04f29660ea3fda874c630799e"+
			"142c577914fea90d3bc2502e833685d9")
	plain := make([]byte, len(want)) // all-zero plaintext -> output is the keystream.
	got := make([]byte, len(plain))
	ctracpkm.NewCTRACPKM(newKuz, key, iv, 96).XORKeyStream(got, plain)

	if !bytes.Equal(got, want) {
		t.Fatalf("Kuznyechik CTR-ACPKM-Master-768:\n got  %x\n want %x", got, want)
	}
}

// Magma single ACPKM transform in isolation (K -> K2), ctr-acpkm.md §"Magma
// ACPKM key-meshing KAT (K2)". This test verifies the ACPKM transform
// directly: it computes ACPKM(K) = E_K(D[0:8])||E_K(D[8:16])||E_K(D[16:24])||E_K(D[24:32])
// using magma.NewCipher directly, and checks the result equals the known K2.
// It does NOT invoke the ctracpkm package's rekey path; the end-to-end Magma
// CTR-ACPKM keystream is pinned by TestCTRACPKM_Magma_OfficialA1 below.
func TestACPKM_Magma_K2(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	wantK2 := mustHex(t, "863ea017842c3d372b18a85a28e2317d74befc107720de0c9e8ab974abd00ca0")

	// Compute ACPKM(K) directly: E_K(D[0:8])||...||E_K(D[24:32]) with Magma.
	b := magma.NewCipher(key)
	d := []byte{
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	}
	gotK2 := make([]byte, 32)

	for off := 0; off < 32; off += 8 {
		b.Encrypt(gotK2[off:off+8], d[off:off+8])
	}

	if !bytes.Equal(gotK2, wantK2) {
		t.Fatalf("Magma ACPKM(K):\n got  %x\n want %x", gotK2, wantK2)
	}
}

// N=0 disables ACPKM and must match plain CTR byte-for-byte.
func TestCTRACPKM_MatchesPlainCTR_WhenSectionZero(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "1234567890abcef00000000000000000")
	plain := bytes.Repeat([]byte{0xa5}, 200)

	a := make([]byte, len(plain))
	ctracpkm.NewCTRACPKM(newKuz, key, iv, 0).XORKeyStream(a, plain)

	bb := make([]byte, len(plain))
	ctracpkm.NewCTR(kuznyechik.NewCipher(key), iv).XORKeyStream(bb, plain)

	if !bytes.Equal(a, bb) {
		t.Fatalf("N=0 differs from plain CTR:\n acpkm %x\n plain %x", a, bb)
	}
}

// Split-write equals one-shot (partial-block num carried across calls).
func TestCTR_PartialBlock(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := mustHex(t, "1234567890abcef00000000000000000")
	plain := bytes.Repeat([]byte{0x11}, 100)

	oneShot := make([]byte, len(plain))
	ctracpkm.NewCTRACPKM(newKuz, key, iv, 32).XORKeyStream(oneShot, plain)

	split := make([]byte, len(plain))
	s := ctracpkm.NewCTRACPKM(newKuz, key, iv, 32)

	for _, chunk := range [][2]int{{0, 7}, {7, 23}, {23, 64}, {64, 65}, {65, 100}} {
		s.XORKeyStream(split[chunk[0]:chunk[1]], plain[chunk[0]:chunk[1]])
	}

	if !bytes.Equal(oneShot, split) {
		t.Fatalf("split-write != one-shot:\n one %x\n split %x", oneShot, split)
	}
}

// Big-endian carry: block 2's gamma equals a fresh CTR seeded at IV+1.
func TestCTR_CounterIncrement(t *testing.T) {
	t.Parallel()

	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	// Counter ending in 0xFF in the last byte forces a carry into the next
	// byte on the increment after the first block.
	ivA := mustHex(t, "123456780000000000000000000000ff")
	zero := make([]byte, 32)
	out := make([]byte, 32)
	ctracpkm.NewCTR(kuznyechik.NewCipher(key), ivA).XORKeyStream(out, zero)

	gammaBlock2 := out[16:32]

	// Fresh CTR seeded at ivA+1 — its first block gamma must equal block 2.
	ivB := make([]byte, 16)
	copy(ivB, ivA)

	for i := range slices.Backward(ivB) {
		ivB[i]++
		if ivB[i] != 0 {
			break
		}
	}

	out2 := make([]byte, 16)
	ctracpkm.NewCTR(kuznyechik.NewCipher(key), ivB).XORKeyStream(out2, zero[:16])

	if !bytes.Equal(gammaBlock2, out2) {
		t.Fatalf("counter increment mismatch:\n block2 %x\n freshIV+1 %x", gammaBlock2, out2)
	}
}

// TestCTRACPKM_Magma_OfficialA1 ports the official Magma CTR-ACPKM end-to-end
// vector from R 1323565.1.017-2018 Appendix A.1 (the package's own
// ctracpkm/rfc/R1323565.1.017-2018.pdf, pp. 7-8). This is the only external
// anchor for the Magma ACPKM rekey path (bs=8, N=16, 3 rekeys over 56 bytes).
// The ciphertext was verified empirically against the implementation on
// 2026-06-10 and matches the standard byte-for-byte (confirmed by the audit
// verifier in finding CTRA-01).
//
// N=16 forces a rekey every 16 bytes (every 2 Magma blocks). Over 56 bytes
// there are 3 rekeys (before bytes 17, 33, 49), using section keys K2, K3, K4.
func TestCTRACPKM_Magma_OfficialA1(t *testing.T) {
	t.Parallel()

	// R 1323565.1.017-2018 Appendix A.1, p. 7.
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	// IV is the 4-byte nonce 12345678 zero-padded to the 8-byte Magma counter.
	iv := mustHex(t, "1234567800000000")
	// 56-byte plaintext from the standard.
	plain := mustHex(t,
		"1122334455667700ffeeddccbbaa9988"+
			"00112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a00"+
			"2233445566778899")
	// Expected 56-byte ciphertext from R 1323565.1.017-2018 A.1.
	want := mustHex(t,
		"2ab81deeeb1e4cab68e104c4bd6b94ea"+
			"c72c67af6c2e5b6b0eafb61770f1b32e"+
			"a1ae71149eed1382abd467180672ec6f"+
			"84a2f15b3fca72c1")

	got := make([]byte, len(plain))
	ctracpkm.NewCTRACPKM(newMagma, key, iv, 16).XORKeyStream(got, plain)

	if !bytes.Equal(got, want) {
		t.Fatalf("Magma CTR-ACPKM A.1 (one-shot):\n got  %x\n want %x", got, want)
	}

	// Split-write variant: split at offsets crossing the N=16 section boundary.
	// Splits at 7, 16, 33, 50 cross both intra-block and section boundaries.
	got2 := make([]byte, len(plain))
	s := ctracpkm.NewCTRACPKM(newMagma, key, iv, 16)

	for _, chunk := range [][2]int{{0, 7}, {7, 16}, {16, 33}, {33, 50}, {50, 56}} {
		s.XORKeyStream(got2[chunk[0]:chunk[1]], plain[chunk[0]:chunk[1]])
	}

	if !bytes.Equal(got2, want) {
		t.Fatalf("Magma CTR-ACPKM A.1 (split-write):\n got  %x\n want %x", got2, want)
	}
}

func TestCTRACPKM_Roundtrip_BothCiphers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		newBlock func([]byte) cipher.Block
		ivLen    int
		section  int
	}{
		{"kuznyechik", newKuz, 16, 32},
		{"magma", newMagma, 8, 16},
	}
	key := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	plain := bytes.Repeat([]byte{0x42}, 3*32+16) // > 3 sections.

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			iv := make([]byte, tc.ivLen)
			copy(iv, []byte{0x12, 0x34, 0x56, 0x78})

			ct := make([]byte, len(plain))
			ctracpkm.NewCTRACPKM(tc.newBlock, key, iv, tc.section).XORKeyStream(ct, plain)

			back := make([]byte, len(plain))
			ctracpkm.NewCTRACPKM(tc.newBlock, key, iv, tc.section).XORKeyStream(back, ct)

			if !bytes.Equal(back, plain) {
				t.Fatalf("%s round-trip mismatch", tc.name)
			}

			if bytes.Equal(ct, plain) {
				t.Fatalf("%s ciphertext equals plaintext", tc.name)
			}
		})
	}
}
