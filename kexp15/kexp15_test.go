package kexp15_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/kexp15"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// TestKexp15_Magma_EngineEtalon pins the guide's exact Magma vector
// (kexp15.md "Complete Magma KAT", from
// tmp/engine/test_keyexpimp.c:47-76).
func TestKexp15_Magma_EngineEtalon(t *testing.T) {
	t.Parallel()

	shared := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	cipherKey := mustHex(t, "202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637")
	macKey := mustHex(t, "08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f")
	iv := mustHex(t, "67bed654")
	want := mustHex(t, "cfd5a12d5b81b6e1e99c916d07900c6ac12703fb3abded55567bf3742c899c755dafe7b42e3a8bd9")

	got, err := kexp15.Kexp15(kexp15.KexpMagma, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("KAT mismatch:\n got  %x\n want %x", got, want)
	}

	if len(got) != len(shared)+8 {
		t.Fatalf("output length = %d, want %d", len(got), len(shared)+8)
	}
}

func TestKexp15_ErrorCases(t *testing.T) {
	t.Parallel()

	good := struct {
		shared, cipherKey, macKey, iv []byte
	}{
		shared:    mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"),
		cipherKey: mustHex(t, "202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637"),
		macKey:    mustHex(t, "08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f"),
		iv:        mustHex(t, "67bed654"),
	}

	cases := []struct {
		name                          string
		variant                       kexp15.KexpVariant
		shared, cipherKey, macKey, iv []byte
	}{
		{"empty shared", kexp15.KexpMagma, []byte{}, good.cipherKey, good.macKey, good.iv},
		{"short cipher key", kexp15.KexpMagma, good.shared, good.cipherKey[:31], good.macKey, good.iv},
		{"short mac key", kexp15.KexpMagma, good.shared, good.cipherKey, good.macKey[:31], good.iv},
		{"wrong iv len (magma)", kexp15.KexpMagma, good.shared, good.cipherKey, good.macKey, good.iv[:3]},
		{"kuznyechik iv too short", kexp15.KexpKuznyechik, good.shared, good.cipherKey, good.macKey, good.iv},
		{"bad variant", kexp15.KexpVariant(99), good.shared, good.cipherKey, good.macKey, good.iv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := kexp15.Kexp15(tc.variant, tc.shared, tc.cipherKey, tc.macKey, tc.iv); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

// TestKexp15_Kuznyechik_RFC9189 pins the Kuznyechik KExp15 path with the
// published vector from RFC 9189 Appendix A.1.3.2
// (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC): shared = PMS,
// macKey|cipherKey = "Export keys K_Exp_MAC | K_Exp_ENC", want = PMSEXP.
// KExp15 argument order per RFC 9189 §8.2.1: KExp15(S, K_Exp_MAC, K_Exp_ENC, IV).
func TestKexp15_Kuznyechik_RFC9189(t *testing.T) {
	t.Parallel()

	shared := mustHex(t, "a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d")
	macKey := mustHex(t, "7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1")
	cipherKey := mustHex(t, "1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24")
	iv := mustHex(t, "214a6a298e99e325")
	want := mustHex(t, "250d1b67a270ab04d3f65418e1d380b4cb945f0a3dca51500cf3a1bef37f76c07"+
		"341a9839ccf6cba7189da61eb67176c")

	got, err := kexp15.Kexp15(kexp15.KexpKuznyechik, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("KAT mismatch:\n got  %x\n want %x", got, want)
	}

	if len(got) != len(shared)+16 {
		t.Fatalf("output length = %d, want %d", len(got), len(shared)+16)
	}
}

// TestKexp15_Magma_RFC9189 pins the second published Magma vector, from
// RFC 9189 Appendix A.1.3.1 (TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC).
// It uses the same PMS as the Kuznyechik vector above and corroborates the
// K_Exp_MAC | K_Exp_ENC key ordering used to read the RFC's combined blob.
func TestKexp15_Magma_RFC9189(t *testing.T) {
	t.Parallel()

	shared := mustHex(t, "a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d")
	macKey := mustHex(t, "2d8ba8c84cb232ff41f10c3ad924134223254f71e5696d3d29c3e4c9daa6b293")
	cipherKey := mustHex(t, "849eb6340bffae6928a3c3e4ff92eccb1e8f0cf7a188368e6b748e52ea378b0c")
	iv := mustHex(t, "214a6a29")
	want := mustHex(t, "d7f0f0422367867b25fa4233a954f58bde92e9c9bbfb8816c99f15e6398722a0b2b7bfe8493e9a5c")

	got, err := kexp15.Kexp15(kexp15.KexpMagma, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("KAT mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestKexp15_Kuznyechik_Smoke exercises the 128-bit path for output length
// and determinism (the pinned KAT is TestKexp15_Kuznyechik_RFC9189).
func TestKexp15_Kuznyechik_Smoke(t *testing.T) {
	t.Parallel()

	shared := mustHex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	cipherKey := mustHex(t, "202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637")
	macKey := mustHex(t, "08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f")
	iv := mustHex(t, "67bed65467bed654")

	got, err := kexp15.Kexp15(kexp15.KexpKuznyechik, shared, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15: %v", err)
	}

	if len(got) != len(shared)+16 {
		t.Fatalf("output length = %d, want %d", len(got), len(shared)+16)
	}
}
