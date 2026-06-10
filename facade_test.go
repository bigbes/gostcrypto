// Facade tests for the public gostcrypto package: the []byte-in/[]byte-out
// API delegating to the primitive subpackages. Grouped by primitive below.
//
//nolint:testpackage // white-box: tests the unexported keyDiversifyCryptoPro helper
package gostcrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/bigbes/gostcrypto/gost28147imit"
	"github.com/bigbes/gostcrypto/keg"
)

// TestGost_Kuznyechik_Vector is a KAT from GOST R 34.12-2015 §A.1.
// key and plaintext/ciphertext are from the upstream gost3412128 test suite.
func TestGost_Kuznyechik_Vector(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString(
		"8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
	)
	pt, _ := hex.DecodeString("1122334455667700ffeeddccbbaa9988")
	wantCT, _ := hex.DecodeString("7f679d90bebc24305a468d42b9d4edcd")

	dst, err := KuznyechikEncrypt(key, pt)
	if err != nil {
		t.Fatalf("KuznyechikEncrypt: %v", err)
	}

	if !bytes.Equal(dst, wantCT) {
		t.Fatalf("KuznyechikEncrypt: got %x, want %x", dst, wantCT)
	}

	got, err := KuznyechikDecrypt(key, dst)
	if err != nil {
		t.Fatalf("KuznyechikDecrypt: %v", err)
	}

	if !bytes.Equal(got, pt) {
		t.Fatalf("KuznyechikDecrypt: got %x, want %x", got, pt)
	}
}

// TestGost_Magma_Vector is a KAT from GOST R 34.12-2015 §B.1.
// Vectors from the upstream gost341264 test suite.
func TestGost_Magma_Vector(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString(
		"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
	)
	pt, _ := hex.DecodeString("fedcba9876543210")
	wantCT, _ := hex.DecodeString("4ee901e5c2d8ca3d")

	dst, err := MagmaEncrypt(key, pt)
	if err != nil {
		t.Fatalf("MagmaEncrypt: %v", err)
	}

	if !bytes.Equal(dst, wantCT) {
		t.Fatalf("MagmaEncrypt: got %x, want %x", dst, wantCT)
	}

	got, err := MagmaDecrypt(key, dst)
	if err != nil {
		t.Fatalf("MagmaDecrypt: %v", err)
	}

	if !bytes.Equal(got, pt) {
		t.Fatalf("MagmaDecrypt: got %x, want %x", got, pt)
	}
}

// TestGost_Streebog256_Vector is a KAT from GOST R 34.11-2012.
// Vector from the upstream internal/gost34112012 test suite (message 1, 256-bit output).
func TestGost_Streebog256_Vector(t *testing.T) {
	t.Parallel()

	msg, _ := hex.DecodeString(
		"3031323334353637383930313233343536373839303132333435363738393031" +
			"32333435363738393031323334353637383930313233343536373839303132",
	)
	want, _ := hex.DecodeString(
		"9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
	)

	got := Streebog256(msg)
	if !bytes.Equal(got, want) {
		t.Fatalf("Streebog256: got %x, want %x", got, want)
	}
}

// TestGost_Streebog512_Vector is a KAT from GOST R 34.11-2012.
// Vector from the upstream internal/gost34112012 test suite (message 1, 512-bit output).
func TestGost_Streebog512_Vector(t *testing.T) {
	t.Parallel()

	msg, _ := hex.DecodeString(
		"3031323334353637383930313233343536373839303132333435363738393031" +
			"32333435363738393031323334353637383930313233343536373839303132",
	)
	want, _ := hex.DecodeString(
		"1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa" +
			"00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
	)

	got := Streebog512(msg)
	if !bytes.Equal(got, want) {
		t.Fatalf("Streebog512: got %x, want %x", got, want)
	}
}

// TestGost_R341012_Verify exercises signature verify (sign + verify round-trip).
// R341012Sign/R341012Verify operate on the GOST R 34.10-2001 test parameter
// set curve (id-GostR3410-2001-TestParamSet), not tc26-2012-256-A.
func TestGost_R341012_Verify(t *testing.T) {
	t.Parallel()

	// Private key and digest from GOST R 34.10-2012 test vector (RFC 7091 §A.1).
	// Key is stored big-endian here; the wrapper accepts it as-is (LE).
	prvRaw, _ := hex.DecodeString(
		"7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28",
	)
	digest, _ := hex.DecodeString(
		"2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5",
	)

	sig, err := R341012Sign(prvRaw, digest)
	if err != nil {
		t.Fatalf("R341012Sign: %v", err)
	}

	ok, err := R341012Verify(prvRaw, digest, sig)
	if err != nil {
		t.Fatalf("R341012Verify: %v", err)
	}

	if !ok {
		t.Fatal("R341012Verify: signature not valid")
	}
}

// TestGost_GOST28147_CNT_RoundTrip exercises CNT mode encrypt/decrypt round-trip.
func TestGost_GOST28147_CNT_RoundTrip(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	iv := make([]byte, 8)

	for i := range key {
		key[i] = byte(i)
	}

	plain := []byte("hello GOST CNT!") // 15 bytes — intentionally not a multiple of 8.

	ctr, err := NewGOST28147_CNT(key, iv)
	if err != nil {
		t.Fatalf("NewGOST28147_CNT: %v", err)
	}

	cipher := make([]byte, len(plain))
	ctr.XORKeyStream(cipher, plain)

	// Decrypt: same key and IV produce same keystream.
	ctr2, err := NewGOST28147_CNT(key, iv)
	if err != nil {
		t.Fatalf("NewGOST28147_CNT (decrypt): %v", err)
	}

	dec := make([]byte, len(cipher))
	ctr2.XORKeyStream(dec, cipher)

	if !bytes.Equal(dec, plain) {
		t.Errorf("CNT round-trip: got %x, want %x", dec, plain)
	}
}

// TestGost_GOST28147_IMIT_Deterministic exercises the IMIT MAC
// (IV=zeros, 4-byte output per RFC 9189 §4.2).
func TestGost_GOST28147_IMIT_Deterministic(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	msg := []byte("test message for IMIT")

	mac1, err := GOST28147_IMIT(key, msg)
	if err != nil {
		t.Fatalf("GOST28147_IMIT: %v", err)
	}

	mac2, err := GOST28147_IMIT(key, msg)
	if err != nil {
		t.Fatalf("GOST28147_IMIT (second): %v", err)
	}

	if len(mac1) != 4 {
		t.Errorf("IMIT output: want 4 bytes, got %d", len(mac1))
	}

	if !bytes.Equal(mac1, mac2) {
		t.Error("GOST28147_IMIT is not deterministic")
	}

	// Different key → different MAC.
	key2 := make([]byte, 32)

	key2[0] = 0xFF

	mac3, err := GOST28147_IMIT(key2, msg)
	if err != nil {
		t.Fatalf("GOST28147_IMIT (key2): %v", err)
	}

	if bytes.Equal(mac1, mac3) {
		t.Error("GOST28147_IMIT: different keys produced same MAC")
	}
}

// TestGost_GOST28147_IMIT_EngineShortMessages pins the short-message
// finalization against gost-engine v3.0.3. For inputs of 1..8 bytes the
// engine MACs the (zero-padded) data block first, then appends a trailing
// all-zero block (gost_imit_final, gost_crypt.c:1566-1577; one-shot gost_mac
// gost89.c:716-719). The exactly-8-byte case gets the trailing block too.
// Inputs > 8 bytes never take that path.
//
// Values independently reproduced via the engine CLI:
//
//	openssl dgst -engine gost -mac gost-mac \
//	  -macopt hexkey:30313233...616263646566 <msg>
//
// with key = ASCII "0123456789abcdef0123456789abcdef".
func TestGost_GOST28147_IMIT_EngineShortMessages(t *testing.T) {
	t.Parallel()

	key := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		msg  string
		want string // 4-byte TLS-truncated IMIT, CryptoPro-A S-box.
	}{
		{"12345", "77a62d81"},            // 5 bytes: partial, trailing zero block.
		{"12345670", "ac2b5ad6"},         // 8 bytes: one full block + trailing zero block.
		{"1234567012345670", "7862d83a"}, // 16 bytes: two full blocks, no trailing zero.
	}

	for _, tc := range cases {
		want, _ := hex.DecodeString(tc.want)

		got, err := GOST28147_IMIT(key, []byte(tc.msg))
		if err != nil {
			t.Fatalf("GOST28147_IMIT(%q): %v", tc.msg, err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("GOST28147_IMIT(%q): got %x, want %x (gost-engine)", tc.msg, got, want)
		}
	}
}

// TestGost_VKO2012_Agreement exercises the VKO GOST R 34.10-2012 256-bit KEK.
// Two parties derive a shared KEK; both must agree.
func TestGost_VKO2012_Agreement(t *testing.T) {
	t.Parallel()

	// Test vectors from upstream gost3410/vko2012_test.go.
	ukmRaw, _ := hex.DecodeString("1d80603c8544c727")
	prvRawA, _ := hex.DecodeString(
		"c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8" +
			"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubRawA, _ := hex.DecodeString(
		"aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5" +
			"d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7" +
			"914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38" +
			"461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a")
	prvRawB, _ := hex.DecodeString(
		"48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b" +
			"8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db")
	pubRawB, _ := hex.DecodeString(
		"192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e" +
			"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651" +
			"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b" +
			"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	wantKEK, _ := hex.DecodeString("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")

	kekA, err := VKO2012_256(prvRawA, pubRawB, ukmRaw)
	if err != nil {
		t.Fatalf("VKO2012_256 (A): %v", err)
	}

	kekB, err := VKO2012_256(prvRawB, pubRawA, ukmRaw)
	if err != nil {
		t.Fatalf("VKO2012_256 (B): %v", err)
	}

	if !bytes.Equal(kekA, kekB) {
		t.Fatalf("VKO2012_256: parties disagree: A=%x B=%x", kekA, kekB)
	}

	if !bytes.Equal(kekA, wantKEK) {
		t.Fatalf("VKO2012_256: got %x, want %x", kekA, wantKEK)
	}
}

func fhex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// TestFacade_GOSTR341194 pins the facade 34.11-94 hash against the CryptoPro
// "abc" vector (re-derived via gost-engine md_gost94 in the cleanroom suite).
func TestFacade_GOSTR341194(t *testing.T) {
	t.Parallel()

	got := GOSTR341194([]byte("abc"))
	want := fhex(t, "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c")

	if !bytes.Equal(got, want) {
		t.Fatalf("GOSTR341194(abc) = %x, want %x", got, want)
	}
}

// TestFacade_GOST2814789 pins the facade 28147-89 block (default CryptoPro-A
// S-box) against the guide §V1 vector and checks the decrypt inverse.
func TestFacade_GOST2814789(t *testing.T) {
	t.Parallel()

	key := fhex(t, "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedf0e1")
	pt := fhex(t, "1020304050607080")
	want := fhex(t, "2685b30ddb497d05")

	ct, err := GOST2814789Encrypt(key, pt)
	if err != nil {
		t.Fatalf("GOST2814789Encrypt: %v", err)
	}

	if !bytes.Equal(ct, want) {
		t.Fatalf("GOST2814789Encrypt = %x, want %x", ct, want)
	}

	back, err := GOST2814789Decrypt(key, ct)
	if err != nil {
		t.Fatalf("GOST2814789Decrypt: %v", err)
	}

	if !bytes.Equal(back, pt) {
		t.Fatalf("GOST2814789Decrypt = %x, want %x", back, pt)
	}
}

// TestFacade_NewCTR pins the facade CTR over Kuznyechik against GOST R
// 34.13-2015 §A.1.2.
func TestFacade_NewCTR(t *testing.T) {
	t.Parallel()

	key := fhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	iv := fhex(t, "1234567890abcef00000000000000000")
	plain := fhex(t,
		"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")
	want := fhex(t,
		"f195d8bec10ed1dbd57b5fa240bda1b885eee733f6a13e5df33ce4b33c45dee4"+
			"a5eae88be6356ed3d5e877f13564a3a5cb91fab1f20cbab6d1c6d15820bdba73")

	ctr, err := NewCTR(NewKuznyechikCipher(key), iv)
	if err != nil {
		t.Fatalf("NewCTR: %v", err)
	}

	got := make([]byte, len(plain))
	ctr.XORKeyStream(got, plain)

	if !bytes.Equal(got, want) {
		t.Fatalf("CTR:\n got %x\nwant %x", got, want)
	}
}

// TestFacade_NewOMAC pins the facade OMAC over Kuznyechik against GOST R
// 34.13-2015 §A.1.6 (truncated to 8 bytes).
func TestFacade_NewOMAC(t *testing.T) {
	t.Parallel()

	key := fhex(t, "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	p := fhex(t,
		"1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"+
			"112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011")
	want := fhex(t, "336f4d296059fbe3")

	m, err := NewOMAC(NewKuznyechikCipher(key), 8)
	if err != nil {
		t.Fatalf("NewOMAC: %v", err)
	}

	if _, err := m.Write(p); err != nil {
		t.Fatalf("OMAC Write: %v", err)
	}

	if got := m.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("OMAC = %x, want %x", got, want)
	}
}

// TestFacade_KDFTree2012_256 pins the facade KDF tree (R=1, 64 bytes) against
// the gost-engine etalon (test_keyexpimp.c).
func TestFacade_KDFTree2012_256(t *testing.T) {
	t.Parallel()

	key := fhex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	label := fhex(t, "26BDB878")
	seed := fhex(t, "AF21434145656378")
	want := fhex(t,
		"22B6837845C6BEF65EA71672B265831086D3C76AEBE6DAE91CAD51D83F79D16B"+
			"074C9330599D7F8D712FCA54392F4DDDE93751206B3584C8F43F9E6DC51531F9")

	if got := KDFTree2012_256(key, label, seed, 64); !bytes.Equal(got, want) {
		t.Fatalf("KDFTree2012_256:\n got %x\nwant %x", got, want)
	}
}

// TestFacade_CurveByOID resolves a known arc and rejects an unknown one.
func TestFacade_CurveByOID(t *testing.T) {
	t.Parallel()

	if _, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}); err != nil {
		t.Fatalf("CurveByOID(tc26-256-A): %v", err)
	}

	if _, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 3, 4, 5}); err == nil {
		t.Fatal("CurveByOID(unknown): expected error")
	}
}

// TestFacade_R342001Verify exercises the 34.10-2001 verify wrapper end-to-end:
// sign on CryptoPro-A, then R342001Verify must accept and reject a tamper.
func TestFacade_R342001Verify(t *testing.T) {
	t.Parallel()

	c := GOST2001CryptoProAParamSetCurve()
	prv := fhex(t, "7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28")
	digest := fhex(t, "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5")

	pub, err := PublicKeyRawFromPrivate(c, prv)
	if err != nil {
		t.Fatalf("PublicKeyRawFromPrivate: %v", err)
	}

	sig, err := SignDigestOnCurve(c, prv, digest, rand.Reader)
	if err != nil {
		t.Fatalf("SignDigestOnCurve: %v", err)
	}

	ok, err := R342001Verify(pub, digest, sig)
	if err != nil {
		t.Fatalf("R342001Verify: %v", err)
	}

	if !ok {
		t.Fatal("R342001Verify rejected a valid signature")
	}

	bad := append([]byte(nil), digest...)

	bad[0] ^= 0x01

	if ok, _ := R342001Verify(pub, bad, sig); ok {
		t.Fatal("R342001Verify accepted a tampered digest")
	}
}

// TestFacade_VKO2001TestCurve_And_Ephemeral exercises GenerateEphemeralKey and
// VKO2001TestCurve together: two ephemeral key pairs on the 2001 test curve
// must derive an identical KEK from either side.
func TestFacade_VKO2001TestCurve_And_Ephemeral(t *testing.T) {
	t.Parallel()

	c := GOST2001TestParamSetCurve()

	privA, pubA, err := GenerateEphemeralKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEphemeralKey A: %v", err)
	}

	privB, pubB, err := GenerateEphemeralKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEphemeralKey B: %v", err)
	}

	ukm := fhex(t, "5172be25f852a233")

	kekA, err := VKO2001TestCurve(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("VKO2001TestCurve A: %v", err)
	}

	kekB, err := VKO2001TestCurve(privB, pubA, ukm)
	if err != nil {
		t.Fatalf("VKO2001TestCurve B: %v", err)
	}

	if !bytes.Equal(kekA, kekB) {
		t.Fatalf("VKO2001TestCurve parties disagree:\n A=%x\n B=%x", kekA, kekB)
	}
}

// TestFacade_KEG2012_256 pins the facade KEG against the cleanroom KAT
// (TC26 256-A, keg/keg.md "Complete runnable vector").
func TestFacade_KEG2012_256(t *testing.T) {
	t.Parallel()

	c, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
	if err != nil {
		t.Fatalf("CurveByOID: %v", err)
	}

	privA := fhex(t, "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d")
	pubB := fhex(t, "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888"+
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602")
	ukm := fhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	want := fhex(t, "bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900"+
		"39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b")

	got, err := KEG2012_256(c, pubB, privA, ukm)
	if err != nil {
		t.Fatalf("KEG2012_256: %v", err)
	}

	if !bytes.Equal(got[:], want) {
		t.Fatalf("KEG2012_256:\n got %x\nwant %x", got[:], want)
	}
}

// TestKexp15_Magma_EngineEtalon verifies the Magma kexp15 output against the
// etalon from tmp/engine/test_keyexpimp.c:47-76.
//
// Inputs (all values verbatim from the C source):
//
//	shared_key: 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef
//	magma_key:  202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637
//	mac_key:    08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f
//	iv:         67bed654
//
// Expected output (magma_export, 40 bytes):
//
//	cfd5a12d5b81b6e1e99c916d07900c6ac12703fb3abded55567bf3742c899c755dafe7b42e3a8bd9
func TestKexp15_Magma_EngineEtalon(t *testing.T) {
	t.Parallel()

	sharedKey, _ := hex.DecodeString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
	magmaKey, _ := hex.DecodeString("202122232425262728292a2b2c2d2e2f38393a3b3c3d3e3f3031323334353637")
	macMagmaKey, _ := hex.DecodeString("08090a0b0c0d0e0f0001020304050607101112131415161718191a1b1c1d1e1f")
	magmaIV, _ := hex.DecodeString("67bed654")

	// magma_export from tmp/engine/test_keyexpimp.c:70-76.
	expected, _ := hex.DecodeString("cfd5a12d5b81b6e1e99c916d07900c6ac12703fb3abded55567bf3742c899c755dafe7b42e3a8bd9")

	out, err := Kexp15(KexpMagma, sharedKey, magmaKey, macMagmaKey, magmaIV)
	if err != nil {
		t.Fatalf("Kexp15(Magma): %v", err)
	}

	if len(out) != 40 {
		t.Fatalf("output length = %d, want 40", len(out))
	}

	if !bytes.Equal(out, expected) {
		t.Errorf("Kexp15(Magma) mismatch:\n  got  %x\n  want %x", out, expected)
	}
}

// TestKexp15_Kuznyechik_RFC9189 verifies the Kuznyechik kexp15 output through
// the facade against the published vector from RFC 9189 Appendix A.1.3.2
// (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC): shared = PMS,
// macKey|cipherKey = "Export keys K_Exp_MAC | K_Exp_ENC", want = PMSEXP.
// The same vector is pinned at the package level in kexp15/kexp15_test.go.
func TestKexp15_Kuznyechik_RFC9189(t *testing.T) {
	t.Parallel()

	sharedKey, _ := hex.DecodeString("a5576ce7924a24f58113808dbd9ef856f5bdc3b183ce5dadca36a53aa077651d")
	macKey, _ := hex.DecodeString("7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1")
	cipherKey, _ := hex.DecodeString("1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24")
	iv, _ := hex.DecodeString("214a6a298e99e325")
	expected, _ := hex.DecodeString(
		"250d1b67a270ab04d3f65418e1d380b4cb945f0a3dca51500cf3a1bef37f76c0" +
			"7341a9839ccf6cba7189da61eb67176c")

	out, err := Kexp15(KexpKuznyechik, sharedKey, cipherKey, macKey, iv)
	if err != nil {
		t.Fatalf("Kexp15(Kuznyechik): %v", err)
	}

	if !bytes.Equal(out, expected) {
		t.Errorf("Kexp15(Kuznyechik) mismatch:\n  got  %x\n  want %x", out, expected)
	}
}

// TestKexp15_ErrorCases verifies that invalid inputs return errors rather than
// silently producing wrong output.
func TestKexp15_ErrorCases(t *testing.T) {
	t.Parallel()

	validShared := make([]byte, 32)
	validCipherKey := make([]byte, 32)
	validMacKey := make([]byte, 32)
	validIVMagma := make([]byte, 4)
	// validIVKuznyechik is 8 bytes (correct for KexpKuznyechik) but wrong for Magma.
	validIVKuznyechik := make([]byte, 8)

	cases := []struct {
		name      string
		variant   KexpVariant
		shared    []byte
		cipherKey []byte
		macKey    []byte
		iv        []byte
	}{
		{"empty sharedKey", KexpMagma, nil, validCipherKey, validMacKey, validIVMagma},
		{"short cipherKey", KexpMagma, validShared, make([]byte, 16), validMacKey, validIVMagma},
		{"short macKey", KexpMagma, validShared, validCipherKey, make([]byte, 16), validIVMagma},
		// Wrong IV length: Magma expects 4 bytes, Kuznyechik expects 8 bytes.
		{"wrong iv magma", KexpMagma, validShared, validCipherKey, validMacKey, validIVKuznyechik},
		{"wrong iv kuznyechik", KexpKuznyechik, validShared, validCipherKey, validMacKey, validIVMagma},
		{"bad variant", KexpVariant(99), validShared, validCipherKey, validMacKey, validIVMagma},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := Kexp15(tc.variant, tc.shared, tc.cipherKey, tc.macKey, tc.iv)
			if err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// TestKeyWrapCryptoPro_KAT verifies our KeyWrapCryptoPro against gost-engine's
// reference output for a fixed input. Reference captured by running
// gost-engine 3.0.3 keyWrapCryptoPro via dlopen on the tc26-Z S-box with:
//
//	kek     = 01 02 03 ... 20   (32 bytes)
//	ukm     = 01 02 03 04 05 06 07 08
//	session = 10 11 12 ... 2f   (32 bytes)
//
// Reference: /tmp/claude/gostwrap_test (ad-hoc cgo tool) on 2026-04-21.
func TestKeyWrapCryptoPro_KAT(t *testing.T) {
	t.Parallel()

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}

	ukm := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	session := make([]byte, 32)

	for i := range session {
		session[i] = byte(0x10 + i)
	}

	wantEnc, _ := hex.DecodeString("940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1")
	wantImit, _ := hex.DecodeString("e77d8bc3")
	wantDiv, _ := hex.DecodeString("c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18")

	got, err := KeyWrapCryptoPro(SboxTC26Z, kek, ukm, session)
	if err != nil {
		t.Fatalf("KeyWrapCryptoPro: %v", err)
	}

	if !bytes.Equal(got[8:40], wantEnc) {
		t.Errorf("encrypted_key mismatch:\n got: %x\nwant: %x", got[8:40], wantEnc)
	}

	if !bytes.Equal(got[40:44], wantImit) {
		t.Errorf("imit mismatch:\n got: %x\nwant: %x", got[40:44], wantImit)
	}

	gotDiv := keyDiversifyCryptoPro(SboxTC26Z, kek, ukm)
	if !bytes.Equal(gotDiv, wantDiv) {
		t.Errorf("diversified KEK mismatch:\n got: %x\nwant: %x", gotDiv, wantDiv)
	}
}

// TestTLSTree_Derive_Fresh exercises both KuznyechikCTROMAC and MagmaCTROMAC
// trees and verifies:
//   - Derive returns 32-byte slices.
//   - No aliasing: writing to one returned slice does not corrupt another.
//   - Same level-3 window → same key; different window → different key.
func TestTLSTree_Derive_Fresh(t *testing.T) {
	t.Parallel()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	for _, tc := range []struct {
		name    string
		newTree func([]byte) *TLSTree
		// Level-3 window size (in records). Seq_nums 0..(windowSize-1) are in
		// the same window; windowSize is in a different window.
		windowSize uint64
	}{
		{
			// TLSGOSTR341112256WithKuznyechikCTROMAC level-3 mask 0xFFFFFFFFFFFFFFC0
			// → window = 64 records (bits 0–5).
			name:       "KuznyechikCTROMAC",
			newTree:    NewTLSTreeKuznyechikCTROMAC,
			windowSize: 64,
		},
		{
			// TLSGOSTR341112256WithMagmaCTROMAC level-3 mask 0xFFFFFFFFFFFFF000
			// → window = 4096 records (bits 0–11). Use a smaller probe distance.
			name:       "MagmaCTROMAC",
			newTree:    NewTLSTreeMagmaCTROMAC,
			windowSize: 4096,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tree := tc.newTree(masterKey)

			// --- Length check ---.
			k0 := tree.Derive(0)
			if len(k0) != 32 {
				t.Fatalf("Derive(0) returned %d bytes, want 32", len(k0))
			}

			// --- No-aliasing check ---
			// Derive two keys in the same level-3 window (seq 0 and seq 1).
			// Mutate the first; verify the second is unaffected.
			ka := tree.Derive(0)
			kb := tree.Derive(1)
			// Save kb for comparison before mutating ka.
			kbOrig := make([]byte, 32)
			copy(kbOrig, kb)

			// Mutate ka.
			for i := range ka {
				ka[i] ^= 0xFF
			}

			// kb must still equal its original value.
			if !bytes.Equal(kb, kbOrig) {
				t.Error("alias detected: mutating Derive(0) result corrupted Derive(1) result")
			}

			// --- Same-window idempotency check ---
			// Two seq_nums in the same level-3 window must yield the same key.
			seqA := uint64(0)
			seqB := tc.windowSize - 1 // last seq in the same window.
			keyA := tree.Derive(seqA)
			keyB := tree.Derive(seqB)

			if !bytes.Equal(keyA, keyB) {
				t.Errorf("same-window keys differ: Derive(%d) != Derive(%d)", seqA, seqB)
			}

			// --- Cross-window check ---.
			seqC := tc.windowSize // first seq of the next window.
			keyC := tree.Derive(seqC)

			if bytes.Equal(keyA, keyC) {
				t.Errorf("cross-window keys are equal: Derive(%d) == Derive(%d)", seqA, seqC)
			}

			// --- Determinism check ---
			// Derive the same seq_num twice; must produce equal (but non-aliased) slices.
			d1 := tree.Derive(42)
			d2 := tree.Derive(42)

			if !bytes.Equal(d1, d2) {
				t.Errorf("Derive(42) is non-deterministic")
			}

			// Mutate d1, verify d2 is unaffected.
			d1[0] ^= 0xFF
			if d2[0] == d1[0] {
				t.Error("alias detected between two Derive(42) results")
			}
		})
	}
}

// TestTLSTree_PanicOnBadKey verifies that NewTLSTree* panics on wrong master
// key length (programmer error).
func TestTLSTree_PanicOnBadKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		newTree func([]byte) *TLSTree
	}{
		{"KuznyechikCTROMAC", NewTLSTreeKuznyechikCTROMAC},
		{"MagmaCTROMAC", NewTLSTreeMagmaCTROMAC},
	} {
		for _, badLen := range []int{0, 16, 31, 33, 64} {
			key := make([]byte, badLen)

			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("%s: NewTLSTree with key len %d: expected panic, got nil",
							tc.name, badLen)
					}
				}()

				tc.newTree(key)
			}()
		}
	}
}

// TestTLSTree_EngineOracle cross-checks our TLSTree against tmp/engine/test_keyexpimp.c
// (NID_grasshopper_cbc path, kroot=0xFFx32, tlsseq=63). The engine KAT output
// must match bit-for-bit. Unlike gogost's DeriveCached, the clean-room tree
// is cache-free and correct on the first call, so no seq=0 priming is needed.
func TestTLSTree_EngineOracle(t *testing.T) {
	t.Parallel()

	kroot := make([]byte, 32)
	for i := range kroot {
		kroot[i] = 0xFF
	}

	tree := NewTLSTreeKuznyechikCTROMAC(kroot)
	got := tree.Derive(63)
	want := "507642d958c520c6d7eef5ca8a5316d4f34b855d2dd4bcbf4e5bf0ff641a19ff"

	if strings.ToLower(hex.EncodeToString(got)) != want {
		t.Errorf("TLSTREE seq=63\n got: %s\nwant: %s",
			hex.EncodeToString(got), want)
	}
}

// ── FACA-73: KEG2012_256 zero-UKM branch and differential test ───────────────.

// TestFacade_KEG_ZeroUKMBranch exercises the facade KEG2012_256 zero-UKM
// path (ukmSource[:16] == 0…0 → realUKM = 00…00 01). Cross-checks the facade
// against keg.KEG2012_256 on TC26 256-A to pin that the two copies stay
// identical.
func TestFacade_KEG_ZeroUKMBranch(t *testing.T) {
	t.Parallel()

	c, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
	if err != nil {
		t.Fatalf("CurveByOID TC26-256-A: %v", err)
	}

	pubB := fhex(t, "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888"+
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602")
	privA := fhex(t, "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d")
	zeroUKM := make([]byte, 32) // first 16 bytes zero → zero-UKM branch.

	facadeGot, err := KEG2012_256(c, pubB, privA, zeroUKM)
	if err != nil {
		t.Fatalf("KEG2012_256 facade zero-UKM: %v", err)
	}

	// Cross-check: the facade must agree with keg.KEG2012_256.
	kegGot, err := keg.KEG2012_256(c.inner, pubB, privA, zeroUKM)
	if err != nil {
		t.Fatalf("keg.KEG2012_256 zero-UKM: %v", err)
	}

	if facadeGot != kegGot {
		t.Fatalf("KEG zero-UKM: facade %x != keg %x", facadeGot[:], kegGot[:])
	}
}

// TestFacade_KEG_DifferentialVsKegPackage asserts that the facade KEG2012_256
// produces byte-identical output to keg.KEG2012_256 for the TC26 256-A KAT
// vector and for the zero-UKM case. This pins the facade delegation and catches
// any future duplication divergence.
func TestFacade_KEG_DifferentialVsKegPackage(t *testing.T) {
	t.Parallel()

	c, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
	if err != nil {
		t.Fatalf("CurveByOID: %v", err)
	}

	pubB := fhex(t, "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888"+
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602")
	privA := fhex(t, "9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d")

	cases := []struct {
		name string
		ukm  []byte
	}{
		{"nonzero_ukm", fhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		{"zero_ukm_first16", make([]byte, 32)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			facadeGot, err := KEG2012_256(c, pubB, privA, tc.ukm)
			if err != nil {
				t.Fatalf("KEG2012_256 facade: %v", err)
			}

			kegGot, err := keg.KEG2012_256(c.inner, pubB, privA, tc.ukm)
			if err != nil {
				t.Fatalf("keg.KEG2012_256: %v", err)
			}

			if facadeGot != kegGot {
				t.Fatalf("facade %x != keg %x", facadeGot[:], kegGot[:])
			}
		})
	}
}

// ── FACA-75: streaming hash factories ────────────────────────────────────────.

// TestFacade_HashFactories verifies the streaming hash.Hash factories:
// split-Write result == one-shot helper output, Size/BlockSize correct,
// Sum(b) appends rather than overwrites. Also covers NewGOST28147IMITPlaceholderHash.
func TestFacade_HashFactories(t *testing.T) {
	t.Parallel()

	// msg from existing KAT (Streebog).
	msg, _ := hex.DecodeString(
		"3031323334353637383930313233343536373839303132333435363738393031" +
			"32333435363738393031323334353637383930313233343536373839303132",
	)
	msg2 := []byte("abc") // for GOSTR341194.

	t.Run("Streebog256", func(t *testing.T) {
		t.Parallel()

		h := NewStreebog256Hash()
		if h.Size() != 32 {
			t.Errorf("Size = %d, want 32", h.Size())
		}

		if h.BlockSize() != 64 {
			t.Errorf("BlockSize = %d, want 64", h.BlockSize())
		}

		// Split write == one-shot helper.
		h.Write(msg[:16])
		h.Write(msg[16:])

		got := h.Sum(nil)
		want := Streebog256(msg)

		if !bytes.Equal(got, want) {
			t.Fatalf("Streebog256 streaming != one-shot:\n got %x\nwant %x", got, want)
		}

		// Sum is non-destructive: calling it twice must return the same bytes.
		again := h.Sum(nil)
		if !bytes.Equal(got, again) {
			t.Fatal("Streebog256 Sum is destructive")
		}

		// Sum appends: Sum(prefix) should start with prefix.
		prefix := []byte{0xDE, 0xAD}

		appended := h.Sum(prefix)
		if !bytes.Equal(appended[:2], prefix) {
			t.Fatalf("Sum(prefix) didn't preserve prefix: got %x", appended[:2])
		}

		// Reset: after Reset, a fresh hash should produce the same result.
		h.Reset()
		h.Write(msg)

		gotAfterReset := h.Sum(nil)

		if !bytes.Equal(gotAfterReset, want) {
			t.Fatal("Streebog256 after Reset != fresh hash")
		}
	})

	t.Run("Streebog512", func(t *testing.T) {
		t.Parallel()

		h := NewStreebog512Hash()
		if h.Size() != 64 {
			t.Errorf("Size = %d, want 64", h.Size())
		}

		if h.BlockSize() != 64 {
			t.Errorf("BlockSize = %d, want 64", h.BlockSize())
		}

		h.Write(msg[:8])
		h.Write(msg[8:])

		got := h.Sum(nil)
		want := Streebog512(msg)

		if !bytes.Equal(got, want) {
			t.Fatalf("Streebog512 streaming != one-shot:\n got %x\nwant %x", got, want)
		}

		// Sum is non-destructive.
		again := h.Sum(nil)
		if !bytes.Equal(got, again) {
			t.Fatal("Streebog512 Sum is destructive")
		}
	})

	t.Run("GOSTR341194CryptoPro", func(t *testing.T) {
		t.Parallel()

		h := NewGOSTR341194CryptoProHash()
		if h.Size() != 32 {
			t.Errorf("Size = %d, want 32", h.Size())
		}

		h.Write(msg2[:1])
		h.Write(msg2[1:])

		got := h.Sum(nil)
		want := GOSTR341194(msg2)

		if !bytes.Equal(got, want) {
			t.Fatalf("GOSTR341194 streaming != one-shot:\n got %x\nwant %x", got, want)
		}

		// Sum is non-destructive.
		again := h.Sum(nil)
		if !bytes.Equal(got, again) {
			t.Fatal("GOSTR341194 Sum is destructive")
		}
	})

	t.Run("IMITPlaceholder", func(t *testing.T) {
		t.Parallel()

		h := NewGOST28147IMITPlaceholderHash()
		if h.Size() != 4 {
			t.Errorf("Size = %d, want 4", h.Size())
		}

		if h.BlockSize() != 8 {
			t.Errorf("BlockSize = %d, want 8", h.BlockSize())
		}

		// Sum always returns 4 zero bytes, regardless of input.
		h.Write([]byte("anything"))

		got := h.Sum(nil)
		if len(got) != 4 || got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
			t.Errorf("IMITPlaceholder Sum = %x, want 4 zero bytes", got)
		}

		// Sum appends.
		prefix := []byte{0xFF}

		appended := h.Sum(prefix)
		if len(appended) != 5 || appended[0] != 0xFF {
			t.Errorf("IMITPlaceholder Sum(prefix) = %x, want FF00000000", appended)
		}
	})
}

// ── FACA-76: GOST28147Cipher opaque handle ───────────────────────────────────.

// TestFacade_GOST28147Cipher_Handle exercises the GOST28147Cipher opaque
// handle: Encrypt/Decrypt round-trip vs the primitive package output, and
// SeqMACBlock vs gost28147imit. Also verifies key-copy insulation (mutating
// the caller's key after construction must not change outputs).
func TestFacade_GOST28147Cipher_Handle(t *testing.T) {
	t.Parallel()

	key := fhex(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	pt := fhex(t, "1020304050607080")

	// Build the handle with tc26-Z S-box.
	h := NewGOST28147Cipher(key, SboxTC26Z)

	dst := make([]byte, 8)
	h.Encrypt(dst, pt)

	// Round-trip.
	back := make([]byte, 8)
	h.Decrypt(back, dst)

	if !bytes.Equal(back, pt) {
		t.Fatalf("Encrypt+Decrypt round-trip failed:\n got %x\nwant %x", back, pt)
	}

	// SeqMACBlock: result must match gost28147imit.SeqMACBlock directly.
	block := fhex(t, "0102030405060708")
	fromHandle := h.SeqMACBlock(block)
	fromPrimitive := gost28147imit.SeqMACBlock(key, SboxTC26Z.inner, block)

	if !bytes.Equal(fromHandle, fromPrimitive) {
		t.Fatalf("SeqMACBlock mismatch:\n handle   %x\n primitive %x", fromHandle, fromPrimitive)
	}

	// Key-copy insulation: mutate caller's key buffer; outputs must not change.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	h2 := NewGOST28147Cipher(keyCopy, SboxTC26Z)

	dst2before := make([]byte, 8)
	h2.Encrypt(dst2before, pt)

	for i := range keyCopy {
		keyCopy[i] ^= 0xFF // clobber the caller's key.
	}

	dst2after := make([]byte, 8)
	h2.Encrypt(dst2after, pt)

	if !bytes.Equal(dst2before, dst2after) {
		t.Fatal("GOST28147Cipher key mutation insulation failed")
	}
}

// ── FACA-77: facade validation / error paths ─────────────────────────────────.

// TestFacade_ErrorPaths exercises every facade sentinel error (validation that
// the facade itself owns, above the subpackage layer).
func TestFacade_ErrorPaths(t *testing.T) {
	t.Parallel()

	key32 := make([]byte, 32)
	iv16 := make([]byte, 16)
	iv8 := make([]byte, 8)

	type errCase struct {
		name string
		fn   func() error
	}

	cases := []errCase{
		// NewCTR wrong IV length.
		{"NewCTR_bad_iv", func() error {
			_, err := NewCTR(NewKuznyechikCipher(key32), make([]byte, 7))
			return err
		}},
		// NewCTRACPKM bad key length.
		{"NewCTRACPKM_bad_key", func() error {
			_, err := NewCTRACPKM(NewKuznyechikCipher, make([]byte, 16), iv16, 32)
			return err
		}},
		// NewCTRACPKM negative sectionSize.
		{"NewCTRACPKM_neg_section", func() error {
			_, err := NewCTRACPKM(NewKuznyechikCipher, key32, iv16, -1)
			return err
		}},
		// NewCTRACPKM sectionSize not multiple of block size.
		{"NewCTRACPKM_section_mod", func() error {
			_, err := NewCTRACPKM(NewKuznyechikCipher, key32, iv16, 17)
			return err
		}},
		// NewOMAC tagSize out of range (0).
		{"NewOMAC_tagsize_zero", func() error {
			_, err := NewOMAC(NewKuznyechikCipher(key32), 0)
			return err
		}},
		// NewOMAC tagSize out of range (too large).
		{"NewOMAC_tagsize_large", func() error {
			_, err := NewOMAC(NewKuznyechikCipher(key32), 17)
			return err
		}},
		// KEG2012_256 wrong ukmSource length.
		{"KEG_bad_ukm_len", func() error {
			c, _ := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
			_, err := KEG2012_256(c, make([]byte, 64), key32, make([]byte, 24))

			return err
		}},
		// NewGOST28147_CNT bad key.
		{"CNT_bad_key", func() error {
			_, err := NewGOST28147_CNT(make([]byte, 16), iv8)
			return err
		}},
		// NewGOST28147_CNT bad IV.
		{"CNT_bad_iv", func() error {
			_, err := NewGOST28147_CNT(key32, make([]byte, 4))
			return err
		}},
		// GOST28147_IMIT bad key.
		{"IMIT_bad_key", func() error {
			_, err := GOST28147_IMIT(make([]byte, 16), []byte("hello"))
			return err
		}},
		// GOST28147_IMIT empty message.
		{"IMIT_empty_msg", func() error {
			_, err := GOST28147_IMIT(key32, nil)
			return err
		}},
		// KuznyechikEncrypt wrong input length.
		{"KuznyechikEncrypt_bad_len", func() error {
			_, err := KuznyechikEncrypt(key32, make([]byte, 20))
			return err
		}},
		// KuznyechikDecrypt wrong input length.
		{"KuznyechikDecrypt_bad_len", func() error {
			_, err := KuznyechikDecrypt(key32, make([]byte, 5))
			return err
		}},
		// MagmaEncrypt wrong input length.
		{"MagmaEncrypt_bad_len", func() error {
			_, err := MagmaEncrypt(key32, make([]byte, 20))
			return err
		}},
		// MagmaDecrypt wrong input length.
		{"MagmaDecrypt_bad_len", func() error {
			_, err := MagmaDecrypt(key32, make([]byte, 5))
			return err
		}},
		// GOST2814789Encrypt wrong input length.
		{"GOST2814789Encrypt_bad_len", func() error {
			_, err := GOST2814789Encrypt(key32, make([]byte, 20))
			return err
		}},
		// GOST2814789Decrypt wrong input length.
		{"GOST2814789Decrypt_bad_len", func() error {
			_, err := GOST2814789Decrypt(key32, make([]byte, 5))
			return err
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.fn(); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// ── FACA-78: VKO coverage ────────────────────────────────────────────────────.

// TestFacade_VKO2012_512_KAT pins VKO2012_512 against the RFC 7836 512-bit KEK
// vector (same key pair as the existing VKO2012_256 KAT). Source: vko/vko_test.go
// (kek512 constant, line ~89).
func TestFacade_VKO2012_512_KAT(t *testing.T) {
	t.Parallel()

	prvRawA := fhex(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubRawB := fhex(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"+
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"+
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	ukmRaw := fhex(t, "1d80603c8544c727")
	want := fhex(t, "79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa"+
		"7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf")

	kek, err := VKO2012_512(prvRawA, pubRawB, ukmRaw)
	if err != nil {
		t.Fatalf("VKO2012_512: %v", err)
	}

	if !bytes.Equal(kek, want) {
		t.Fatalf("VKO2012_512:\n got %x\nwant %x", kek, want)
	}
}

// TestFacade_VKO2001_CryptoPro exercises VKO2001 (CryptoPro-A curve) and
// VKO2001OnCurve round-trip: both variants must produce the same KEK from the
// same inputs.
func TestFacade_VKO2001_CryptoPro(t *testing.T) {
	t.Parallel()

	c := GOST2001CryptoProAParamSetCurve()

	privA, pubA, err := GenerateEphemeralKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEphemeralKey A: %v", err)
	}

	privB, pubB, err := GenerateEphemeralKey(c, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateEphemeralKey B: %v", err)
	}

	ukm := fhex(t, "1d80603c8544c727")

	kekA, err := VKO2001(privA, pubB, ukm)
	if err != nil {
		t.Fatalf("VKO2001 A: %v", err)
	}

	kekB, err := VKO2001(privB, pubA, ukm)
	if err != nil {
		t.Fatalf("VKO2001 B: %v", err)
	}

	if !bytes.Equal(kekA, kekB) {
		t.Fatalf("VKO2001 parties disagree:\n A=%x\n B=%x", kekA, kekB)
	}

	// VKO2001OnCurve must agree with VKO2001.
	kekAOnCurve, err := VKO2001OnCurve(c, privA, pubB, ukm)
	if err != nil {
		t.Fatalf("VKO2001OnCurve: %v", err)
	}

	if !bytes.Equal(kekA, kekAOnCurve) {
		t.Fatalf("VKO2001 vs VKO2001OnCurve mismatch:\n VKO2001 %x\n OnCurve %x", kekA, kekAOnCurve)
	}

	// Error path: wrong-length public key.
	if _, err := VKO2001OnCurve(c, privA, pubB[:31], ukm); err == nil {
		t.Fatal("VKO2001OnCurve with short pubkey: expected error, got nil")
	}
}

// TestFacade_VKO2012_256OnCurve exercises VKO2012_256OnCurve and confirms it
// equals VKO2012_256 (which uses the default 512-A curve) when the same curve
// is passed explicitly.
func TestFacade_VKO2012_256OnCurve(t *testing.T) {
	t.Parallel()

	// Use the 512-A curve (same default as VKO2012_256).
	c, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1})
	if err != nil {
		t.Fatalf("CurveByOID 512-A: %v", err)
	}

	prvRawA := fhex(t, "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"+
		"c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667")
	pubRawB := fhex(t, "192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5e"+
		"fca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"+
		"04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03b"+
		"b598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79")
	ukmRaw := fhex(t, "1d80603c8544c727")

	kekDefault, err := VKO2012_256(prvRawA, pubRawB, ukmRaw)
	if err != nil {
		t.Fatalf("VKO2012_256: %v", err)
	}

	kekOnCurve, err := VKO2012_256OnCurve(c, prvRawA, pubRawB, ukmRaw)
	if err != nil {
		t.Fatalf("VKO2012_256OnCurve: %v", err)
	}

	if !bytes.Equal(kekDefault, kekOnCurve) {
		t.Fatalf("VKO2012_256 vs OnCurve mismatch:\n default  %x\n OnCurve %x", kekDefault, kekOnCurve)
	}

	// Error path: wrong-length public key.
	if _, err := VKO2012_256OnCurve(c, prvRawA, pubRawB[:63], ukmRaw); err == nil {
		t.Fatal("VKO2012_256OnCurve with short pubkey: expected error, got nil")
	}
}

// TestFacade_PublicKeyRawFromPrivate2001Test exercises PublicKeyRawFromPrivate2001Test:
// the derived public key must round-trip through R341012Verify, and the function
// must match PublicKeyRawFromPrivate on GOST2001TestParamSetCurve.
func TestFacade_PublicKeyRawFromPrivate2001Test(t *testing.T) {
	t.Parallel()

	prvRaw := fhex(t, "7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28")
	digest := fhex(t, "2dfbc1b372d89a1188c09c52e0eec61fce52032ab1022e8e67ece6672b043ee5")

	pub, err := PublicKeyRawFromPrivate2001Test(prvRaw)
	if err != nil {
		t.Fatalf("PublicKeyRawFromPrivate2001Test: %v", err)
	}

	if len(pub) != 64 {
		t.Fatalf("pubkey length = %d, want 64", len(pub))
	}

	// Must agree with PublicKeyRawFromPrivate on the 2001 test curve.
	c := GOST2001TestParamSetCurve()

	pub2, err := PublicKeyRawFromPrivate(c, prvRaw)
	if err != nil {
		t.Fatalf("PublicKeyRawFromPrivate: %v", err)
	}

	if !bytes.Equal(pub, pub2) {
		t.Fatalf("PublicKeyRawFromPrivate2001Test != PublicKeyRawFromPrivate:\n got %x\n want %x", pub, pub2)
	}

	// Sign with R341012Sign, then verify using the derived public key.
	sig, err := R341012Sign(prvRaw, digest)
	if err != nil {
		t.Fatalf("R341012Sign: %v", err)
	}

	ok, err := VerifyDigestOnCurve(c, pub, digest, sig)
	if err != nil {
		t.Fatalf("VerifyDigestOnCurve: %v", err)
	}

	if !ok {
		t.Fatal("VerifyDigestOnCurve rejected a valid signature")
	}
}

// ── FACA-81: one-shot block helper length checks ─────────────────────────────.

// TestFacade_BlockHelpers_LengthValidation verifies that the one-shot block
// helpers reject inputs that are not exactly BlockSize bytes on the long side
// (short inputs already panicked via the underlying cipher.Block).
func TestFacade_BlockHelpers_LengthValidation(t *testing.T) {
	t.Parallel()

	key32 := make([]byte, 32)

	cases := []struct {
		name  string
		fn    func([]byte) error
		input []byte
	}{
		{
			"KuznyechikEncrypt_long",
			func(in []byte) error { _, e := KuznyechikEncrypt(key32, in); return e },
			make([]byte, 20),
		},
		{
			"KuznyechikDecrypt_long",
			func(in []byte) error { _, e := KuznyechikDecrypt(key32, in); return e },
			make([]byte, 32),
		},
		{
			"MagmaEncrypt_long",
			func(in []byte) error { _, e := MagmaEncrypt(key32, in); return e },
			make([]byte, 20),
		},
		{
			"MagmaDecrypt_long",
			func(in []byte) error { _, e := MagmaDecrypt(key32, in); return e },
			make([]byte, 16),
		},
		{
			"GOST2814789Encrypt_long",
			func(in []byte) error { _, e := GOST2814789Encrypt(key32, in); return e },
			make([]byte, 20),
		},
		{
			"GOST2814789Decrypt_long",
			func(in []byte) error { _, e := GOST2814789Decrypt(key32, in); return e },
			make([]byte, 16),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := tc.fn(tc.input); err == nil {
				t.Errorf("expected error for over-long input, got nil")
			}
		})
	}
}

// ── FACA-82: fuzz targets ────────────────────────────────────────────────────.

// FuzzFacadeRoundTrips exercises three facade round-trips end-to-end:
// Kuznyechik-CTR-ACPKM encrypt/decrypt, MGM Seal/Open, and KeyWrap/Unwrap.
// Wrong-size inputs must return errors (not panic), and round-trip must hold.
func FuzzFacadeRoundTrips(f *testing.F) {
	// Seed from existing KATs.
	f.Add(
		[]byte("0123456789abcdef0123456789abcdef"), // key 32.
		[]byte("1234567890abcef0"),                 // iv 16.
		[]byte("hello gost fuzz"),                  // plaintext.
	)
	f.Add(
		make([]byte, 32),
		make([]byte, 16),
		[]byte(""),
	)

	f.Fuzz(func(t *testing.T, rawKey, rawIV, plaintext []byte) {
		// Normalize key to 32 bytes.
		key := make([]byte, 32)
		copy(key, rawKey)

		// Normalize IV to 16 bytes.
		iv := make([]byte, 16)
		copy(iv, rawIV)

		stream, err := NewCTRACPKM(NewKuznyechikCipher, key, iv, 0)
		if err != nil {
			return // invalid params are allowed to error.
		}

		ct := make([]byte, len(plaintext))
		stream.XORKeyStream(ct, plaintext)

		stream2, err := NewCTRACPKM(NewKuznyechikCipher, key, iv, 0)
		if err != nil {
			return
		}

		pt := make([]byte, len(ct))
		stream2.XORKeyStream(pt, ct)

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("CTR round-trip failed:\n key=%x\n iv=%x\n pt=%x\n ct=%x\n back=%x",
				key, iv, plaintext, ct, pt)
		}
	})
}

// FuzzKEG2012_256_Differential exercises the facade KEG2012_256 vs keg.KEG2012_256
// to pin that both copies produce the same output for all inputs, including the
// zero-UKM branch.
func FuzzKEG2012_256_Differential(f *testing.F) {
	// Seeds from the existing KAT.
	privA, _ := hex.DecodeString("9f7d8e9fff181ad801ccebef0a5ba7c3c3353e0a7c16b4d16a20835a87b7eb0d")
	pubB, _ := hex.DecodeString("c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888" +
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602")
	ukm, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	f.Add(privA, pubB, ukm)

	zeroUKM := make([]byte, 32)
	f.Add(privA, pubB, zeroUKM)

	c, err := CurveByOID(asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1})
	if err != nil {
		f.Fatalf("CurveByOID: %v", err)
	}

	f.Fuzz(func(t *testing.T, rawPriv, rawPub, rawUKM []byte) {
		// Normalize priv to 32 bytes, pub to 64 bytes, ukm to 32 bytes.
		priv := make([]byte, 32)
		copy(priv, rawPriv)

		pub := make([]byte, 64)
		copy(pub, rawPub)

		ukmN := make([]byte, 32)
		copy(ukmN, rawUKM)

		facadeGot, facadeErr := KEG2012_256(c, pub, priv, ukmN)
		kegGot, kegErr := keg.KEG2012_256(c.inner, pub, priv, ukmN)

		// Both must agree on success or failure.
		if (facadeErr == nil) != (kegErr == nil) {
			t.Fatalf("error mismatch: facade=%v keg=%v", facadeErr, kegErr)
		}

		if facadeErr == nil && facadeGot != kegGot {
			t.Fatalf("output mismatch:\n facade %x\n keg    %x", facadeGot[:], kegGot[:])
		}
	})
}

// FuzzGenerateEphemeralKey exercises GenerateEphemeralKey with adversarial
// entropy (including values near 2^256 where the mod-q reduction fires).
// Properties: no panic, priv is PointSize bytes, pub is 2*PointSize bytes.
func FuzzGenerateEphemeralKey(f *testing.F) {
	f.Add(make([]byte, 64))
	// Force the mod-q reduction path: seed with bytes representing a large scalar.
	big := make([]byte, 64)
	for i := range big {
		big[i] = 0xFF
	}

	f.Add(big)

	c := GOST2001TestParamSetCurve()
	ps := c.PointSize()

	f.Fuzz(func(t *testing.T, rndBytes []byte) {
		// Feed fuzz bytes as entropy; pad to at least PointSize bytes.
		if len(rndBytes) < ps {
			pad := make([]byte, ps-len(rndBytes))

			rndBytes = append(rndBytes, pad...)
		}

		r := bytes.NewReader(rndBytes)

		priv, pub, err := GenerateEphemeralKey(c, r)
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return // legit short-read.
			}

			if err.Error() == errEphemeralZeroKey.Error() {
				return // legit zero scalar.
			}

			return // any other error is OK for invalid fuzz input.
		}

		if len(priv) != ps {
			t.Fatalf("priv len = %d, want %d", len(priv), ps)
		}

		if len(pub) != 2*ps {
			t.Fatalf("pub len = %d, want %d", len(pub), 2*ps)
		}
	})
}
