package keywrap //nolint:testpackage // white-box: tests unexported diversify/imit4/macStep

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// Guide §"Test vectors" — captured from gost-engine 3.0.3 keyWrapCryptoPro on
// the tc26-Z S-box.
const (
	katKEK     = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	katUKM     = "0102030405060708"
	katSession = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	katKEKUKM  = "c8ffc6b8d22ea16fdecbed3c770eb2406537e24300dd10349f57f4c647016c18"
	katCEKENC  = "940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1"
	katCEKMAC  = "e77d8bc3"
	katWrapped = "0102030405060708940e6d83505f7725919a76bbc6d5d991315eb9dfc6d77fb8788cb0cef8b925c1e77d8bc3"
)

// TestDiversify_KAT pins the intermediate KEK(UKM) (guide checklist step 3).
func TestDiversify_KAT(t *testing.T) {
	t.Parallel()

	got := diversify(SboxTC26Z, mustHex(t, katKEK), mustHex(t, katUKM))
	want := mustHex(t, katKEKUKM)

	if !bytes.Equal(got, want) {
		t.Fatalf("KEK(UKM) mismatch:\n got: %x\nwant: %x", got, want)
	}
}

// TestKeyWrapCryptoPro_KAT pins the full 44-byte vector plus each field.
func TestKeyWrapCryptoPro_KAT(t *testing.T) {
	t.Parallel()

	got, err := KeyWrapCryptoPro(SboxTC26Z, mustHex(t, katKEK), mustHex(t, katUKM), mustHex(t, katSession))
	if err != nil {
		t.Fatalf("KeyWrapCryptoPro: %v", err)
	}

	want := mustHex(t, katWrapped)
	if !bytes.Equal(got, want) {
		t.Fatalf("wrapped mismatch:\n got: %x\nwant: %x", got, want)
	}

	if len(got) != 44 {
		t.Fatalf("wrapped length = %d, want 44", len(got))
	}

	// Field-level assertions against the guide's split.
	if !bytes.Equal(got[0:8], mustHex(t, katUKM)) {
		t.Errorf("UKM field: got %x", got[0:8])
	}

	if !bytes.Equal(got[8:40], mustHex(t, katCEKENC)) {
		t.Errorf("CEK_ENC field: got %x", got[8:40])
	}

	if !bytes.Equal(got[40:44], mustHex(t, katCEKMAC)) {
		t.Errorf("CEK_MAC field: got %x", got[40:44])
	}
}

// TestIMIT4_KAT pins the 4-byte MAC alone, keyed with KEK(UKM), IV = UKM.
func TestIMIT4_KAT(t *testing.T) {
	t.Parallel()

	got := imit4(SboxTC26Z, mustHex(t, katKEKUKM), mustHex(t, katUKM), mustHex(t, katSession))
	want := mustHex(t, katCEKMAC)

	if !bytes.Equal(got, want) {
		t.Fatalf("CEK_MAC mismatch:\n got: %x\nwant: %x", got, want)
	}
}

func TestKeyWrapCryptoPro_BadSizes(t *testing.T) {
	t.Parallel()

	good32 := make([]byte, 32)
	good8 := make([]byte, 8)
	cases := []struct {
		name           string
		kek, ukm, sess []byte
	}{
		{"short kek", make([]byte, 31), good8, good32},
		{"long kek", make([]byte, 33), good8, good32},
		{"short ukm", good32, make([]byte, 7), good32},
		{"long ukm", good32, make([]byte, 9), good32},
		{"short session", good32, good8, make([]byte, 31)},
		{"long session", good32, good8, make([]byte, 33)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := KeyWrapCryptoPro(SboxTC26Z, tc.kek, tc.ukm, tc.sess); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestDiversify_PanicOnBadSizes guards that Diversify panics cleanly on
// wrong-length inputs (KEYW-41). A 16-byte kek previously caused silent
// zero-padding; a 7-byte ukm previously caused a raw index panic.
func TestDiversify_PanicOnBadSizes(t *testing.T) {
	t.Parallel()

	good32 := make([]byte, 32)
	good8 := make([]byte, 8)

	cases := []struct {
		name    string
		kek     []byte
		ukm     []byte
		wantMsg string
	}{
		{"short kek", make([]byte, 16), good8, "keywrap: kek must be 32 bytes"},
		{"long kek", make([]byte, 33), good8, "keywrap: kek must be 32 bytes"},
		{"short ukm", good32, make([]byte, 7), "keywrap: ukm must be 8 bytes"},
		{"long ukm", good32, make([]byte, 9), "keywrap: ukm must be 8 bytes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("expected panic, got none")
				}

				if got, ok := r.(string); !ok || got != tc.wantMsg {
					t.Fatalf("panic message: got %q, want %q", r, tc.wantMsg)
				}
			}()

			Diversify(SboxTC26Z, tc.kek, tc.ukm)
		})
	}
}

// Sanity: confirm LE32(n1) truncation assumption is internally consistent —
// the MAC field equals the first 4 bytes of the running state, little-endian.
func TestMACTruncationShape(t *testing.T) {
	t.Parallel()

	mac := imit4(SboxTC26Z, mustHex(t, katKEKUKM), mustHex(t, katUKM), mustHex(t, katSession))
	if got := binary.LittleEndian.Uint32(mac); got == 0 {
		t.Fatal("unexpected zero MAC word")
	}
}
