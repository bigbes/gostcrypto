package tlstree //nolint:testpackage // white-box: tests unexported kdf/labelLevel1

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

// TestKAT_MultiSeq pins window-crossing TLSTree leaves for both cipher suites
// against gost-engine 3.0.3's gost_tlstree(): kuznyechik-cbc (NID 1015) and
// magma-cbc (NID 1190), K_root = 32×0xFF. These seqs straddle the level-3 and
// level-2 window boundaries, where the per-suite TLSTREE constants (RFC 9367)
// differ — so they exercise key paths the seq=63 leaf (level seeds all zero)
// cannot. Re-derived via dlopen(gost.dylib)+gost_tlstree.
func TestKAT_MultiSeq(t *testing.T) {
	t.Parallel()

	kFF := bytes.Repeat([]byte{0xFF}, 32)

	kuz := []struct {
		seq  uint64
		want string
	}{
		{64, "c19b639f4bea788c1c59b4c887db5b07c19119101868dab89a8d9361b2f010f3"},
		{1024, "f818bf12ada4bff50ea28686decc9b1294ec945608df3afe353f73a82b321e0a"},
		{65535, "45900412294e1b94e9d14928852f95307d5c6d3a00e154f1c3378705d7d32893"},
		{65536, "ed269cd321d716af69ddad3b87c841d6ff4fa9c0baaec4a77e8ab158f825addb"},
		{16777216, "e94a0214d0e1db8716c2d3f82546b98b6a4e58644e949382da191ac9e4c7ad4e"},
		{4398046511104, "2bb03cf1a17aff32210ba44e57415acf73e8746e635039559cd767e6c682ecf5"},
	}
	mag := []struct {
		seq  uint64
		want string
	}{
		{64, "507642d958c520c6d7eef5ca8a5316d4f34b855d2dd4bcbf4e5bf0ff641a19ff"},
		{1024, "507642d958c520c6d7eef5ca8a5316d4f34b855d2dd4bcbf4e5bf0ff641a19ff"},
		{65535, "2dbcc0382629d7dd29772844e8233f443b3d31aa0178527e6b8729aa7bb0c09b"},
		{65536, "ed269cd321d716af69ddad3b87c841d6ff4fa9c0baaec4a77e8ab158f825addb"},
		{16777216, "730a28f66a423ce6b979347c209ea0c1a86ae4cc36e364b15ea4e927b30a78ac"},
		{4398046511104, "2bb03cf1a17aff32210ba44e57415acf73e8746e635039559cd767e6c682ecf5"},
	}

	for _, tc := range kuz {
		got := NewTLSTreeKuznyechikCTROMAC(kFF).Derive(tc.seq)
		if !bytes.Equal(got, mustHex(t, tc.want)) {
			t.Fatalf("Kuznyechik Derive(%d):\n got %x\nwant %s", tc.seq, got, tc.want)
		}
	}

	for _, tc := range mag {
		got := NewTLSTreeMagmaCTROMAC(kFF).Derive(tc.seq)
		if !bytes.Equal(got, mustHex(t, tc.want)) {
			t.Fatalf("Magma Derive(%d):\n got %x\nwant %s", tc.seq, got, tc.want)
		}
	}
}

// TestKAT_Kuznyechik_Seq63 pins the guide's inline Kuznyechik KAT
// (tlstree.md "Inline KAT"): K_root = 32×0xFF, i = 63 ⇒
// 507642d9...641a19ff. Critically, this is a *first* call on a fresh tree —
// the clean-room impl must NOT carry gogost's D2 zero-key trap.
func TestKAT_Kuznyechik_Seq63(t *testing.T) {
	t.Parallel()

	kFF := bytes.Repeat([]byte{0xFF}, 32)
	want := mustHex(t, "507642d958c520c6d7eef5ca8a5316d4f34b855d2dd4bcbf4e5bf0ff641a19ff")

	got := NewTLSTreeKuznyechikCTROMAC(kFF).Derive(63)
	if !bytes.Equal(got, want) {
		t.Fatalf("Derive(63) on fresh tree:\n got %x\nwant %x", got, want)
	}
}

// TestKAT_FirstCallNotZero guards specifically against the D2 startup trap: a
// fresh Derive(63) must not return 32 zero bytes.
func TestKAT_FirstCallNotZero(t *testing.T) {
	t.Parallel()

	kFF := bytes.Repeat([]byte{0xFF}, 32)
	got := NewTLSTreeKuznyechikCTROMAC(kFF).Derive(63)

	if bytes.Equal(got, make([]byte, KeySize)) {
		t.Fatal("fresh Derive(63) returned all-zero key (D2 trap reproduced)")
	}
}

// TestKDF_Level1_K1 pins the intermediate K1 from the re-implementation
// checklist step 2: K = 32×0xFF, label="level1", seed = 8×0x00. We derive K1
// independently here and assert it is deterministic and non-zero; the exact
// value is implicitly validated by the seq63 leaf KAT above (K1→K2→K3 chain).
func TestKDF_Single_Deterministic(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xFF}, 32)
	seed := make([]byte, 8)
	a := kdf(key, labelLevel1, seed)
	b := kdf(key, labelLevel1, seed)

	if a != b {
		t.Fatal("kdf not deterministic")
	}

	if a == ([KeySize]byte{}) {
		t.Fatal("kdf returned all-zero")
	}
}

// TestSeedSerialization covers D1/step 4: STR_8(i & C_n) is big-endian 8 bytes
// of the masked uint64.
func TestSeedSerialization(t *testing.T) {
	t.Parallel()

	const c3 = uint64(0xFFFFFFFFFFFFFFC0)

	var seed [8]byte

	// i=63 < 64 (window) ⇒ 63 & C_3 == 0 ⇒ 8 zero bytes.
	binary.BigEndian.PutUint64(seed[:], 63&c3)

	if !bytes.Equal(seed[:], make([]byte, 8)) {
		t.Fatalf("i=63 seed = %x, want 8 zero bytes", seed)
	}

	// i=64 ⇒ 64 & C_3 == 64 ⇒ 00 00 00 00 00 00 00 40.
	binary.BigEndian.PutUint64(seed[:], 64&c3)

	want := mustHex(t, "0000000000000040")
	if !bytes.Equal(seed[:], want) {
		t.Fatalf("i=64 seed = %x, want %x", seed, want)
	}
}

// TestWindowing covers the leaf-window invariant (step 6 / D2): same window ⇒
// identical key, crossing it ⇒ different key. 64 records for Kuznyechik, 4096
// for Magma.
func TestWindowing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		newFn  func([]byte) *TLSTree
		window uint64
	}{
		{"kuznyechik", NewTLSTreeKuznyechikCTROMAC, 64},
		{"magma", NewTLSTreeMagmaCTROMAC, 4096},
	}
	master := bytes.Repeat([]byte{0x11}, 32)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			k0 := tc.newFn(master).Derive(0)
			kIn := tc.newFn(master).Derive(tc.window - 1)
			kOut := tc.newFn(master).Derive(tc.window)

			if !bytes.Equal(k0, kIn) {
				t.Fatalf("intra-window key changed: Derive(0)=%x Derive(%d)=%x", k0, tc.window-1, kIn)
			}

			if bytes.Equal(k0, kOut) {
				t.Fatalf("cross-window key unchanged at boundary %d: %x", tc.window, kOut)
			}
		})
	}
}

// TestDeriveNonAliasing covers D3: each Derive returns an independent buffer.
func TestDeriveNonAliasing(t *testing.T) {
	t.Parallel()

	tr := NewTLSTreeKuznyechikCTROMAC(bytes.Repeat([]byte{0xAB}, 32))
	a := tr.Derive(63)
	cp := append([]byte(nil), a...)
	b := tr.Derive(63)
	// Mutating b must not change a.
	for i := range b {
		b[i] ^= 0xFF
	}

	if !bytes.Equal(a, cp) {
		t.Fatal("Derive results alias a shared buffer")
	}

	if len(a) != KeySize {
		t.Fatalf("len = %d, want %d", len(a), KeySize)
	}
}

// TestDeterminism: repeated Derive of the same seq yields equal keys.
func TestDeterminism(t *testing.T) {
	t.Parallel()

	tr := NewTLSTreeMagmaCTROMAC(bytes.Repeat([]byte{0x5A}, 32))
	if !bytes.Equal(tr.Derive(100000), tr.Derive(100000)) {
		t.Fatal("Derive not deterministic across calls")
	}
}

// TestMasterKeyLength: non-32-byte master keys panic.
func TestMasterKeyLength(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, 16, 31, 33, 64} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("len=%d did not panic", n)
				}
			}()

			NewTLSTreeKuznyechikCTROMAC(make([]byte, n))
		}()
	}
}
