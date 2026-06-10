package tlstree //nolint:testpackage // white-box: shares kdf/labelLevel* with tlstree_test.go

// TestRFC9189_A1_1_Magma and TestRFC9189_A1_1_Kuznyechik pin the official
// TLSTREE test vectors from RFC 9189 Appendix A.1.1, exactly as printed in
// tlstree/rfc/rfc9189.txt.  They assert K1 ("Divers_1"), K2 ("Divers_2"), and
// the final K3 ("resulting key") for each of the 7 published seqnums per suite.
//
// Both suites share the same root key:
//
//	00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A
//	11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00
//
// (rfc9189.txt:1568–1570 for Magma; rfc9189.txt:1667–1669 for Kuznyechik)
//
// Anti-footgun: every expected byte string below is transcribed verbatim from
// the bundled RFC text — NOT computed from the implementation.  Each cite
// comment gives the exact line(s) in tlstree/rfc/rfc9189.txt.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// rfc9189KRoot is the 32-byte root key used in Appendix A.1.1.
// Source: rfc9189.txt:1568–1570 (Magma) / rfc9189.txt:1667–1669 (Kuznyechik).
var rfc9189KRoot = []byte{ //nolint:gochecknoglobals // test fixture, not a production global
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00,
}

// str8 serializes v as big-endian 8 bytes (STR_8 in RFC 9189 §8.1).
func str8(v uint64) []byte {
	var b [8]byte

	binary.BigEndian.PutUint64(b[:], v)

	return b[:]
}

// rfcVec is one row of RFC 9189 Appendix A.1.1 (one seqnum, three derived keys).
// Hex strings use RFC-formatted space-separated pairs; stripHexSpaces decodes them.
type rfcVec struct {
	seqnum uint64
	k1hex  string // First-level key from Divers_1 (K1).
	k2hex  string // Second-level key from Divers_2 (K2).
	k3hex  string // The resulting key from Divers_3 (K3).
}

// TestRFC9189_A1_1_Magma pins the seven Magma TLSTREE vectors from
// RFC 9189 Appendix A.1.1.1 (rfc9189.txt:1564–1661).
func TestRFC9189_A1_1_Magma(t *testing.T) {
	t.Parallel()

	// Magma suite constants (RFC 9189 §8.1.1).
	const c1, c2 = uint64(magmaC1), uint64(magmaC2)

	// All seven seqnum entries from rfc9189.txt:1564–1661.
	vectors := []rfcVec{
		{
			// rfc9189.txt:1572 seqnum=0; K1:1573–1575 K2:1577–1579 K3:1581–1583.
			seqnum: 0,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "19 A7 6E D3 0F 4D 6D 1F 5B 72 63 EC 49 1A D8 38 17 C0 B5 7D 8A 03 56 12 71 40 FB 4F 74 25 49 4D",
		},
		{
			// rfc9189.txt:1585 seqnum=4095; K1:1586–1588 K2:1590–1592 K3:1594–1596.
			seqnum: 4095,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "19 A7 6E D3 0F 4D 6D 1F 5B 72 63 EC 49 1A D8 38 17 C0 B5 7D 8A 03 56 12 71 40 FB 4F 74 25 49 4D",
		},
		{
			// rfc9189.txt:1598 seqnum=4096; K1:1599–1601 K2:1603–1605 K3:1607–1609.
			seqnum: 4096,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			//nolint:dupword // "CF CF" is verbatim from rfc9189.txt:1608 — both bytes are the GOST-derived value CF.
			k3hex: "FB 30 EE 53 CF CF 89 D7 48 FC 0C 72 EF 16 0B 8B 53 CB BB FD 03 12 82 B0 26 21 4A B2 E0 77 58 FF",
		},
		{
			// rfc9189.txt:1611 seqnum=33554431; K1:1612–1614 K2:1616–1618 K3:1620–1622.
			seqnum: 33554431,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "B8 5B 36 DC 22 82 32 6B C0 35 C5 72 DC 93 F1 8D 83 AA 01 74 F3 94 20 9A 51 3B B3 74 DC 09 35 AE",
		},
		{
			// rfc9189.txt:1624 seqnum=33554432; K1:1625–1627 K2:1629–1631 K3:1633–1635.
			seqnum: 33554432,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "3F EA 59 38 DA 2B F8 DD C4 7E C1 DC 55 61 89 66 79 02 BE 42 0D F4 C3 7D AF 21 75 3B CB 1D C7 F3",
			k3hex:  "0F D7 C0 9E FD F8 E8 15 73 EE CC F8 6E 4B 95 E3 AF 7F 34 DA B1 17 7C FD 7D B9 7B 6D A9 06 40 8A",
		},
		{
			// rfc9189.txt:1637 seqnum=274877906943; K1:1638–1640 K2:1642–1644 K3:1646–1648.
			seqnum: 274877906943,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "AB F3 A5 37 98 3A 1B 98 40 06 6D E6 8A 49 BF 25 97 7E E5 C3 F5 2D 33 3E 3C 22 0F 1D 15 C5 08 93",
			k3hex:  "48 0F 99 72 BA F2 5D 4C 36 9A 96 AF 91 BC A4 55 3F 79 D8 F0 C5 61 8B 19 FD 44 CF DC 57 FA 37 33",
		},
		{
			// rfc9189.txt:1650 seqnum=274877906944; K1:1651–1653 K2:1655–1657 K3:1659–1661.
			seqnum: 274877906944,
			k1hex:  "15 60 0D 9E 8F A6 85 54 CF 15 2D C7 4F BC 42 51 17 B0 3E 09 76 BB 28 EA 98 24 C3 B7 0F 28 CB D8",
			k2hex:  "6C C2 8E B0 93 24 72 12 5C 7A D3 F8 09 73 B3 C8 C4 13 7D A5 73 BC 17 1A 24 ED D4 A3 71 F1 F8 73",
			k3hex:  "25 28 C1 C6 A8 F0 92 7B F2 BE 27 BB 78 D2 7F 21 46 D6 55 93 B0 C7 17 3A 06 CB 9D 88 DF 92 32 65",
		},
	}

	runRFCVectors(t, vectors, c1, c2, NewTLSTreeMagmaCTROMAC, "Magma")
}

// TestRFC9189_A1_1_Kuznyechik pins the seven Kuznyechik TLSTREE vectors from
// RFC 9189 Appendix A.1.1.2 (rfc9189.txt:1663–1760).
func TestRFC9189_A1_1_Kuznyechik(t *testing.T) {
	t.Parallel()

	// Kuznyechik suite constants (RFC 9189 §8.1.1).
	const c1, c2 = uint64(kuznyechikC1), uint64(kuznyechikC2)

	// All seven seqnum entries from rfc9189.txt:1663–1760.
	vectors := []rfcVec{
		{
			// rfc9189.txt:1671 seqnum=0; K1:1672–1674 K2:1676–1678 K3:1680–1682.
			seqnum: 0,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "19 A7 6E D3 0F 4D 6D 1F 5B 72 63 EC 49 1A D8 38 17 C0 B5 7D 8A 03 56 12 71 40 FB 4F 74 25 49 4D",
		},
		{
			// rfc9189.txt:1684 seqnum=63; K1:1685–1687 K2:1689–1691 K3:1693–1695.
			seqnum: 63,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "19 A7 6E D3 0F 4D 6D 1F 5B 72 63 EC 49 1A D8 38 17 C0 B5 7D 8A 03 56 12 71 40 FB 4F 74 25 49 4D",
		},
		{
			// rfc9189.txt:1697 seqnum=64; K1:1698–1700 K2:1702–1704 K3:1706–1708.
			seqnum: 64,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "AE BE 1E F4 18 71 3B F0 44 B9 FC D9 E5 72 D4 37 FB 38 B5 D8 29 56 7A 6F 79 18 39 6D 9F 4E 09 6B",
		},
		{
			// rfc9189.txt:1710 seqnum=524287; K1:1711–1713 K2:1715–1717 K3:1719–1721.
			seqnum: 524287,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "51 37 D5 C4 A6 E6 BE 42 C4 40 D1 0A 95 EE A0 7F 08 9E 74 0D 38 90 EB 52 65 2C 0C B9 3F 20 7B B4",
			k3hex:  "6F 18 D4 00 3E A2 CB 30 F5 FE C1 93 A2 34 F0 7D 7C 43 94 98 7F 50 75 8D E2 2B 22 0D 8A 10 51 06",
		},
		{
			// rfc9189.txt:1723 seqnum=524288; K1:1724–1726 K2:1728–1730 K3:1732–1734.
			seqnum: 524288,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "F6 59 EB 85 EE BD 2A 8D CC 1B B3 F7 C6 00 57 FF 6D 33 B6 0F 74 65 DD 42 B5 11 2C F3 A6 B1 AB 66",
			k3hex:  "E5 4B 16 41 5B 3B 66 3E 78 0B 06 2D 24 F7 36 C4 49 54 63 C3 A8 91 E1 FA 46 F7 AE 99 FF F9 F3 78",
		},
		{
			// rfc9189.txt:1736 seqnum=4294967295; K1:1737–1739 K2:1741–1743 K3:1745–1747.
			seqnum: 4294967295,
			k1hex:  "F3 55 89 F0 9B F8 01 B1 CA 11 42 73 B9 5F D6 C1 39 2E 78 F9 FB 81 4D A0 5A 7C CA 08 9E C8 65 42",
			k2hex:  "F4 BC 10 1A BB 68 86 2A 8C E3 1E A0 0D DF A7 FE B8 29 10 F1 24 F4 B1 E2 9E A8 3B E0 06 C2 26 8D",
			k3hex:  "CF 60 09 04 C7 1E 7B 88 A4 9A C8 E2 45 77 4B 3D BE ED FB 81 DE 9A 0E 2F 4E 46 C3 56 07 BC 2F 04",
		},
		{
			// rfc9189.txt:1749 seqnum=4294967296; K1:1750–1752 K2:1754–1756 K3:1758–1760.
			seqnum: 4294967296,
			k1hex:  "55 CC 95 E0 D1 FB 54 85 AF 8E F6 9A CD 72 B2 32 79 7C D2 E8 5D 86 CD FD 1D E5 5B D1 FA 14 37 78",
			k2hex:  "72 16 91 E1 01 C4 28 96 A6 40 AE 18 3F BB 44 5B 76 37 9C 57 E1 FD 8A 7D 49 A6 23 E4 23 8C 0E 1D",
			k3hex:  "16 18 0B 24 64 54 00 B8 36 14 38 37 D8 6A AC 93 95 2A E3 EB 82 44 D5 EC 2A B0 2C FF 30 78 11 38",
		},
	}

	runRFCVectors(t, vectors, c1, c2, NewTLSTreeKuznyechikCTROMAC, "Kuznyechik")
}

// runRFCVectors drives Appendix A.1.1 KAT verification for one suite.
// It checks K1 (Divers_1) and K2 (Divers_2) via the white-box kdf function,
// and K3 (Divers_3 / "resulting key") via the public Derive method.
func runRFCVectors(
	t *testing.T,
	vectors []rfcVec,
	c1, c2 uint64,
	newFn func([]byte) *TLSTree,
	suiteName string,
) {
	t.Helper()

	for _, tc := range vectors {
		t.Run(suiteName+"_seqnum_"+itoa(tc.seqnum), func(t *testing.T) {
			t.Parallel()

			wantK1 := mustHex(t, stripHexSpaces(tc.k1hex))
			wantK2 := mustHex(t, stripHexSpaces(tc.k2hex))
			wantK3 := mustHex(t, stripHexSpaces(tc.k3hex))

			// K1 = kdf(K_root, "level1", STR_8(seqnum & C_1)).
			gotK1 := kdf(rfc9189KRoot, labelLevel1, str8(tc.seqnum&c1))
			if !bytes.Equal(gotK1[:], wantK1) {
				t.Fatalf("%s seqnum=%d K1 (Divers_1):\n got %x\nwant %x",
					suiteName, tc.seqnum, gotK1, wantK1)
			}

			// K2 = kdf(K1, "level2", STR_8(seqnum & C_2)).
			gotK2 := kdf(gotK1[:], labelLevel2, str8(tc.seqnum&c2))
			if !bytes.Equal(gotK2[:], wantK2) {
				t.Fatalf("%s seqnum=%d K2 (Divers_2):\n got %x\nwant %x",
					suiteName, tc.seqnum, gotK2, wantK2)
			}

			// K3 is the full Derive result (via the public API).
			gotK3 := newFn(rfc9189KRoot).Derive(tc.seqnum)
			if !bytes.Equal(gotK3, wantK3) {
				t.Fatalf("%s seqnum=%d K3 (resulting key):\n got %x\nwant %x",
					suiteName, tc.seqnum, gotK3, wantK3)
			}
		})
	}
}

// stripHexSpaces removes ASCII spaces from a hex string so RFC-formatted
// "AA BB CC …" literals can be decoded with hex.DecodeString.
func stripHexSpaces(s string) string {
	out := make([]byte, 0, len(s))

	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}

	return string(out)
}

// itoa renders a uint64 as a decimal string for subtest names.
// Avoids importing strconv to keep the test file zero-dep.
func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}

	buf := [20]byte{}
	pos := len(buf)

	for n > 0 {
		pos--

		buf[pos] = byte('0' + n%10)

		n /= 10
	}

	return string(buf[pos:])
}

// FuzzTLSTree is the C2 fuzz target for TLSTREE key derivation.
//
// Properties checked on every (keyBytes, seqNum) corpus entry / mutant:
//
//  1. Determinism: two independent NewTLSTree{Suite}(master).Derive(seqNum)
//     calls with the same inputs return byte-equal keys.
//  2. Output length: always exactly KeySize (32) bytes.
//  3. Level-window boundary safety: Derive must not panic for seqNums at, just
//     before, and just after the C_3 window edges (window-1, window, window+1).
//  4. Intra-window invariant: if seqNum and its neighbor seqNum^1 share the same
//     C_3-masked window, their derived keys must be equal.
func FuzzTLSTree(f *testing.F) {
	// Seed corpus: all RFC 9189 Appendix A.1.1 seqnums for both suites.
	for _, seq := range []uint64{
		0, 63, 64,
		4095, 4096,
		524287, 524288,
		4294967295, 4294967296,
		33554431, 33554432,
		274877906943, 274877906944,
	} {
		f.Add(rfc9189KRoot, seq)
	}

	// All-0xFF root key (used by the gost-engine KAT in tlstree_test.go).
	ffKey := bytes.Repeat([]byte{0xFF}, 32)

	for _, seq := range []uint64{0, 63, 64, 1<<32 - 1, 1 << 32} {
		f.Add(ffKey, seq)
	}

	// Explicit Kuznyechik C_3 window boundaries (window = 64 records).
	for _, floor := range []uint64{0, 64, 128, 256, 512, 1 << 19, 1<<32 - 64, 1 << 32} {
		f.Add(ffKey, floor)

		if floor > 0 {
			f.Add(ffKey, floor-1)
		}

		f.Add(ffKey, floor+63)
	}

	// Explicit Magma C_3 window boundaries (window = 4096 records).
	for _, floor := range []uint64{0, 4096, 8192, 1 << 25, 1<<32 - 4096, 1 << 32} {
		f.Add(ffKey, floor)

		if floor > 0 {
			f.Add(ffKey, floor-1)
		}

		f.Add(ffKey, floor+4095)
	}

	f.Fuzz(func(t *testing.T, keyBytes []byte, seqNum uint64) {
		// Normalize fuzz-supplied key to exactly 32 bytes (pad with zeros or truncate).
		var master [KeySize]byte
		copy(master[:], keyBytes)

		// Properties 1 & 2: determinism and fixed output length.

		kuzA := NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(seqNum)
		kuzB := NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(seqNum)

		if !bytes.Equal(kuzA, kuzB) {
			t.Fatalf("Kuznyechik: non-deterministic output for seqNum=%d", seqNum)
		}

		if len(kuzA) != KeySize {
			t.Fatalf("Kuznyechik: output len=%d, want %d", len(kuzA), KeySize)
		}

		magA := NewTLSTreeMagmaCTROMAC(master[:]).Derive(seqNum)
		magB := NewTLSTreeMagmaCTROMAC(master[:]).Derive(seqNum)

		if !bytes.Equal(magA, magB) {
			t.Fatalf("Magma: non-deterministic output for seqNum=%d", seqNum)
		}

		if len(magA) != KeySize {
			t.Fatalf("Magma: output len=%d, want %d", len(magA), KeySize)
		}

		// Property 3: no panic at level-window boundary neighbours.

		// Kuznyechik window = 64 records (C_3 low 6 bits vary).
		kuzFloor := seqNum &^ uint64(63)

		if kuzFloor > 0 {
			NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(kuzFloor - 1)
		}

		NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(kuzFloor)
		NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(kuzFloor + 63)

		if kuzFloor <= ^uint64(0)-64 {
			NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(kuzFloor + 64)
		}

		// Magma window = 4096 records (C_3 low 12 bits vary).
		magFloor := seqNum &^ uint64(4095)

		if magFloor > 0 {
			NewTLSTreeMagmaCTROMAC(master[:]).Derive(magFloor - 1)
		}

		NewTLSTreeMagmaCTROMAC(master[:]).Derive(magFloor)
		NewTLSTreeMagmaCTROMAC(master[:]).Derive(magFloor + 4095)

		if magFloor <= ^uint64(0)-4096 {
			NewTLSTreeMagmaCTROMAC(master[:]).Derive(magFloor + 4096)
		}

		// Property 4: intra-window invariant (seqNum vs seqNum ^ 1).

		neighbor := seqNum ^ 1

		if (seqNum & uint64(kuznyechikC3)) == (neighbor & uint64(kuznyechikC3)) {
			kuzN := NewTLSTreeKuznyechikCTROMAC(master[:]).Derive(neighbor)

			if !bytes.Equal(kuzA, kuzN) {
				t.Fatalf("Kuznyechik: intra-window keys differ for seqNum=%d vs seqNum^1=%d",
					seqNum, neighbor)
			}
		}

		if (seqNum & uint64(magmaC3)) == (neighbor & uint64(magmaC3)) {
			magN := NewTLSTreeMagmaCTROMAC(master[:]).Derive(neighbor)

			if !bytes.Equal(magA, magN) {
				t.Fatalf("Magma: intra-window keys differ for seqNum=%d vs seqNum^1=%d",
					seqNum, neighbor)
			}
		}
	})
}
