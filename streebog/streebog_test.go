package streebog_test

import (
	"bytes"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/bigbes/gostcrypto/streebog"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// decodeHex decodes a compile-time-constant hex string for package-level
// vectors, panicking on a malformed literal (test-author error, not runtime).
func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex literal: " + err.Error())
	}

	return b
}

// carryVector builds the 128-byte carry-propagation stress input from the
// guide: 0xee x64, then 0x16, then 0x11 x62, then 0x16.
func carryVector() []byte {
	b := make([]byte, 0, 128)
	for range 64 {
		b = append(b, 0xee)
	}

	b = append(b, 0x16)
	for range 62 {
		b = append(b, 0x11)
	}

	return append(b, 0x16)
}

var kats = []struct {
	name    string
	in      []byte
	want256 string
	want512 string
}{
	{
		name:    "M1",
		in:      []byte("012345678901234567890123456789012345678901234567890123456789012"),
		want256: "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
		want512: "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa" +
			"00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48",
	},
	{
		name:    "empty",
		in:      nil,
		want256: "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
		want512: "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7" +
			"362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
	},
	{
		// M2 from RFC 6986 §10.2 / GOST R 34.11-2012 §А.2 — the CP1251-encoded
		// "Се ветри, Стрибожи внуци..." message. Bytes and both digests are
		// taken verbatim from gost-engine 3.0.3 test_digest.c:227-256.
		name: "M2",
		in: decodeHex("d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f1" +
			"20eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb"),
		want256: "9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50",
		want512: "1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d9613760" +
			"35fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28",
	},
	{
		name:    "carry128",
		in:      carryVector(),
		want256: "81bb632fa31fcc38b4c379a662dbc58b9bed83f50d3a1b2ce7271ab02d25babb",
		want512: "8b06f41e59907d9636e892caf5942fcdfb71fa31169a5e70f0edb873664df41c" +
			"2cce6e06dc6755d15a61cdeb92bd607cc4aaca6732bf3568a23a210dd520fd41",
	},
}

func TestKAT256(t *testing.T) {
	t.Parallel()

	for _, tc := range kats {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want256)
			got := streebog.Sum256(tc.in)

			if !bytes.Equal(got[:], want) {
				t.Fatalf("Sum256 got %x want %x", got, want)
			}

			h := streebog.New256()
			h.Write(tc.in)

			if d := h.Sum(nil); !bytes.Equal(d, want) {
				t.Fatalf("New256 got %x want %x", d, want)
			}
		})
	}
}

func TestKAT512(t *testing.T) {
	t.Parallel()

	for _, tc := range kats {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			want := mustHex(t, tc.want512)
			got := streebog.Sum512(tc.in)

			if !bytes.Equal(got[:], want) {
				t.Fatalf("Sum512 got %x want %x", got, want)
			}

			h := streebog.New512()
			h.Write(tc.in)

			if d := h.Sum(nil); !bytes.Equal(d, want) {
				t.Fatalf("New512 got %x want %x", d, want)
			}
		})
	}
}

// TestStreaming feeds the M1 message via many small Write calls of varying
// chunk sizes to exercise the partial-block buffering, and checks the digest
// matches the one-shot result.
func TestStreaming(t *testing.T) {
	t.Parallel()

	msg := bytes.Repeat([]byte("The quick brown fox. "), 50) // 1050 bytes, crosses many blocks.

	for _, chunk := range []int{1, 3, 7, 31, 63, 64, 65, 127, 128} {
		t.Run("chunk", func(t *testing.T) {
			t.Parallel()

			for _, mk := range []func() hash.Hash{streebog.New256, streebog.New512} {
				stream := mk()

				for i := 0; i < len(msg); i += chunk {
					end := min(i+chunk, len(msg))

					stream.Write(msg[i:end])
				}

				streamDigest := stream.Sum(nil)

				oneShot := mk()
				oneShot.Write(msg)

				oneShotDigest := oneShot.Sum(nil)

				if !bytes.Equal(streamDigest, oneShotDigest) {
					t.Fatalf("chunk=%d size=%d streaming %x != one-shot %x",
						chunk, stream.Size(), streamDigest, oneShotDigest)
				}
			}
		})
	}
}

// TestSumNonDestructive verifies Sum does not mutate the receiver: you can
// Sum, Write more, Sum again, and get the running-hash result.
func TestSumNonDestructive(t *testing.T) {
	t.Parallel()

	h := streebog.New512()
	h.Write([]byte("abc"))

	d1 := h.Sum(nil)
	d1again := h.Sum(nil)

	if !bytes.Equal(d1, d1again) {
		t.Fatalf("Sum mutated receiver: %x != %x", d1, d1again)
	}

	h.Write([]byte("def"))

	d2 := h.Sum(nil)

	ref := streebog.New512()
	ref.Write([]byte("abcdef"))

	if !bytes.Equal(d2, ref.Sum(nil)) {
		t.Fatalf("post-Sum Write wrong: %x", d2)
	}
}

// TestSizes checks the hash.Hash metadata.
func TestSizes(t *testing.T) {
	t.Parallel()

	if streebog.New256().Size() != 32 || streebog.New256().BlockSize() != 64 {
		t.Fatal("256 size/blocksize wrong")
	}

	if streebog.New512().Size() != 64 || streebog.New512().BlockSize() != 64 {
		t.Fatal("512 size/blocksize wrong")
	}
}
