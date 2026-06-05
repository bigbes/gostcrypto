package gostr341194_test

import (
	"encoding/hex"
	"testing"

	"github.com/bigbes/gostcrypto/gostr341194"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}

	return b
}

// KATs from gostr341194.md "Test vectors".
//
// NOTE on the empty-input vector: gogost and gost-engine DISAGREE (guide D1).
// This clean-room implementation matches the gost-engine / Tarantool value
// (3f25bc1f...), NOT the gogost value (981e5f3c...), because Tarantool interop
// requires the engine's extra zero-block compression step for empty input.
func TestConformance(t *testing.T) {
	t.Parallel()

	const u128 = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" +
		"UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"

	cases := []struct {
		name, in, want string
	}{
		{"a", "a", "e74c52dd282183bf37af0079c9f78055715a103f17e3133ceff1aacf2f403011"},
		{"abc", "abc", "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c"},
		// EMPTY: gost-engine / Tarantool value (NOT gogost's 981e5f3c...).
		{"empty", "", "3f25bc1fbbce27ca10fb1958f319473ae7e17482c3b53ecf47a7e2de8aabe4c8"},
		// Extended string set, re-derived against gost-engine 3.0.3
		//   OPENSSL_CONF=.../gost-engine.cnf openssl dgst -md_gost94 -r
		// (CryptoPro S-box, id-GostR3411-94-CryptoProParamSet). These match the
		// canonical CryptoPro GOST R 34.11-94 published test vectors.
		{
			"message digest", "message digest",
			"bc6041dd2aa401ebfa6e9886734174febdb4729aa972d60f549ac39b29721ba0",
		},
		{"128*U", u128, "e791faa11d4ab35ffcdb5246db8fe4c3d6802e9eef52be9405c11b69bce108b4"},
		{
			"lazy dog", "The quick brown fox jumps over the lazy dog",
			"9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76",
		},
		// lazy cog: one-letter change from lazy dog — avalanche check.
		{
			"lazy cog", "The quick brown fox jumps over the lazy cog",
			"a93124f5bf2c6d83c3bbf722bc55569310245ca5957541f4dbd7dfaf8137e6f2",
		},
		{
			"length=32", "This is message, length=32 bytes",
			"2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb",
		},
		{
			"length=50", "Suppose the original message has length = 50 bytes",
			"c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_ = mustHex(t, tc.want) // validate hex literal.

			got := gostr341194.Sum([]byte(tc.in))

			if hex.EncodeToString(got[:]) != tc.want {
				t.Fatalf("Sum(%q) = %x, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestStreamingMatchesOneShot verifies that writing the message in odd-sized
// chunks via the hash.Hash interface yields the same digest as Sum, exercising
// the buffering path across block boundaries.
func TestStreamingMatchesOneShot(t *testing.T) {
	t.Parallel()

	msg := make([]byte, 200)
	for i := range msg {
		msg[i] = byte(i * 7)
	}

	want := gostr341194.Sum(msg)

	for _, chunk := range []int{1, 3, 7, 31, 32, 33, 64, 199} {
		h := gostr341194.New()

		for off := 0; off < len(msg); off += chunk {
			end := min(off+chunk, len(msg))

			h.Write(msg[off:end])
		}

		got := h.Sum(nil)
		if hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
			t.Fatalf("chunk=%d: streaming %x != one-shot %x", chunk, got, want)
		}
	}
}

// TestSumNonDestructive verifies Sum may be followed by more Write (guide D8).
func TestSumNonDestructive(t *testing.T) {
	t.Parallel()

	h := gostr341194.New()
	h.Write([]byte("ab"))

	_ = h.Sum(nil) // must not mutate state.
	h.Write([]byte("c"))

	got := h.Sum(nil)
	want := "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c"

	if hex.EncodeToString(got) != want {
		t.Fatalf("after non-destructive Sum: got %x want %s", got, want)
	}
}

func TestInterface(t *testing.T) {
	t.Parallel()

	var _ = gostr341194.New()
}
