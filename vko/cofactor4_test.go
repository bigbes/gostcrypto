package vko_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	crv "github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/vko"
)

// TestVKO2012_256_Cofactor4 pins a VKO vector on tc26-256-A, a cofactor-4
// curve. This closes the gap the random differential skipped (it exercised
// cofactor-1 only) and settles the guide-D2 question: gogost AND gost-engine
// both apply the cofactor, so the clean-room (which also does) matches both.
//
// The engine applies the cofactor inside gost_ec_point_mul — the explicit
// cofactor multiply in tmp/engine/gost_ec_keyx.c:74 (BN_lshift(scalar,2)) is
// `#if 0`-disabled precisely because the point-mul already clears it
// (gost_ec_keyx.c:65-69). The expected value below was computed via the gogost
// oracle and independently reproduced by this package's KEK2012256.
//
//	curve  = id-tc26-gost-3410-12-256-paramSetA (OID 1.2.643.7.1.2.1.1.1)
//	priv   = 0x11 * 32 (LE)
//	peerQ  = pub of 0x22*32 on the same curve (LE X||Y, below)
//	ukm    = 01 00 00 00 00 00 00 00
func TestVKO2012_256_Cofactor4(t *testing.T) {
	t.Parallel()

	c, err := crv.CurveByOID("1.2.643.7.1.2.1.1.1")
	if err != nil {
		t.Fatal(err)
	}

	priv := bytes.Repeat([]byte{0x11}, 32)
	pub, _ := hex.DecodeString(
		"5bdf2b87cb48d375feaed65e3c840548d0c3c497f1dbbba163a6a25077a927b8" +
			"5b99b9f94433e8fe42aaf7190f5ae254695f65b52e111a129f1a65e3a62976ce")
	ukm := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	want, _ := hex.DecodeString(
		"0fb3a1f57deab23f4ac566ae07707169f1f5ec7fea2477625b58b259cf529453")

	got, err := vko.KEK2012256(c, priv, pub, ukm)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("cofactor-4 VKO: got %x want %x", got, want)
	}
}
