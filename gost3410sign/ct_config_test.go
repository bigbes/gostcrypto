// ct_config_test.go — EXPERIMENT. The ConstantTime knob must be transparent:
// signing and public-key derivation produce byte-identical results whether the
// secret-scalar multiplies run on the constant-time path or the reference one.

package gost3410sign_test

import (
	"bytes"
	"testing"

	gost3410sign "github.com/bigbes/gostcrypto/gost3410sign"
)

func TestConstantTime_MatchesReference(t *testing.T) {
	t.Parallel()

	c := testParamSetCurve()
	prv := mustHex(t, katPrvLE)
	dig := mustHex(t, katDigBE)
	k := mustHex(t, katNonce)

	c.ConstantTime = false

	sigRef := gost3410sign.SignDigest(c, prv, dig, k)
	pubRef := gost3410sign.PublicKeyRaw(c, prv)

	c.ConstantTime = true

	sigCT := gost3410sign.SignDigest(c, prv, dig, k)
	pubCT := gost3410sign.PublicKeyRaw(c, prv)

	switch {
	case sigRef == nil || sigCT == nil:
		t.Fatal("SignDigest returned nil for a valid KAT input")
	case !bytes.Equal(sigRef, sigCT):
		t.Fatalf("signature differs CT vs reference:\n ref=%x\n  ct=%x", sigRef, sigCT)
	case !bytes.Equal(pubRef, pubCT):
		t.Fatalf("public key differs CT vs reference:\n ref=%x\n  ct=%x", pubRef, pubCT)
	}

	// The constant-time signature must still verify under the reference path.
	if !gost3410sign.VerifyDigest(c, pubCT, dig, sigCT) {
		t.Fatal("constant-time signature failed VerifyDigest")
	}
}
