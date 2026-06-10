// Package keg implements KEG ("key export generation"), the GOST 2012 TLS 1.2
// key-derivation step from R 1323565.1.020-2018 §6.4.5.1, used by the RFC 9189 /
// RFC 9367 GOST cipher suites (engine function gost_keg).
//
// KEG turns a VKO Diffie-Hellman shared secret into the 64-byte symmetric key
// block that gost_kexp15 then uses to wrap the TLS pre-master secret. It produces
// only the key block; it does not do the wrapping.
//
// This is a clean-room implementation built strictly from
// keg.md. It reuses the sibling clean-room packages vko
// (VKO 2012-256) and kdftree (KDF_TREE_GOSTR3411_2012_256) and imports
// no gogost code.
//
// # References
//
//   - RFC 9189: https://github.com/bigbes/gostcrypto/blob/master/keg/rfc/rfc9189.txt
//   - R 1323565.1.020-2018: https://github.com/bigbes/gostcrypto/blob/master/keg/rfc/R1323565.1.020-2018.pdf
package keg

import (
	"errors"

	"github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/kdftree"
	"github.com/bigbes/gostcrypto/vko"
)

const (
	// ukmLen is the byte length of the VKO UKM taken from ukm_source[0:16].
	ukmLen = 16
	// kdfSeedEnd is the end offset of the 8-byte KDF seed ukm_source[16:24].
	kdfSeedEnd = 24
	// ukmSourceLen is the exact ukm_source length: 32 bytes, the size of
	// Streebog256(client_random ‖ server_random) in RFC 9189 TLS. The spec
	// (keg.md §Sizes) fixes it at exactly 32, and the downstream KExp15 IV is
	// read from ukm_source[24:24+ivLen], so a shorter ukm_source is malformed.
	ukmSourceLen = 32
	// outLen is the KDFTree output length in bytes (the 64-byte export block).
	outLen = 64
	// max256BitLen is the largest field-prime bit length accepted by the
	// 256-bit KEG: a curve whose P.BitLen() exceeds this is a 512-bit curve,
	// which uses a different algorithm KEG2012_256 does not implement.
	max256BitLen = 256
)

// errUKMSourceLen is returned when ukm_source is not exactly 32 bytes.
var errUKMSourceLen = errors.New("keg: ukm_source must be exactly 32 bytes")

// errCurve512 is returned when a 512-bit curve is supplied: KEG2012_256
// implements only the 256-bit case (NID_id_GostR3410_2012_256). The 512-bit
// KEG is a distinct algorithm (keg.md §Specification) not handled here.
var errCurve512 = errors.New("keg: KEG2012_256 supports only 256-bit curves; 512-bit curve rejected")

// kdfLabel is the fixed 8-byte ASCII label "kdf tree" (no NUL terminator); a
// separate 0x00 separator follows it inside KDFTree. keg.md §"Step 3".
var kdfLabel = []byte("kdf tree")

// curveTC26256A returns GOST R 34.10-2012 256-bit TC26 ParamSet A
// (OID 1.2.643.7.1.2.1.1.1, cofactor 4) — the curve KEG2012_256 operates on.
func curveTC26256A() *gost3410curves.Curve {
	c, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.1.1")
	if err != nil {
		panic("keg: tc26-256-A curve missing: " + err.Error())
	}

	return c
}

// KEG2012_256 derives the 64-byte export key block for the 256-bit GOST TLS
// suites (keg.md §Specification, R 1323565.1.020-2018 §6.4.5.1).
//
// The curve argument selects the 256-bit GOST R 34.10-2012 domain the VKO and
// scalar steps run on — "whatever 256-bit curve the certificate uses",
// including the CryptoPro paramsets signalled as GC256B/C/D (RFC 9189
// §A.1.3 / keg/rfc/rfc9189.txt). A nil curve defaults to TC26 256-bit
// ParamSet A (OID 1.2.643.7.1.2.1.1.1), the curve the algorithm is specified
// against. A 512-bit curve is rejected (errCurve512): the 512-bit KEG is a
// different algorithm not implemented here.
//
// Inputs:
//   - serverPub:  peer GOST 2012-256 public key, 64 raw bytes (LE X ‖ LE Y).
//   - clientPriv: local GOST 2012-256 private key, 32-byte LE scalar.
//   - ukmSource:  32-byte UKM material (Streebog256(client_random ‖ server_random)).
//
// Output split (documented for the consumer; KEG itself returns the flat 64 B):
//
//	expkeys[ 0:32] = MAC key
//	expkeys[32:64] = cipher key
func KEG2012_256(curve *gost3410curves.Curve, serverPub, clientPriv, ukmSource []byte) ([64]byte, error) {
	var out [64]byte

	if len(ukmSource) != ukmSourceLen {
		return out, errUKMSourceLen
	}

	if curve == nil {
		curve = curveTC26256A()
	} else if curve.P.BitLen() > max256BitLen {
		return out, errCurve512
	}

	// Step 1 — UKM adjustment (keg.md §"Step 1").
	// real_ukm = reverse(ukm_source[0:16]); all-zero special case → 00…00 01.
	realUKM := make([]byte, ukmLen)
	src := ukmSource[:ukmLen]
	allZero := true

	for _, b := range src {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		realUKM[15] = 1
	} else {
		for i := range 16 {
			realUKM[i] = src[15-i] // byte-reverse the first 16 bytes.
		}
	}

	// Step 2 — VKO 2012-256 shared secret (keg.md §"Step 2").
	// tmpkey = VKO_GOSTR3411_2012_256(serverPub, clientPriv, real_ukm) on the
	// selected 256-bit curve. The sibling vko package handles the LE point-mul,
	// cofactor clear, LE(X)‖LE(Y) serialization, the Streebog-256 finalize, and
	// validates that serverPub/clientPriv lengths and on-curve membership are
	// correct (those errors propagate out unchanged).
	tmpkey, err := vko.KEK2012256(curve, clientPriv, serverPub, realUKM)
	if err != nil {
		return out, err
	}

	// Step 3 — KDFTree expansion to 64 bytes (keg.md §"Step 3").
	// keyout = KDF_TREE(key=tmpkey, label="kdf tree", seed=ukm_source[16:24],
	//                   r=1 (single-byte counter), outLen=64).
	seed := ukmSource[ukmLen:kdfSeedEnd]
	keyout := kdftree.KDFTree256(tmpkey, kdfLabel, seed, 1, outLen)
	copy(out[:], keyout)

	return out, nil
}
