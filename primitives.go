// Package gostcrypto is the public facade over the clean-room, pure-Go GOST
// primitive subpackages (streebog, kuznyechik, magma, ...).
//
// Every function accepts and returns plain []byte so callers (gostls,
// x509gost) never import the primitive subpackages directly. This is the
// designed swap point: changing a primitive's implementation is confined to
// this package.
//
// Each primitive subpackage's doc lists the RFC(s) and GOST standard(s) it
// implements; see the package table in the repository README.
package gostcrypto

import (
	"encoding/asn1"
	"errors"
	"fmt"

	crgost28147 "github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost3410curves"
	crgostr341194 "github.com/bigbes/gostcrypto/gostr341194"
	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	"github.com/bigbes/gostcrypto/streebog"
	"github.com/bigbes/gostcrypto/vko"
)

// Sentinel errors for the one-shot block helper input validation.
var (
	errKuznyechikInputLen = errors.New("gost: KuznyechikEncrypt/Decrypt: input must be exactly 16 bytes")
	errMagmaInputLen      = errors.New("gost: MagmaEncrypt/Decrypt: input must be exactly 8 bytes")
	errGOST28147InputLen  = errors.New("gost: GOST2814789Encrypt/Decrypt: input must be exactly 8 bytes")
)

// errUnsupportedCurveOID is returned when an OID does not map to a known GOST
// curve parameter set.
var errUnsupportedCurveOID = errors.New("gost: unsupported curve OID")

// Curve is an opaque handle for a GOST R 34.10 curve. It wraps the clean-room
// curve type so callers in tls/internal/ke, tls/internal/handshake, and
// x509gost can pass a curve around without naming the backend. Obtain one via
// CurveByOID or GOST2001TestParamSetCurve.
type Curve struct{ inner *gost3410curves.Curve }

// Sbox is an opaque handle for a GOST 28147-89 S-box. It wraps the clean-room
// S-box value so callers select a wrap / session S-box by identity without
// naming the backend. Use the SboxCryptoProA / SboxTC26Z package variables.
type Sbox struct{ inner crgost28147.SBox }

// SboxCryptoProA is the GOST 28147-89 CryptoPro-A S-box.
var SboxCryptoProA = &Sbox{inner: crgost28147.SboxCryptoProA}

// SboxTC26Z is the GOST 28147-89 tc26 param-Z S-box.
var SboxTC26Z = &Sbox{inner: crgost28147.SboxTC26Z}

// CurveByOID resolves a GOST R 34.10 curve from its ASN.1 OID.
// Returns errUnsupportedCurveOID when the OID is not a known GOST curve.
func CurveByOID(oid asn1.ObjectIdentifier) (*Curve, error) {
	c, err := gost3410curves.CurveByOID(oid.String())
	if err != nil {
		return nil, fmt.Errorf("%w %v", errUnsupportedCurveOID, oid)
	}

	return &Curve{inner: c}, nil
}

// ── Kuznyechik (GOST R 34.12-2015, 128-bit) ──────────────────────────────────.

// KuznyechikEncrypt encrypts one 16-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 16 bytes.
func KuznyechikEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) != kuznyechik.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errKuznyechikInputLen, len(plaintext))
	}

	c := kuznyechik.NewCipher(key)
	dst := make([]byte, kuznyechik.BlockSize)
	c.Encrypt(dst, plaintext)

	return dst, nil
}

// KuznyechikDecrypt decrypts one 16-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 16 bytes.
func KuznyechikDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != kuznyechik.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errKuznyechikInputLen, len(ciphertext))
	}

	c := kuznyechik.NewCipher(key)
	dst := make([]byte, kuznyechik.BlockSize)
	c.Decrypt(dst, ciphertext)

	return dst, nil
}

// ── Magma (GOST R 34.12-2015, 64-bit) ────────────────────────────────────────.

// MagmaEncrypt encrypts one 8-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 8 bytes.
func MagmaEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) != magma.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errMagmaInputLen, len(plaintext))
	}

	c := magma.NewCipher(key)
	dst := make([]byte, magma.BlockSize)
	c.Encrypt(dst, plaintext)

	return dst, nil
}

// MagmaDecrypt decrypts one 8-byte block with the given 32-byte key.
// Returns an error if the input is not exactly 8 bytes.
func MagmaDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != magma.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errMagmaInputLen, len(ciphertext))
	}

	c := magma.NewCipher(key)
	dst := make([]byte, magma.BlockSize)
	c.Decrypt(dst, ciphertext)

	return dst, nil
}

// ── GOST 28147-89 ─────────────────────────────────────────────────────────────.

// GOST2814789Encrypt encrypts one 8-byte block with the given 32-byte key using
// the default (CryptoPro-A) S-box. Returns an error if the input is not
// exactly 8 bytes.
func GOST2814789Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext) != crgost28147.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errGOST28147InputLen, len(plaintext))
	}

	c := crgost28147.NewCipher(key, crgost28147.SboxCryptoProA)
	dst := make([]byte, crgost28147.BlockSize)
	c.Encrypt(dst, plaintext)

	return dst, nil
}

// GOST2814789Decrypt decrypts one 8-byte block with the given 32-byte key using
// the default (CryptoPro-A) S-box. Returns an error if the input is not
// exactly 8 bytes.
func GOST2814789Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != crgost28147.BlockSize {
		return nil, fmt.Errorf("%w: got %d", errGOST28147InputLen, len(ciphertext))
	}

	c := crgost28147.NewCipher(key, crgost28147.SboxCryptoProA)
	dst := make([]byte, crgost28147.BlockSize)
	c.Decrypt(dst, ciphertext)

	return dst, nil
}

// ── Streebog (GOST R 34.11-2012) ─────────────────────────────────────────────.

// Streebog256 computes the Streebog-256 (GOST R 34.11-2012, 256-bit) hash.
func Streebog256(msg []byte) []byte {
	h := streebog.Sum256(msg)
	return h[:]
}

// Streebog512 computes the Streebog-512 (GOST R 34.11-2012, 512-bit) hash.
func Streebog512(msg []byte) []byte {
	h := streebog.Sum512(msg)
	return h[:]
}

// ── GOST R 34.11-94 hash ──────────────────────────────────────────────────────.

// GOSTR341194 computes the GOST R 34.11-94 hash using the CryptoPro parameter set.
func GOSTR341194(msg []byte) []byte {
	h := crgostr341194.Sum(msg)
	return h[:]
}

// ── GOST R 34.10-2001 signature verify ───────────────────────────────────────.

// R342001Verify verifies a GOST R 34.10-2001 signature on the
// id-GostR3410-2001-CryptoPro-A parameter set.
func R342001Verify(pubRaw, digest, sig []byte) (bool, error) {
	c, err := gost3410curves.CurveByOID("1.2.643.2.2.35.1")
	if err != nil {
		return false, err
	}

	return verifyOnCurve(c, pubRaw, digest, sig)
}

// ── VKO GOST R 34.10-2001 key agreement ──────────────────────────────────────.

// VKO2001 computes the VKO GOST R 34.10-2001 shared KEK (RFC 4357) on the
// id-GostR3410-2001-CryptoPro-A curve.
func VKO2001(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	c, err := gost3410curves.CurveByOID("1.2.643.2.2.35.1")
	if err != nil {
		return nil, err
	}

	return VKO2001OnCurve(&Curve{inner: c}, prvRaw, pubRaw, ukmRaw)
}

// VKO2001OnCurve is the curve-aware variant of VKO2001.
func VKO2001OnCurve(curve *Curve, prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return vko.KEK2001(curve.inner, prvRaw, pubRaw, ukmRaw)
}

// VKO2001TestCurve computes VKO GOST R 34.10-2001 shared KEK using the test
// parameter set curve.
func VKO2001TestCurve(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return vko.VKO2001TestCurve(prvRaw, pubRaw, ukmRaw)
}

// ── VKO GOST R 34.10-2012 key agreement ──────────────────────────────────────.

// VKO2012_256 computes VKO GOST R 34.10-2012 with 256-bit KEK output (RFC 7836)
// on the id-tc26-gost-3410-2012-512-paramSetA curve.
func VKO2012_256(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return vko.VKO2012_256(prvRaw, pubRaw, ukmRaw)
}

// VKO2012_256OnCurve is the curve-aware variant of VKO2012_256.
func VKO2012_256OnCurve(curve *Curve, prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return vko.KEK2012256(curve.inner, prvRaw, pubRaw, ukmRaw)
}

// VKO2012_512 computes VKO GOST R 34.10-2012 with 512-bit KEK output (RFC 7836)
// on the id-tc26-gost-3410-2012-512-paramSetA curve.
func VKO2012_512(prvRaw, pubRaw, ukmRaw []byte) ([]byte, error) {
	return vko.VKO2012_512(prvRaw, pubRaw, ukmRaw)
}
