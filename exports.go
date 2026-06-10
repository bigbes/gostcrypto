package gostcrypto

// exports.go is the facade's containment boundary. Every primitive type that
// would otherwise appear in a caller's signature is wrapped here so that
// consumers (gostls, x509gost) import only this package, never the primitive
// subpackages directly.

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"

	crgost28147 "github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147imit"
	"github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/gost3410sign"
	crgostr341194 "github.com/bigbes/gostcrypto/gostr341194"
	"github.com/bigbes/gostcrypto/keywrap"
	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	"github.com/bigbes/gostcrypto/streebog"
	"github.com/bigbes/gostcrypto/vko"
)

// Block-cipher dimensions, re-exported so callers size buffers without naming
// the backend packages.
const (
	GOST28147BlockSize  = crgost28147.BlockSize // 8
	GOST28147KeySize    = crgost28147.KeySize   // 32
	KuznyechikBlockSize = kuznyechik.BlockSize  // 16
	MagmaBlockSize      = magma.BlockSize       // 8
)

// Fixed sizes for the CryptoPro key-wrap inputs (RFC 4357).
const (
	// kekSize is the KEK length in bytes.
	kekSize = 32
	// ukmSize is the UKM length in bytes.
	ukmSize = 8
	// sessionKeySize is the session-key length in bytes.
	sessionKeySize = 32
	// imitPlaceholderTagSize is the 4-byte IMIT metadata tag length the suite
	// registry reports.
	imitPlaceholderTagSize = 4
	// signNonceAttempts bounds the rejection-sampling loop for the per-signature
	// nonce.
	signNonceAttempts = 64
)

// errExhaustedNonceAttempts is returned when signing fails to find a valid
// nonce within signNonceAttempts tries.
var errExhaustedNonceAttempts = errors.New("gost: SignDigestOnCurve: exhausted nonce attempts")

// Sentinel errors for the CryptoPro key-wrap input validation.
var (
	errKeyWrapKEKSize        = errors.New("gost: KeyWrapCryptoPro KEK must be 32 bytes")
	errKeyWrapUKMSize        = errors.New("gost: KeyWrapCryptoPro UKM must be 8 bytes")
	errKeyWrapSessionKeySize = errors.New("gost: KeyWrapCryptoPro session key must be 32 bytes")
)

// ── Hash factories (return hash.Hash, never a backend type) ──────────────────.

// NewStreebog256Hash returns a fresh Streebog-256 (GOST R 34.11-2012) hash.
func NewStreebog256Hash() hash.Hash { return streebog.New256() }

// NewStreebog512Hash returns a fresh Streebog-512 (GOST R 34.11-2012) hash.
func NewStreebog512Hash() hash.Hash { return streebog.New512() }

// NewGOSTR341194CryptoProHash returns a fresh GOST R 34.11-94 hash using the
// CryptoPro parameter-set S-box.
func NewGOSTR341194CryptoProHash() hash.Hash { return crgostr341194.New() }

// imitPlaceholderHash satisfies hash.Hash for the suite registry's metadata
// field (KeyLen / MACLen reporting). It does not compute a real GOST 28147-89
// IMIT; the record-layer protector does that with the session key.
type imitPlaceholderHash struct{ n int }

func (h *imitPlaceholderHash) Write(p []byte) (int, error) { h.n += len(p); return len(p), nil }
func (h *imitPlaceholderHash) Sum(b []byte) []byte {
	return append(b, make([]byte, imitPlaceholderTagSize)...)
}
func (h *imitPlaceholderHash) Reset()         { h.n = 0 }
func (h *imitPlaceholderHash) Size() int      { return imitPlaceholderTagSize }
func (h *imitPlaceholderHash) BlockSize() int { return GOST28147BlockSize }

// NewGOST28147IMITPlaceholderHash returns a GOST 28147-89 IMIT placeholder
// hash.Hash. It exists solely to satisfy the suite registry's MACSpec.Hash
// metadata field (consulted for KeyLen / MACLen reporting); the real
// record-layer MAC is computed by the protector with the session key.
func NewGOST28147IMITPlaceholderHash() hash.Hash { return &imitPlaceholderHash{} }

// ── Block ciphers (return crypto/cipher.Block, never a backend type) ─────────.

// NewKuznyechikCipher returns a Kuznyechik (GOST R 34.12-2015, 128-bit) block
// cipher for the given 32-byte key.
func NewKuznyechikCipher(key []byte) cipher.Block { return kuznyechik.NewCipher(key) }

// NewMagmaCipher returns a Magma (GOST R 34.12-2015, 64-bit) block cipher for
// the given 32-byte key.
func NewMagmaCipher(key []byte) cipher.Block { return magma.NewCipher(key) }

// ── GOST 28147-89 block cipher (opaque handle for the CNT/IMIT protector) ────.

// GOST28147Cipher is an opaque GOST 28147-89 block cipher. It exposes the
// single-block primitives the record-layer CNT mode and IMIT MAC need.
type GOST28147Cipher struct {
	inner *crgost28147.Cipher
	key   []byte
	sbox  crgost28147.SBox
}

// NewGOST28147Cipher builds a GOST 28147-89 cipher from a 32-byte key and the
// given S-box.
func NewGOST28147Cipher(key []byte, sbox *Sbox) *GOST28147Cipher {
	k := make([]byte, len(key))
	copy(k, key)

	return &GOST28147Cipher{
		inner: crgost28147.NewCipher(key, sbox.inner),
		key:   k,
		sbox:  sbox.inner,
	}
}

// Encrypt encrypts one 8-byte block (32-round schedule) from src into dst.
func (c *GOST28147Cipher) Encrypt(dst, src []byte) { c.inner.Encrypt(dst, src) }

// Decrypt decrypts one 8-byte block (32-round schedule) from src into dst.
func (c *GOST28147Cipher) Decrypt(dst, src []byte) { c.inner.Decrypt(dst, src) }

// SeqMACBlock runs the 16-round SeqMAC encryption of a single 8-byte block with
// a zero IV — the per-block step of the GOST 28147-89 IMIT MAC. block must be
// 8 bytes; returns 8 bytes.
func (c *GOST28147Cipher) SeqMACBlock(block []byte) []byte {
	return gost28147imit.SeqMACBlock(c.key, c.sbox, block)
}

// ── GOST R 34.10 signature / key helpers on an explicit curve ────────────────.

// verifyOnCurve verifies a GOST R 34.10 signature over digest using pubRaw on
// the given clean-room curve.
func verifyOnCurve(c *gost3410curves.Curve, pubRaw, digest, sig []byte) (bool, error) {
	return gost3410sign.VerifyDigest(c, pubRaw, digest, sig), nil
}

// VerifyDigestOnCurve verifies a GOST R 34.10 signature over digest using the
// public key pubRaw on the given curve.
func VerifyDigestOnCurve(curve *Curve, pubRaw, digest, sig []byte) (bool, error) {
	return verifyOnCurve(curve.inner, pubRaw, digest, sig)
}

// Name returns the underlying curve's parameter-set name.
func (c *Curve) Name() string { return c.inner.Name }

// PointSize returns the curve's coordinate size in bytes.
func (c *Curve) PointSize() int { return c.inner.PointSize() }

// PublicKeyRawFromPrivate derives the LE-encoded public key from prvRaw on the
// given curve.
func PublicKeyRawFromPrivate(curve *Curve, prvRaw []byte) ([]byte, error) {
	return gost3410sign.PublicKeyRaw(curve.inner, prvRaw), nil
}

// signDigestOnCurve signs digest with the GOST R 34.10 private key prvRaw on
// the given clean-room curve, generating a random nonce from rnd and retrying
// until it yields a valid (r != 0, s != 0) signature.
func signDigestOnCurve(c *gost3410curves.Curve, prvRaw, digest []byte, rnd io.Reader) ([]byte, error) {
	q := c.Q
	for range signNonceAttempts {
		k, err := rand.Int(rnd, q)
		if err != nil {
			return nil, err
		}

		if k.Sign() == 0 {
			continue
		}

		kRaw := big2leFixed(k, c.PointSize())
		sig := gost3410sign.SignDigest(c, prvRaw, digest, kRaw)

		if sig != nil {
			return sig, nil
		}
	}

	return nil, errExhaustedNonceAttempts
}

// SignDigestOnCurve signs digest with the GOST R 34.10 private key prvRaw on
// the given curve, returning the raw signature. rnd supplies the per-signature
// nonce.
func SignDigestOnCurve(curve *Curve, prvRaw, digest []byte, rnd io.Reader) ([]byte, error) {
	return signDigestOnCurve(curve.inner, prvRaw, digest, rnd)
}

// big2leFixed serializes n as size little-endian bytes (the GOST private-key /
// nonce encoding).
func big2leFixed(n *big.Int, size int) []byte {
	be := n.Bytes()
	out := make([]byte, size)
	// copy big-endian into the low bytes, then reverse to little-endian.
	if len(be) > size {
		be = be[len(be)-size:]
	}

	copy(out[size-len(be):], be)

	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out
}

// ── GOST R 34.10 parameter-set helpers (test-vector support) ─────────────────.

// GOST2001TestParamSetCurve returns the GOST R 34.10-2001 test parameter set
// curve.
func GOST2001TestParamSetCurve() *Curve {
	return &Curve{inner: vko.Curve2001Test()}
}

// GOST2001CryptoProAParamSetCurve returns the GOST R 34.10-2001 CryptoPro-A
// parameter set curve (id-GostR3410-2001-CryptoPro-A-ParamSet).
func GOST2001CryptoProAParamSetCurve() *Curve {
	c, err := gost3410curves.CurveByOID("1.2.643.2.2.35.1")
	if err != nil {
		panic("gost: CryptoPro-A curve missing: " + err.Error())
	}

	return &Curve{inner: c}
}

// PublicKeyRawFromPrivate2001Test derives the LE-encoded GOST R 34.10-2001
// public key from prvRaw on the test parameter set curve.
func PublicKeyRawFromPrivate2001Test(prvRaw []byte) ([]byte, error) {
	return gost3410sign.PublicKeyRaw(vko.Curve2001Test(), prvRaw), nil
}

// ── GOST R 34.10-2012 sign + verify on the test parameter set curve ──────────.

// R341012Sign signs digest with a GOST R 34.10-2012 256-bit private key on the
// 2001 test parameter set curve.
func R341012Sign(prvRaw, digest []byte) ([]byte, error) {
	return signDigestOnCurve(vko.Curve2001Test(), prvRaw, digest, rand.Reader)
}

// R341012Verify verifies a GOST R 34.10-2012 256-bit signature on the 2001 test
// parameter set curve. prvRaw is the LE private key; the public key is derived.
func R341012Verify(prvRaw, digest, sig []byte) (bool, error) {
	c := vko.Curve2001Test()
	pubRaw := gost3410sign.PublicKeyRaw(c, prvRaw)

	return verifyOnCurve(c, pubRaw, digest, sig)
}

// ── CryptoPro key wrap (RFC 4357 §6.3 + §6.5) ────────────────────────────────.

// KeyWrapCryptoPro implements the CryptoPro key wrap algorithm (RFC 4357 §6.3
// wrap + §6.5 diversification). Returns a 44-byte buffer:
// [ukm(8) | encryptedSessionKey(32) | MAC(4)].
func KeyWrapCryptoPro(sbox *Sbox, kek, ukm, sessionKey []byte) ([]byte, error) {
	if len(kek) != kekSize {
		return nil, fmt.Errorf("%w, got %d", errKeyWrapKEKSize, len(kek))
	}

	if len(ukm) != ukmSize {
		return nil, fmt.Errorf("%w, got %d", errKeyWrapUKMSize, len(ukm))
	}

	if len(sessionKey) != sessionKeySize {
		return nil, fmt.Errorf("%w, got %d", errKeyWrapSessionKeySize, len(sessionKey))
	}

	return keywrap.KeyWrapCryptoPro(sbox.inner, kek, ukm, sessionKey)
}

// keyDiversifyCryptoPro implements RFC 4357 §6.5 KEK diversification, retained
// as a package-private helper so TestKeyWrapCryptoPro_KAT (facade_test.go) can
// cross-check the intermediate diversified key independently of the full wrap.
func keyDiversifyCryptoPro(sbox *Sbox, inputKey, ukm []byte) []byte {
	return keywrap.Diversify(sbox.inner, inputKey, ukm)
}

// ── compile-time assertions that the clean-room ciphers satisfy cipher.Block ─.

var (
	_ cipher.Block = (*kuznyechik.Cipher)(nil)
	_ cipher.Block = (*magma.Cipher)(nil)
)
