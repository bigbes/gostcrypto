package gostcrypto

// modes.go backs the GOST mode/KDF/KEX wrappers (CTR, OMAC, KDFTree,
// TLSTree, KEG, kexp15, CNT, IMIT, ephemeral keygen) with the clean-room
// implementation packages.

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/bigbes/gostcrypto/ctracpkm"
	crgost28147 "github.com/bigbes/gostcrypto/gost28147"
	"github.com/bigbes/gostcrypto/gost28147cnt"
	"github.com/bigbes/gostcrypto/gost28147imit"
	"github.com/bigbes/gostcrypto/gost3410sign"
	"github.com/bigbes/gostcrypto/kdftree"
	"github.com/bigbes/gostcrypto/keg"
	"github.com/bigbes/gostcrypto/kexp15"
	"github.com/bigbes/gostcrypto/omac"
	"github.com/bigbes/gostcrypto/tlstree"
)

// Fixed sizes (bytes) for the mode/KDF/KEX wrappers below.
const (
	// acpkmKeySize is the ACPKM key length.
	acpkmKeySize = 32
	// tlsTreeMasterKeySize is the TLSTree master-key length.
	tlsTreeMasterKeySize = 32
	// kegUKMSourceSize is the KEG2012_256 ukmSource length.
	kegUKMSourceSize = 32
)

// Sentinel errors for the mode/KDF/KEX wrapper input validation.
var (
	errCTRIVLen         = errors.New("gost/ctr: iv length does not match block size")
	errACPKMKeyLen      = errors.New("gost/ctr: ACPKM key length, want 32")
	errCTRNegSection    = errors.New("gost/ctr: negative sectionSize")
	errCTRSectionMod    = errors.New("gost/ctr: sectionSize not a multiple of block size")
	errOMACTagSize      = errors.New("gost: NewOMAC: tagSize out of range")
	errKEGUKMSourceLen  = errors.New("gost.KEG2012_256: ukmSource must be 32 bytes")
	errKexpUnknown      = errors.New("gost.Kexp15: unknown variant")
	errCNTKeyLen        = errors.New("gost: GOST28147_CNT key length")
	errCNTIVLen         = errors.New("gost: GOST28147_CNT iv length")
	errIMITKeyLen       = errors.New("gost: GOST28147_IMIT key length")
	errIMITEmptyMessage = errors.New("gost: GOST28147_IMIT message must not be empty")
	errEphemeralZeroKey = errors.New("gost.GenerateEphemeralKey: zero private key")
)

// ── GOST R 34.13-2015 CTR mode (+ ACPKM) ─────────────────────────────────────.

// CTR holds per-record CTR state. Create one per record via NewCTR or
// NewCTRACPKM; discard after the record is processed.
type CTR struct{ inner cipher.Stream }

// NewCTR creates a new CTR stream cipher over block with the given iv. iv must
// be exactly block.BlockSize() bytes.
func NewCTR(block cipher.Block, iv []byte) (*CTR, error) {
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("%w: iv %d, block %d", errCTRIVLen, len(iv), block.BlockSize())
	}

	return &CTR{inner: ctracpkm.NewCTR(block, iv)}, nil
}

// NewCTRACPKM creates a CTR with intra-record ACPKM key meshing enabled.
// newBlock builds a cipher.Block from a 32-byte key. sectionSize is the number
// of keystream bytes after which the key is refreshed (0 disables ACPKM).
func NewCTRACPKM(newBlock func([]byte) cipher.Block, key, iv []byte, sectionSize int) (*CTR, error) {
	if len(key) != acpkmKeySize {
		return nil, fmt.Errorf("%w: got %d", errACPKMKeyLen, len(key))
	}

	bs := newBlock(key).BlockSize()
	if len(iv) != bs {
		return nil, fmt.Errorf("%w: iv %d, block %d", errCTRIVLen, len(iv), bs)
	}

	if sectionSize < 0 {
		return nil, fmt.Errorf("%w: %d", errCTRNegSection, sectionSize)
	}

	if sectionSize != 0 && sectionSize%bs != 0 {
		return nil, fmt.Errorf("%w: section %d, block %d", errCTRSectionMod, sectionSize, bs)
	}

	return &CTR{inner: ctracpkm.NewCTRACPKM(newBlock, key, iv, sectionSize)}, nil
}

// XORKeyStream XORs each byte of src with the CTR gamma stream, writing the
// result into dst.
func (c *CTR) XORKeyStream(dst, src []byte) { c.inner.XORKeyStream(dst, src) }

// ── OMAC (CMAC) ──────────────────────────────────────────────────────────────.

// OMAC wraps the clean-room OMAC/CMAC implementation. It implements hash.Hash
// (Write / Sum / Reset / BlockSize / Size) with non-destructive Sum.
type OMAC struct {
	inner   *omac.OMAC
	block   cipher.Block
	tagSize int
}

// NewOMAC returns an OMAC/CMAC instance using the given block cipher. tagSize
// must be in [1, block.BlockSize()].
func NewOMAC(block cipher.Block, tagSize int) (*OMAC, error) {
	bs := block.BlockSize()
	if tagSize < 1 || tagSize > bs {
		return nil, fmt.Errorf("%w: tagSize %d, want [1, %d]", errOMACTagSize, tagSize, bs)
	}

	return &OMAC{inner: omac.New(block, tagSize), block: block, tagSize: tagSize}, nil
}

// Write adds data to the running MAC state.
func (o *OMAC) Write(p []byte) (int, error) { return o.inner.Write(p) }

// Sum appends the current MAC to b and returns the result. Non-destructive.
func (o *OMAC) Sum(b []byte) []byte { return o.inner.Sum(b) }

// Reset re-initialises the OMAC state to zero (as if freshly constructed). The
// clean-room OMAC has no in-place reset by design, so a fresh instance is
// built over the same block and tag size.
func (o *OMAC) Reset() { o.inner = omac.New(o.block, o.tagSize) }

// BlockSize returns the block size of the underlying cipher.
func (o *OMAC) BlockSize() int { return o.inner.BlockSize() }

// Size returns the tag size in bytes.
func (o *OMAC) Size() int { return o.inner.Size() }

// ── KDFTree2012_256 (R 50.1.113-2016) ────────────────────────────────────────.

// KDFTree2012_256 derives keyOutLen bytes of key material from key + label +
// seed. keyOutLen must be a positive multiple of 32.
func KDFTree2012_256(key, label, seed []byte, keyOutLen int) []byte {
	if keyOutLen <= 0 || keyOutLen%32 != 0 {
		panic("gost.KDFTree2012_256: keyOutLen must be a positive multiple of 32")
	}

	if keyOutLen > 0xFFFF/8 {
		panic("gost.KDFTree2012_256: keyOutLen too large for 2-byte length encoding")
	}

	return kdftree.KDFTree256(key, label, seed, 1, keyOutLen)
}

// ── TLSTree (RFC 9367 per-record key derivation) ─────────────────────────────.

// TLSTree wraps the clean-room TLSTree.
type TLSTree struct{ inner *tlstree.TLSTree }

// NewTLSTreeKuznyechikCTROMAC creates a TLSTree for the
// TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC cipher suite (RFC 9367 §4.3).
func NewTLSTreeKuznyechikCTROMAC(masterKey []byte) *TLSTree {
	if len(masterKey) != tlsTreeMasterKeySize {
		panic("gost/tlstree: masterKey must be 32 bytes for KuznyechikCTROMAC")
	}

	return &TLSTree{inner: tlstree.NewTLSTreeKuznyechikCTROMAC(masterKey)}
}

// NewTLSTreeMagmaCTROMAC creates a TLSTree for the
// TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC cipher suite (RFC 9367 §4.4).
func NewTLSTreeMagmaCTROMAC(masterKey []byte) *TLSTree {
	if len(masterKey) != tlsTreeMasterKeySize {
		panic("gost/tlstree: masterKey must be 32 bytes for MagmaCTROMAC")
	}

	return &TLSTree{inner: tlstree.NewTLSTreeMagmaCTROMAC(masterKey)}
}

// Derive returns a fresh 32-byte key for the given TLS record sequence number.
func (t *TLSTree) Derive(seqNum uint64) []byte { return t.inner.Derive(seqNum) }

// ── KEG2012_256 (GOST 2018 key exchange) ─────────────────────────────────────.

// KEG2012_256 derives a 64-byte shared secret using the GOST 2018 KEG algorithm
// (R 1323565.1.020-2018 §6.4.5.1) on the supplied 256-bit curve.
//
// It honors the caller's curve (extracted from the server certificate),
// delegating to the clean-room keg package, which performs the UKM adjustment,
// VKO-2012-256 agreement and KDFTree expansion. A 512-bit curve is rejected by
// keg with an error.
func KEG2012_256(curve *Curve, serverPubRaw, clientPrivRaw, ukmSource []byte) ([64]byte, error) {
	var out [64]byte

	// Preserve the facade's own UKM-length sentinel; keg also enforces 32, but
	// surfacing errKEGUKMSourceLen keeps the facade error contract stable.
	if len(ukmSource) != kegUKMSourceSize {
		return out, fmt.Errorf("%w, got %d", errKEGUKMSourceLen, len(ukmSource))
	}

	return keg.KEG2012_256(curve.inner, serverPubRaw, clientPrivRaw, ukmSource)
}

// ── kexp15 (GOST 2018 key export) ────────────────────────────────────────────.

// KexpVariant selects the underlying block cipher for kexp15.
type KexpVariant int

const (
	// KexpKuznyechik uses Kuznyechik (128-bit block). iv_len=8, mac_len=16.
	KexpKuznyechik KexpVariant = iota
	// KexpMagma uses Magma (64-bit block). iv_len=4, mac_len=8.
	KexpMagma
)

// Kexp15 wraps a shared key for transport using gost_kexp15.
func Kexp15(variant KexpVariant, sharedKey, cipherKey, macKey, iv []byte) ([]byte, error) {
	var cv kexp15.KexpVariant

	switch variant {
	case KexpKuznyechik:
		cv = kexp15.KexpKuznyechik
	case KexpMagma:
		cv = kexp15.KexpMagma
	default:
		return nil, fmt.Errorf("%w %d", errKexpUnknown, variant)
	}

	return kexp15.Kexp15(cv, sharedKey, cipherKey, macKey, iv)
}

// ── GOST 28147-89 CNT mode and IMIT MAC ──────────────────────────────────────.

// gostCNTStream adapts the clean-room CNT to cipher.Stream over the default
// (CryptoPro-A) S-box.
type gostCNTStream struct{ inner *gost28147cnt.CNT }

func (s *gostCNTStream) XORKeyStream(dst, src []byte) { s.inner.XORKeyStream(dst, src) }

// NewGOST28147_CNT returns a cipher.Stream implementing GOST 28147-89 in CNT
// (counter stream) mode with the CryptoPro-A S-box. key must be 32 bytes; iv
// must be 8 bytes.
func NewGOST28147_CNT(key, iv []byte) (cipher.Stream, error) {
	if len(key) != crgost28147.KeySize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errCNTKeyLen, crgost28147.KeySize, len(key))
	}

	if len(iv) != crgost28147.BlockSize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errCNTIVLen, crgost28147.BlockSize, len(iv))
	}

	c := crgost28147.NewCipher(key, crgost28147.SboxCryptoProA)

	return &gostCNTStream{inner: gost28147cnt.NewCNT(c, iv)}, nil
}

// GOST28147_IMIT computes the GOST 28147-89 IMIT MAC over msg using the given
// key and CryptoPro-A S-box with CryptoPro key meshing. Output is 4 bytes.
func GOST28147_IMIT(key, msg []byte) ([]byte, error) {
	if len(key) != crgost28147.KeySize {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errIMITKeyLen, crgost28147.KeySize, len(key))
	}

	if len(msg) == 0 {
		return nil, errIMITEmptyMessage
	}

	return gost28147imit.IMIT(key, msg), nil
}

// ── Ephemeral key generation ─────────────────────────────────────────────────.

// GenerateEphemeralKey generates an ephemeral GOST R 34.10-2012 key pair on
// curve using rnd. Returns privRaw (LE, PointSize bytes) and pubRaw
// (LE(X)||LE(Y), 2×PointSize bytes).
//
// The scalar is drawn exactly as gogost's GenPrivateKey does: read PointSize
// raw bytes from rnd, interpret little-endian, reduce mod q. This keeps the two
// backends byte-for-byte identical for a given rnd stream (the pinned-seed TLS
// key-exchange tests depend on it).
func GenerateEphemeralKey(curve *Curve, rnd io.Reader) (privRaw, pubRaw []byte, err error) {
	ps := curve.inner.PointSize()
	q := curve.inner.Q
	raw := make([]byte, ps)

	if _, err := io.ReadFull(rnd, raw); err != nil {
		return nil, nil, fmt.Errorf("gost.GenerateEphemeralKey: %w", err)
	}

	// Interpret raw little-endian, reduce mod q.
	beRaw := make([]byte, ps)
	for i := range raw {
		beRaw[ps-1-i] = raw[i]
	}

	d := new(big.Int).SetBytes(beRaw)
	if d.Sign() == 0 {
		return nil, nil, errEphemeralZeroKey
	}

	d.Mod(d, q)

	priv := big2leFixed(d, ps)
	pub := gost3410sign.PublicKeyRaw(curve.inner, priv)

	return priv, pub, nil
}
