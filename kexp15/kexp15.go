// Package kexp15 implements the GOST KExp15 key-export envelope
// (R 1323565.1.017-2018), as specified by RFC 9189 §8.2.1. The construction
// is OMAC-then-CTR:
//
//	CEK_MAC = OMAC(K_Exp_MAC, IV || S)      (truncated to mac_len)
//	SExp    = CTR-Encrypt(K_Exp_ENC, IV_full, S || CEK_MAC)
//
// It is pure Go: it sits on the clean-room sibling packages
// {omac,ctracpkm,kuznyechik,magma} and imports no gogost.
//
// # References
//
//   - RFC 9189: https://github.com/bigbes/gostcrypto/blob/master/kexp15/rfc/rfc9189.txt
//   - R 1323565.1.017-2018: https://github.com/bigbes/gostcrypto/blob/master/kexp15/rfc/R1323565.1.017-2018.pdf
package kexp15

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/bigbes/gostcrypto/ctracpkm"
	"github.com/bigbes/gostcrypto/kuznyechik"
	"github.com/bigbes/gostcrypto/magma"
	"github.com/bigbes/gostcrypto/omac"
)

// KexpVariant selects the underlying R 34.12-2015 block cipher.
type KexpVariant int

const (
	// KexpKuznyechik is the 128-bit-block variant: iv_len=8, mac_len=16,
	// block=16. Used by RFC 9189 suite 0xC100
	// (TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC).
	KexpKuznyechik KexpVariant = iota
	// KexpMagma is the 64-bit-block variant: iv_len=4, mac_len=8, block=8.
	// Used by RFC 9189 suite 0xC101
	// (TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC).
	KexpMagma
)

// Per-variant sizes (guide "Inputs and sizes" table).
const (
	kuznyechikBlock  = 16
	kuznyechikIVLen  = 8
	kuznyechikMACLen = 16

	magmaBlock  = 8
	magmaIVLen  = 4
	magmaMACLen = 8

	// exportKeyLen is the required length of cipherKey and macKey.
	exportKeyLen = 32
)

// Sentinel errors for the public API and variant dispatch.
var (
	errUnknownVariant = errors.New("kexp15: unknown variant")
	errEmptySharedKey = errors.New("kexp15: shared key must be non-empty")
	errBadKeyLen      = errors.New("kexp15: key must be 32 bytes")
	errBadIVLen       = errors.New("kexp15: bad iv length")
)

// params holds the per-variant sizes (guide "Inputs and sizes" table).
type params struct {
	block  int
	ivLen  int
	macLen int
	newBlk func(key []byte) cipher.Block
}

func (v KexpVariant) params() (params, error) {
	switch v {
	case KexpKuznyechik:
		return params{
			block:  kuznyechikBlock,
			ivLen:  kuznyechikIVLen,
			macLen: kuznyechikMACLen,
			newBlk: func(k []byte) cipher.Block { return kuznyechik.NewCipher(k) },
		}, nil
	case KexpMagma:
		return params{
			block:  magmaBlock,
			ivLen:  magmaIVLen,
			macLen: magmaMACLen,
			newBlk: func(k []byte) cipher.Block { return magma.NewCipher(k) },
		}, nil
	default:
		return params{}, fmt.Errorf("%w: %d", errUnknownVariant, int(v))
	}
}

// Kexp15 wraps the shared key sharedKey (S) under the independent export keys
// cipherKey (K_Exp_ENC, for CTR) and macKey (K_Exp_MAC, for OMAC), with the
// half-block iv. The output is len(sharedKey)+mac_len bytes: the CTR-encrypted
// concatenation of S and the truncated OMAC tag.
//
// cipherKey and macKey must be 32 bytes; iv must be block/2 bytes
// (8 for Kuznyechik, 4 for Magma); sharedKey must be non-empty.
func Kexp15(variant KexpVariant, sharedKey, cipherKey, macKey, iv []byte) ([]byte, error) {
	p, err := variant.params()
	if err != nil {
		return nil, err
	}

	if len(sharedKey) < 1 {
		return nil, errEmptySharedKey
	}

	if len(cipherKey) != exportKeyLen {
		return nil, fmt.Errorf("%w: cipher key, got %d", errBadKeyLen, len(cipherKey))
	}

	if len(macKey) != exportKeyLen {
		return nil, fmt.Errorf("%w: mac key, got %d", errBadKeyLen, len(macKey))
	}

	if len(iv) != p.ivLen {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", errBadIVLen, p.ivLen, len(iv))
	}

	// Step 1: build the full counter from the half-IV — IV in the LOW bytes,
	// zeros in the remainder (gost_keyexpimp.c:63-64).
	ivFull := make([]byte, p.block)
	copy(ivFull, iv)

	// Step 2: CEK_MAC = OMAC(macKey, IV || S), truncated to mac_len.
	macBlock := p.newBlk(macKey)
	m := omac.New(macBlock, p.macLen)

	if _, err := m.Write(iv); err != nil {
		return nil, err
	}

	if _, err := m.Write(sharedKey); err != nil {
		return nil, err
	}

	cekMAC := m.Sum(nil)

	// Step 3: CTR-Encrypt(cipherKey, ivFull) over the contiguous buffer
	// S || CEK_MAC — one continuous keystream across the boundary.
	plain := make([]byte, 0, len(sharedKey)+len(cekMAC))

	plain = append(plain, sharedKey...)
	plain = append(plain, cekMAC...)

	ctrBlock := p.newBlk(cipherKey)
	stream := ctracpkm.NewCTR(ctrBlock, ivFull)
	out := make([]byte, len(plain))
	stream.XORKeyStream(out, plain)

	return out, nil
}

// Compile-time assurance that the underlying ciphers satisfy cipher.Block and
// the CTR stream satisfies cipher.Stream.
var (
	_ cipher.Block  = (*kuznyechik.Cipher)(nil)
	_ cipher.Block  = (*magma.Cipher)(nil)
	_ cipher.Stream = (*ctracpkm.CTR)(nil)
)
