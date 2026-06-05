package x509gost

import (
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"time"

	gost "github.com/bigbes/gostcrypto"
)

var (
	errGOSTRootsEmpty   = errors.New("x509gost: GOST-signed cert but GOSTRoots is empty")
	errCertNotYetValid  = errors.New("x509gost: certificate is not yet valid")
	errCertExpired      = errors.New("x509gost: certificate has expired")
	errMixedChain       = errors.New("x509gost: mixed chain (GOST leaf, non-GOST root) is not supported")
	errNoValidGOSTChain = errors.New("x509gost: certificate verification failed: no valid GOST chain found")
	errVerifyOnNonGOST  = errors.New("x509gost: verifyGOSTSignature called on non-GOST cert")
	errParentNotGOST    = errors.New(
		"x509gost: verifyGOSTSignature: parent is not GOST-signed; mixed chains not supported",
	)
	errUnknownGOSTAlgo     = errors.New("x509gost: unknown GOSTAlgo")
	errGOSTSigVerifyFailed = errors.New("x509gost: GOST signature verification failed")
)

// VerifyOptions controls certificate chain verification.
type VerifyOptions struct {
	// Roots is a stdlib cert pool used for non-GOST root verification.
	Roots *x509.CertPool

	// GOSTRoots are explicit GOST trust anchors. The stdlib pool cannot hold
	// GOST-signed certs because x509 cannot verify their signatures.
	GOSTRoots []*Certificate

	// DNSName, if non-empty, is validated against the leaf's SANs/CN.
	DNSName string

	// CurrentTime, if non-zero, is used for validity period checks.
	// If zero, time.Now() is used.
	CurrentTime time.Time

	// KeyUsages is the set of extended key usages the leaf must satisfy.
	KeyUsages []x509.ExtKeyUsage
}

// toStdlibVerifyOptions converts to a stdlib x509.VerifyOptions.
// Used for the non-GOST path.
func (o VerifyOptions) toStdlibVerifyOptions() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:       o.Roots,
		DNSName:     o.DNSName,
		CurrentTime: o.CurrentTime,
		KeyUsages:   o.KeyUsages,
	}
}

// Verify verifies the certificate chain. The rules are:
//
//   - If the leaf is GOST-signed, a chain must be found from the leaf to one
//     of opts.GOSTRoots. Each edge is verified with the GOST signature
//     algorithm appropriate for that cert. DNS name and validity are checked
//     via the stdlib-parsed fields.
//   - If the leaf is not GOST-signed, verification is delegated entirely to
//     the stdlib x509 package.
//   - Mixed chains (GOST leaf, non-GOST intermediate or root) are not
//     supported and return an explicit error.
//
// The returned chains mirror stdlib's Verify return shape
// ([][]*Certificate); each inner slice is leaf-first, root-last.
func (c *Certificate) Verify(opts VerifyOptions) ([][]*Certificate, error) {
	if !c.IsGOST {
		// Delegate to stdlib entirely.
		stdOpts := opts.toStdlibVerifyOptions()

		stdChains, err := c.Stdlib.Verify(stdOpts)
		if err != nil {
			return nil, err
		}

		// Wrap each stdlib chain in our Certificate type.
		out := make([][]*Certificate, len(stdChains))
		for i, chain := range stdChains {
			wrapped := make([]*Certificate, len(chain))
			for j, sc := range chain {
				wrapped[j] = &Certificate{Stdlib: sc, Raw: sc.Raw}
			}

			out[i] = wrapped
		}

		return out, nil
	}

	// GOST leaf: must be verified against GOSTRoots.
	if len(opts.GOSTRoots) == 0 {
		return nil, errGOSTRootsEmpty
	}

	// Validate validity period.
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	if now.Before(c.Stdlib.NotBefore) {
		return nil, fmt.Errorf(
			"%w (NotBefore=%v, now=%v)",
			errCertNotYetValid, c.Stdlib.NotBefore, now,
		)
	}

	if now.After(c.Stdlib.NotAfter) {
		return nil, fmt.Errorf(
			"%w (NotAfter=%v, now=%v)",
			errCertExpired, c.Stdlib.NotAfter, now,
		)
	}

	// Validate DNS name if requested, using stdlib fields.
	if opts.DNSName != "" {
		err := c.Stdlib.VerifyHostname(opts.DNSName)
		if err != nil {
			return nil, fmt.Errorf("x509gost: hostname verification: %w", err)
		}
	}

	// Attempt to build a chain from leaf to one of the GOST roots.
	// For a self-signed cert the leaf IS the root.
	chain, err := buildGOSTChain(c, opts.GOSTRoots, now)
	if err != nil {
		return nil, err
	}

	return [][]*Certificate{chain}, nil
}

// buildGOSTChain attempts to build a verified chain from leaf up to a root in
// gostRoots. Returns an error if no such chain can be found or verified.
func buildGOSTChain(leaf *Certificate, gostRoots []*Certificate, now time.Time) ([]*Certificate, error) {
	// Check whether the leaf is directly in the root set (self-signed case).
	for _, root := range gostRoots {
		if certEqual(leaf, root) {
			// Self-signed: verify the cert against itself.
			err := verifyGOSTSignature(leaf, leaf)
			if err != nil {
				return nil, fmt.Errorf("x509gost: self-signed GOST cert signature invalid: %w", err)
			}

			return []*Certificate{leaf}, nil
		}
	}

	// Try each root as the signing cert.
	// For a depth-1 chain (leaf signed directly by root):.
	for _, root := range gostRoots {
		// Check non-GOST intermediate guard: if the root is not GOST-signed
		// we refuse (mixed chain is out of scope per the plan).
		if !root.IsGOST {
			return nil, errMixedChain
		}

		// Check if root's subject matches leaf's issuer.
		if !subjectMatchesIssuer(root.Stdlib, leaf.Stdlib) {
			continue
		}

		// Verify root validity.
		if now.Before(root.Stdlib.NotBefore) || now.After(root.Stdlib.NotAfter) {
			continue
		}

		// Verify leaf signature using root's public key.
		err := verifyGOSTSignature(leaf, root)
		if err != nil {
			continue
		}

		return []*Certificate{leaf, root}, nil
	}

	return nil, errNoValidGOSTChain
}

// verifyGOSTSignature verifies the signature on child using the public key
// from parent. The hash algorithm is determined by child's GOSTAlgo field.
//
// The TBSCertificate DER is taken from child.Stdlib.RawTBSCertificate which
// the stdlib parser populates even for GOST-signed certs.
func verifyGOSTSignature(child, parent *Certificate) error {
	if !child.IsGOST {
		return errVerifyOnNonGOST
	}

	if !parent.IsGOST {
		return errParentNotGOST
	}

	tbsData := child.Stdlib.RawTBSCertificate
	sig := child.Stdlib.Signature

	// Hash TBSCertificate using the algorithm implied by GOSTAlgo.
	var h hash.Hash

	switch child.GOSTAlgo {
	case AlgoR341001:
		// GOST R 34.10-2001 uses GOST R 34.11-94 hash.
		h = gost.NewGOSTR341194CryptoProHash()
	case AlgoR341012_256:
		// GOST R 34.10-2012/256 uses Streebog-256.
		h = gost.NewStreebog256Hash()
	case AlgoR341012_512:
		// GOST R 34.10-2012/512 uses Streebog-512.
		h = gost.NewStreebog512Hash()
	default:
		return fmt.Errorf("%w %d", errUnknownGOSTAlgo, int(child.GOSTAlgo))
	}

	h.Write(tbsData)

	digest := h.Sum(nil)

	// Resolve the parent's curve from its parameter OID, then verify.
	curve, err := gost.CurveByOID(parent.CurveOID)
	if err != nil {
		return fmt.Errorf("x509gost: map parent curve OID to GOST curve: %w", err)
	}

	// Digest is verified as-is. Confirmed against Tarantool-EE 3.5.0 certs
	// (Streebog-256 for GOST2012, GOST R 34.11-94 for GOST2001) via
	// TestTarantoolEE_Ping_GOST_Pure — both verify without byte-order massaging.
	valid, err := gost.VerifyDigestOnCurve(curve, parent.PubKeyRaw, digest, sig)
	if err != nil {
		return fmt.Errorf("x509gost: GOST signature verification error: %w", err)
	}

	if !valid {
		return errGOSTSigVerifyFailed
	}

	return nil
}

// subjectMatchesIssuer returns true when parent.RawSubject equals
// child.RawIssuer (byte-for-byte, as per RFC 5280 §4.1.2.4).
func subjectMatchesIssuer(parent, child *x509.Certificate) bool {
	if len(parent.RawSubject) != len(child.RawIssuer) {
		return false
	}

	for i := range parent.RawSubject {
		if parent.RawSubject[i] != child.RawIssuer[i] {
			return false
		}
	}

	return true
}

// certEqual returns true when a and b represent the same certificate
// (by raw bytes).
func certEqual(a, b *Certificate) bool {
	if len(a.Raw) != len(b.Raw) {
		return false
	}

	for i := range a.Raw {
		if a.Raw[i] != b.Raw[i] {
			return false
		}
	}

	return true
}
