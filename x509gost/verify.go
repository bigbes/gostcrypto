package x509gost

import (
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"slices"
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
	errLeafEKUMismatch     = errors.New(
		"x509gost: leaf does not satisfy the requested extended key usages",
	)
)

// VerifyOptions controls certificate chain verification.
type VerifyOptions struct {
	// Roots is a stdlib cert pool used for non-GOST root verification.
	Roots *x509.CertPool

	// GOSTRoots are explicit GOST trust anchors. The stdlib pool cannot hold
	// GOST-signed certs because x509 cannot verify their signatures.
	GOSTRoots []*Certificate

	// GOSTIntermediates is an optional pool of GOST-signed intermediate CA
	// certificates used to bridge the leaf to a root in GOSTRoots, mirroring
	// the role of stdlib's VerifyOptions.Intermediates. Leave nil for a
	// direct leaf-signed-by-root (depth-1) chain. Chains are built up to a
	// fixed maximum depth (see maxGOSTChainDepth).
	GOSTIntermediates []*Certificate

	// DNSName, if non-empty, is validated against the leaf's SANs/CN.
	DNSName string

	// CurrentTime, if non-zero, is used for validity period checks.
	// If zero, time.Now() is used.
	CurrentTime time.Time

	// KeyUsages is the set of extended key usages the leaf must satisfy.
	//
	// On the GOST path the leaf passes the EKU check when any of the
	// following holds: KeyUsages is empty (no constraint requested);
	// KeyUsages contains x509.ExtKeyUsageAny; the leaf carries no EKU
	// extension (an unconstrained leaf); or at least one requested usage is
	// present in the leaf's ExtKeyUsage. Note that, unlike a common stdlib
	// convenience, an empty KeyUsages does NOT imply ServerAuth here.
	KeyUsages []x509.ExtKeyUsage
}

// maxGOSTChainDepth bounds GOST chain building (leaf included) to keep the
// search finite and to refuse pathologically deep hierarchies.
const maxGOSTChainDepth = 8

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
//     of opts.GOSTRoots, optionally traversing GOST-signed intermediates from
//     opts.GOSTIntermediates. Each edge is verified with the GOST signature
//     algorithm of the signed (child) certificate. DNS name and validity are
//     checked via the stdlib-parsed fields, and opts.KeyUsages is enforced
//     against the leaf's extended key usages (see KeyUsages for the exact
//     semantics).
//   - If the leaf is not GOST-signed, verification is delegated entirely to
//     the stdlib x509 package.
//   - Mixed chains (a GOST leaf chaining through a non-GOST intermediate or
//     root) are not supported; non-GOST entries in the GOST pools are skipped
//     and only contribute to the explicit mixed-chain error when no all-GOST
//     chain exists.
//
// Chain building is depth-bounded: at most maxGOSTChainDepth certificates
// (leaf included) are traversed. Hierarchies deeper than that will not verify.
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

	// Enforce the requested extended key usages on the leaf. stdlib forwards
	// opts.KeyUsages on the non-GOST path; the GOST path must do the same so
	// the documented contract holds for GOST leaves too.
	if !leafSatisfiesKeyUsages(c.Stdlib, opts.KeyUsages) {
		return nil, errLeafEKUMismatch
	}

	// Attempt to build a chain from leaf to one of the GOST roots, optionally
	// via GOST intermediates. For a self-signed cert the leaf IS the root.
	chain, err := buildGOSTChain(c, opts.GOSTRoots, opts.GOSTIntermediates, now)
	if err != nil {
		return nil, err
	}

	return [][]*Certificate{chain}, nil
}

// leafSatisfiesKeyUsages reports whether leaf passes the requested extended
// key usage constraints. The semantics match the doc on
// VerifyOptions.KeyUsages: an empty request, an ExtKeyUsageAny request, a leaf
// with no EKU extension, or any single requested usage being present all pass.
func leafSatisfiesKeyUsages(leaf *x509.Certificate, requested []x509.ExtKeyUsage) bool {
	if len(requested) == 0 {
		return true
	}

	// A leaf with no EKU extension is unconstrained.
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return true
	}

	for _, want := range requested {
		if want == x509.ExtKeyUsageAny {
			return true
		}

		if slices.Contains(leaf.ExtKeyUsage, want) {
			return true
		}
	}

	return false
}

// issuerIsCA reports whether parent is permitted to sign other certificates.
// When the BasicConstraints extension is present it must assert IsCA; when the
// KeyUsage extension is present it must include KeyUsageCertSign. Absent
// extensions are permitted (older GOST CAs frequently omit them), matching the
// permissive-when-unset posture the rest of this package takes.
func issuerIsCA(parent *x509.Certificate) bool {
	if parent.BasicConstraintsValid && !parent.IsCA {
		return false
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}

	return true
}

// buildGOSTChain attempts to build a verified chain from leaf up to a root in
// gostRoots, optionally bridging through GOST intermediates. Returns an error
// if no such chain can be found or verified.
//
// Non-GOST entries in either pool are skipped (a GOST chain cannot pass
// through a non-GOST link); the mixed-chain error is reported only when the
// search exhausts every candidate without finding any GOST path — so a single
// non-GOST root no longer makes verification order-dependent (X509-66).
func buildGOSTChain(
	leaf *Certificate,
	gostRoots, gostIntermediates []*Certificate,
	now time.Time,
) ([]*Certificate, error) {
	// Check whether the leaf is directly in the root set (self-signed case).
	for _, root := range gostRoots {
		if !root.IsGOST {
			continue
		}

		if certEqual(leaf, root) {
			// Self-signed: verify the cert against itself.
			err := verifyGOSTSignature(leaf, leaf)
			if err != nil {
				return nil, fmt.Errorf("x509gost: self-signed GOST cert signature invalid: %w", err)
			}

			return []*Certificate{leaf}, nil
		}
	}

	// sawNonGOST tracks whether any non-GOST candidate was skipped, so a
	// failed search can report the mixed-chain error instead of the generic
	// no-chain error when the only obstruction was a non-GOST link.
	sawNonGOST := false

	chain := buildGOSTChainRec(leaf, gostRoots, gostIntermediates, now, maxGOSTChainDepth, &sawNonGOST)
	if chain != nil {
		return chain, nil
	}

	if sawNonGOST {
		return nil, errMixedChain
	}

	return nil, errNoValidGOSTChain
}

// buildGOSTChainRec recursively extends the chain from child up to a root,
// honoring a maximum depth. It returns the leaf-first, root-last chain rooted
// at child on success, or nil when no chain can be completed within depthLeft
// links. depthLeft counts the certificates that may still be appended,
// including child itself.
func buildGOSTChainRec(
	child *Certificate,
	gostRoots, gostIntermediates []*Certificate,
	now time.Time,
	depthLeft int,
	sawNonGOST *bool,
) []*Certificate {
	if depthLeft <= 0 {
		return nil
	}

	// First, try to terminate the chain at a root that signed child directly.
	for _, root := range gostRoots {
		if !root.IsGOST {
			*sawNonGOST = true
			continue
		}

		if !signerOf(root, child, now) {
			continue
		}

		return []*Certificate{child, root}
	}

	// Otherwise, try to bridge through a GOST intermediate. Each intermediate
	// must itself chain to a root within the remaining depth.
	for _, inter := range gostIntermediates {
		if !inter.IsGOST {
			*sawNonGOST = true
			continue
		}

		// An intermediate cannot be its own issuer in this walk, and must not
		// re-appear (cheap loop guard via raw-byte identity).
		if certEqual(inter, child) {
			continue
		}

		if !signerOf(inter, child, now) {
			continue
		}

		rest := buildGOSTChainRec(inter, gostRoots, gostIntermediates, now, depthLeft-1, sawNonGOST)
		if rest != nil {
			return append([]*Certificate{child}, rest...)
		}
	}

	return nil
}

// signerOf reports whether parent is a valid, currently-valid GOST CA whose
// public key verifies child's signature and whose subject matches child's
// issuer. It enforces the issuer CA constraints (BasicConstraints.IsCA /
// KeyUsageCertSign when present).
func signerOf(parent, child *Certificate, now time.Time) bool {
	if !subjectMatchesIssuer(parent.Stdlib, child.Stdlib) {
		return false
	}

	if now.Before(parent.Stdlib.NotBefore) || now.After(parent.Stdlib.NotAfter) {
		return false
	}

	if !issuerIsCA(parent.Stdlib) {
		return false
	}

	return verifyGOSTSignature(child, parent) == nil
}

// verifyGOSTSignature verifies the signature on child using the public key
// from parent. The hash algorithm is determined by child's SIGNATURE
// algorithm (SigGOSTAlgo / the signwithdigest OID), not by the subject key's
// strength: per RFC 9215 §2 the signwithdigest OID dictates the digest
// computed over TBSCertificate, so a 256-bit subject key signed by a 512-bit
// CA is hashed with Streebog-512. (child.GOSTAlgo, the subject-key family, is
// reserved for key parsing / the VKO-KEX role.)
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

	// Hash TBSCertificate using the algorithm implied by the signature OID.
	var h hash.Hash

	switch child.SigGOSTAlgo {
	case AlgoR341001:
		// GOST R 34.10-2001 uses GOST R 34.11-94 hash.
		h = gost.NewGOSTR341194CryptoProHash()
	case AlgoR341012_256:
		// signwithdigest-gost3410-12-256 uses Streebog-256.
		h = gost.NewStreebog256Hash()
	case AlgoR341012_512:
		// signwithdigest-gost3410-12-512 uses Streebog-512.
		h = gost.NewStreebog512Hash()
	default:
		return fmt.Errorf("%w %d", errUnknownGOSTAlgo, int(child.SigGOSTAlgo))
	}

	h.Write(tbsData)

	digest := h.Sum(nil)

	// GOST signing treats the hash as a little-endian integer (GOST R 34.10
	// §6.1 "alpha"), but gost.VerifyDigestOnCurve reads the digest big-endian
	// (RFC 7091 §5.3, see gost3410sign.VerifyDigest). The hash.Hash.Sum output
	// is the natural (big-endian-displayed) digest, so it must be byte-reversed
	// before verification to match the integer the signer used. This was
	// empirically established against externally-generated certs (OpenSSL 3 +
	// gost-engine 3.0.3) by TestVerify_GOST_ExternalFixture /
	// TestVerify_GOST_ExternalChain: with the reversed digest they verify, with
	// the raw digest they do not.
	//
	// (The Tarantool-EE pure-Go interop test exercises only the GOST VKO KEX
	// and an RSA-signed chain — its CA is RSA — so it never reaches this code
	// path; the previous comment claiming it confirmed the as-is digest here
	// was incorrect.)
	digestLE := make([]byte, len(digest))
	for i := range digest {
		digestLE[len(digest)-1-i] = digest[i]
	}

	// Resolve the parent's curve from its parameter OID, then verify.
	curve, err := gost.CurveByOID(parent.CurveOID)
	if err != nil {
		return fmt.Errorf("x509gost: map parent curve OID to GOST curve: %w", err)
	}

	valid, err := gost.VerifyDigestOnCurve(curve, parent.PubKeyRaw, digestLE, sig)
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
