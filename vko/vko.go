// Package vko implements the VKO (ВКО) Diffie-Hellman-style key agreement
// for GOST elliptic-curve keys, in both the GOST R 34.10-2001 (RFC 4357 §5.2)
// and GOST R 34.10-2012 (RFC 7836 §4.3) flavours.
//
// One party combines its own private scalar d, the peer's public point Q, and
// a little-endian UKM integer into a single curve point, then hashes that
// point's coordinates (LE(X)||LE(Y)) to produce a Key Encryption Key (KEK).
// The agreement is symmetric: KEK(d_A, Q_B, UKM) == KEK(d_B, Q_A, UKM).
//
// This is a pure-Go, clean-room reimplementation built strictly from
// vko-key-agreement.md. It reuses the sibling clean-room
// packages gost3410curves (curve arithmetic), streebog (GOST R 34.11-2012),
// and gostr341194 (GOST R 34.11-94 CryptoPro) and imports no gogost code.
//
// # References
//
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/vko/rfc/rfc4357.txt
//   - RFC 7836: https://github.com/bigbes/gostcrypto/blob/master/vko/rfc/rfc7836.txt
package vko

import (
	"errors"
	"hash"
	"math/big"

	"github.com/bigbes/gostcrypto/gost3410curves"
	"github.com/bigbes/gostcrypto/gostr341194"
	"github.com/bigbes/gostcrypto/streebog"
)

const (
	// coordsPerPoint is the number of coordinates (X, Y) serialized per point.
	coordsPerPoint = 2
	// hexBase is the radix for parsing the test-curve constant hex strings.
	hexBase = 16
	// cofactor4 is the cofactor of the twisted-Edwards-derived paramsets A/C.
	cofactor4 = 4
)

// ---------------------------------------------------------------------------
// Little-endian helpers (guide §"Sizes and constants", D1/D3/D4).
// ---------------------------------------------------------------------------.

// reverse returns a new slice with the bytes of b in reverse order.
func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}

	return out
}

// leBytes2big interprets b as a little-endian integer.
func leBytes2big(b []byte) *big.Int {
	return new(big.Int).SetBytes(reverse(b))
}

// big2leFixed serializes n as a little-endian fixed-width (size bytes) slice.
// n must be non-negative and fit in size bytes.
func big2leFixed(n *big.Int, size int) []byte {
	be := n.Bytes() // big-endian, minimal.
	out := make([]byte, size)
	// Copy be into the high end of a big-endian fixed buffer, then reverse.
	beFixed := make([]byte, size)
	copy(beFixed[size-len(be):], be)

	for i := range beFixed {
		out[size-1-i] = beFixed[i]
	}

	return out
}

// ---------------------------------------------------------------------------
// Key material decode (guide steps 3/4, deltas D1/D3/D7).
// ---------------------------------------------------------------------------.

var (
	errZeroPrivate = errors.New("vko: private key is zero mod q")
	errBadPubLen   = errors.New("vko: public key has wrong length")
	errBadPrivLen  = errors.New("vko: private key has wrong length")
	errZeroUKM     = errors.New("vko: UKM is zero")
	errPubNotOn    = errors.New("vko: public point is not on the curve")
	errIdentity    = errors.New("vko: agreement point is the identity")
	errDerivedID   = errors.New("vko: derived public point is the identity")
)

// loadPrivateLE reverses a little-endian scalar, rejects zero, and reduces it
// mod the subgroup order q (guide D7, private.go:32-46).
func loadPrivateLE(c *gost3410curves.Curve, raw []byte) (*big.Int, error) {
	size := c.PointSize()
	if len(raw) != size {
		return nil, errBadPrivLen
	}

	d := leBytes2big(raw)
	if d.Sign() == 0 {
		return nil, errZeroPrivate
	}

	d.Mod(d, c.Q)

	if d.Sign() == 0 {
		return nil, errZeroPrivate
	}

	return d, nil
}

// loadPublicLE decodes a 2*pointSize little-endian buffer as the public point.
// Per guide D3: X = LE(raw[:size]), Y = LE(raw[size:]).
func loadPublicLE(c *gost3410curves.Curve, raw []byte) (gost3410curves.Point, error) {
	size := c.PointSize()
	if len(raw) != 2*size {
		return gost3410curves.Point{}, errBadPubLen
	}

	x := leBytes2big(raw[:size])
	y := leBytes2big(raw[size:])
	p := gost3410curves.Point{X: x, Y: y}

	if !c.IsOnCurve(p) {
		return gost3410curves.Point{}, errPubNotOn
	}

	return p, nil
}

// ---------------------------------------------------------------------------
// Cofactors (guide D2). The curves package now carries a Cofactor field, so the
// VKO layer reads it directly. All CryptoPro paramsets and tc26-512-A/B have
// Cofactor==1; tc26-256-A and tc26-512-C have Cofactor==4 (twisted-Edwards
// derived). A zero Cofactor (hand-built curve) is treated as 1 for safety.
// ---------------------------------------------------------------------------.

func cofactor(c *gost3410curves.Curve) *big.Int {
	if c.Cofactor == cofactor4 {
		return big.NewInt(cofactor4)
	}

	return big.NewInt(1)
}

// ---------------------------------------------------------------------------
// Core agreement (guide §"Common structure", step 6, deltas D2/D8).
// ---------------------------------------------------------------------------.

// agreementRaw computes the serialized agreement point LE(K_x)||LE(K_y).
//
// Following gogost's factoring (guide D2): K1 = d·Q, u = UKM·cofactor, and if
// u != 1 then K = u·K1, else K = K1. UKM is treated as immutable.
//
// VKO-62 reduction: u is reduced modulo the full group order (cofactor·q)
// before the ScalarMult. This bounds the ScalarMult cost to O(bitLen(cofactor·q))
// regardless of how large the UKM is, while preserving the KEK exactly:
// ord(K1) divides cofactor·q for every point on the curve, so
// (u mod cofactor·q)·K1 == u·K1 exactly, including torsion components on the
// cofactor-4 curves. The cofactor must not be double-applied.
func agreementRaw(c *gost3410curves.Curve, d, ukm *big.Int, q gost3410curves.Point) ([]byte, error) {
	if ukm.Sign() == 0 {
		return nil, errZeroUKM
	}

	// K1 = d·Q.
	k1 := c.ScalarMult(d, q)
	if k1.IsInfinity() {
		return nil, errIdentity
	}

	// u = UKM · cofactor, reduced mod fullGroupOrder = cofactor·q.
	// The reduction is KEK-preserving: ord(K1) | cofactor·q.
	cof := cofactor(c)
	u := new(big.Int).Mul(ukm, cof)
	fullOrder := new(big.Int).Mul(cof, c.Q)
	u.Mod(u, fullOrder)

	if u.Sign() == 0 {
		// u·K1 would be the identity; same failure the post-ScalarMult
		// IsInfinity check reports.
		return nil, errIdentity
	}

	var k gost3410curves.Point

	if u.Cmp(big.NewInt(1)) == 0 {
		k = k1
	} else {
		k = c.ScalarMult(u, k1)
	}

	if k.IsInfinity() {
		return nil, errIdentity
	}

	size := c.PointSize()
	out := make([]byte, 0, coordsPerPoint*size)

	out = append(out, big2leFixed(k.X, size)...)
	out = append(out, big2leFixed(k.Y, size)...)

	return out, nil
}

// kek runs the full pipeline: decode key material, compute the agreement
// point, and hash LE(K_x)||LE(K_y) with the provided hash constructor.
func kek(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte, newHash func() hash.Hash) ([]byte, error) {
	d, err := loadPrivateLE(c, prvLE)
	if err != nil {
		return nil, err
	}

	q, err := loadPublicLE(c, pubLE)
	if err != nil {
		return nil, err
	}

	ukm := leBytes2big(ukmRaw) // D1: wire UKM is little-endian.

	raw, err := agreementRaw(c, d, ukm, q)
	if err != nil {
		return nil, err
	}

	h := newHash()
	h.Write(raw)

	return h.Sum(nil), nil
}

// ---------------------------------------------------------------------------
// Public API. Variant constructors mirror the internal/gost oracle: the bare
// VKO2012_256 / VKO2012_512 default to the 512-bit paramSetA, and
// VKO2001TestCurve pins the 2001 test paramset.
// ---------------------------------------------------------------------------.

// KEK2001 computes VKO GOST R 34.10-2001 (RFC 4357 §5.2): the agreement point
// hashed with GOST R 34.11-94 (CryptoPro S-box). 32-byte KEK.
func KEK2001(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error) {
	return kek(c, prvLE, pubLE, ukmRaw, gostr341194.New)
}

// KEK2012256 computes VKO GOST R 34.10-2012 with a Streebog-256 KEK
// (RFC 7836 §4.3). 32-byte KEK.
func KEK2012256(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error) {
	return kek(c, prvLE, pubLE, ukmRaw, streebog.New256)
}

// KEK2012512 computes VKO GOST R 34.10-2012 with a Streebog-512 KEK
// (RFC 7836 §4.3). 64-byte KEK.
func KEK2012512(c *gost3410curves.Curve, prvLE, pubLE, ukmRaw []byte) ([]byte, error) {
	return kek(c, prvLE, pubLE, ukmRaw, streebog.New512)
}

// curve2001Test is id-GostR3410-2001-TestParamSet (RFC 4357 §11.4),
// the cofactor-1 test curve used by the 2001 inline KAT.
func curve2001Test() *gost3410curves.Curve {
	mustHex := func(s string) *big.Int {
		n, ok := new(big.Int).SetString(s, hexBase)
		if !ok {
			panic("vko: bad test-curve hex " + s)
		}

		return n
	}

	return &gost3410curves.Curve{
		P:        mustHex("8000000000000000000000000000000000000000000000000000000000000431"),
		A:        mustHex("0000000000000000000000000000000000000000000000000000000000000007"),
		B:        mustHex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
		Q:        mustHex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
		X:        mustHex("0000000000000000000000000000000000000000000000000000000000000002"),
		Y:        mustHex("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
		Name:     "id-GostR3410-2001-TestParamSet",
		Cofactor: 1,
	}
}

// Curve2001Test returns a fresh id-GostR3410-2001-TestParamSet curve.
func Curve2001Test() *gost3410curves.Curve { return curve2001Test() }

// Curve2012ParamSetA returns a fresh id-tc26-gost-3410-12-512-paramSetA curve.
func Curve2012ParamSetA() *gost3410curves.Curve { return curve2012paramSetA() }

// DeriveQLE returns the LE-encoded public point d·P (LE(X)||LE(Y)) for a
// little-endian private scalar dLE on curve c. Used by tests to feed both an
// implementation and a reference oracle the same peer point.
func DeriveQLE(c *gost3410curves.Curve, dLE []byte) ([]byte, error) {
	d, err := loadPrivateLE(c, dLE)
	if err != nil {
		return nil, err
	}

	q := c.ScalarMult(d, c.Base())
	if q.IsInfinity() {
		return nil, errDerivedID
	}

	size := c.PointSize()
	out := make([]byte, 0, coordsPerPoint*size)

	out = append(out, big2leFixed(q.X, size)...)
	out = append(out, big2leFixed(q.Y, size)...)

	return out, nil
}

// curve2012paramSetA is id-tc26-gost-3410-12-512-paramSetA, the cofactor-1
// 512-bit curve used by the 2012 inline KAT and the VKO2012_* defaults.
func curve2012paramSetA() *gost3410curves.Curve {
	c, err := gost3410curves.CurveByOID("1.2.643.7.1.2.1.2.1")
	if err != nil {
		panic("vko: 512-paramSetA missing: " + err.Error())
	}

	return c
}

// VKO2001TestCurve computes the 2001 KEK on the fixed test paramset. Mirrors
// internal/gost.VKO2001TestCurve.
func VKO2001TestCurve(prvLE, pubLE, ukmRaw []byte) ([]byte, error) {
	return KEK2001(curve2001Test(), prvLE, pubLE, ukmRaw)
}

// VKO2012_256 computes the 2012 256-bit KEK on the default 512-bit paramSetA.
// Mirrors internal/gost.VKO2012_256.
func VKO2012_256(prvLE, pubLE, ukmRaw []byte) ([]byte, error) {
	return KEK2012256(curve2012paramSetA(), prvLE, pubLE, ukmRaw)
}

// VKO2012_512 computes the 2012 512-bit KEK on the default 512-bit paramSetA.
// Mirrors internal/gost.VKO2012_512.
func VKO2012_512(prvLE, pubLE, ukmRaw []byte) ([]byte, error) {
	return KEK2012512(curve2012paramSetA(), prvLE, pubLE, ukmRaw)
}
