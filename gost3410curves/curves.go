// Package gost3410curves is a clean-room implementation of the GOST R 34.10
// elliptic-curve parameter sets (CryptoPro 2001 + TC26 2012) and the core
// short-Weierstrass affine point arithmetic that consumes them.
//
// The parameters (p, a, b, q, x, y) are transcribed verbatim from
// gost3410-curves.md §2.4 (sourced from RFC 4357 §11 and
// RFC 7836 §5 / Appendix A). All constants are big-endian integers and are
// never byte-reversed: per §3.1 only key/signature *wire* serialization is
// little-endian, the curve constants stay big-endian.
//
// Twisted-Edwards sets (tc26-256-A, tc26-512-C) are stored in their
// birationally-equivalent short-Weierstrass form per §3.3 — the (e,d) pair is
// omitted since signature/VKO never touch it.
//
// # References
//
//   - RFC 4357: https://github.com/bigbes/gostcrypto/blob/master/gost3410curves/rfc/rfc4357.txt
//   - RFC 7836: https://github.com/bigbes/gostcrypto/blob/master/gost3410curves/rfc/rfc7836.txt
package gost3410curves

import (
	"errors"
	"fmt"
	"math/big"
)

// errUnknownCurveOID is returned by CurveByOID for an OID arc that is not one
// of the ten supported parameter sets.
var errUnknownCurveOID = errors.New("gost3410curves: unknown curve OID")

const (
	// hexBase is the radix passed to big.Int.SetString for the big-endian
	// hex curve constants.
	hexBase = 16

	// bits256 is the field-size threshold (in bits) separating the 256-bit
	// curves from the 512-bit ones, per §3.2.
	bits256 = 256

	// pointSize256 / pointSize512 are the serialized coordinate sizes (bytes)
	// for sub-256-bit and larger fields respectively.
	pointSize256 = 32
	pointSize512 = 64

	// doublingXCoeff is the constant 3 in the doubling slope (3·x² + a)/(2·y).
	doublingXCoeff = 3

	// cofactor4 is the cofactor for the twisted-Edwards-derived TC26 curves
	// (tc26-256-A and tc26-512-C). All other registered sets have Cofactor 1.
	cofactor4 = 4
)

// Curve is a GOST R 34.10 short-Weierstrass curve parameter set:
//
//	y² = x³ + a·x + b   (mod P)
//
// over the prime field GF(P), with a base point (X, Y) generating a cyclic
// subgroup of prime order Q.
//
// Cofactor is the cofactor h of the curve (i.e. #E(GF(P)) = h·Q).
// For every registered CryptoPro/TC26 parameter set Cofactor is either 1 or 4:
//   - Cofactor == 1 for all CryptoPro-A/B/C sets and for tc26-512-A/B.
//   - Cofactor == 4 for tc26-256-A and tc26-512-C (twisted-Edwards derived).
//
// The (e,d) pair of the Twisted-Edwards representation is omitted since
// signature/VKO never require it.
type Curve struct {
	P        *big.Int // field characteristic (prime).
	A        *big.Int // Weierstrass coefficient a.
	B        *big.Int // Weierstrass coefficient b.
	Q        *big.Int // order of the base-point subgroup (prime).
	X        *big.Int // base-point affine X.
	Y        *big.Int // base-point affine Y.
	Name     string
	Cofactor int // cofactor h: #E = h·Q; always 1 or 4 for registered sets.
}

// Point is an affine curve point. The identity (point at infinity) is
// represented by (nil, nil).
type Point struct {
	X, Y *big.Int
}

// IsInfinity reports whether p is the point at infinity (the group identity).
func (p Point) IsInfinity() bool {
	return p.X == nil && p.Y == nil
}

// hexInt parses a big-endian hex string (whitespace ignored) into a *big.Int.
func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(stripWS(s), hexBase)
	if !ok {
		panic("gost3410curves: bad hex constant: " + s)
	}

	return n
}

func stripWS(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
			continue
		}

		out = append(out, c)
	}

	return string(out)
}

// PointSize returns the serialized coordinate size in bytes, derived purely
// from P.BitLen() (§3.2): 32 if P fits in 256 bits, else 64.
func (c *Curve) PointSize() int {
	if c.P.BitLen() > bits256 {
		return pointSize512
	}

	return pointSize256
}

// ---------------------------------------------------------------------------
// Parameter tables (§2.4) — big-endian, never reversed.
// ---------------------------------------------------------------------------.

// CryptoPro-A (= tc26-256-B), co = 1, Weierstrass.
func curveCryptoProA() *Curve {
	return &Curve{
		P:        hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
		A:        hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
		B:        hexInt("00000000000000000000000000000000000000000000000000000000000000A6"),
		Q:        hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
		X:        hexInt("0000000000000000000000000000000000000000000000000000000000000001"),
		Y:        hexInt("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
		Name:     "id-GostR3410-2001-CryptoPro-A-ParamSet",
		Cofactor: 1,
	}
}

// CryptoPro-B (= tc26-256-C), co = 1, Weierstrass.
func curveCryptoProB() *Curve {
	return &Curve{
		P:        hexInt("8000000000000000000000000000000000000000000000000000000000000C99"),
		A:        hexInt("8000000000000000000000000000000000000000000000000000000000000C96"),
		B:        hexInt("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"),
		Q:        hexInt("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"),
		X:        hexInt("0000000000000000000000000000000000000000000000000000000000000001"),
		Y:        hexInt("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"),
		Name:     "id-GostR3410-2001-CryptoPro-B-ParamSet",
		Cofactor: 1,
	}
}

// CryptoPro-C (= tc26-256-D), co = 1, Weierstrass.
// NOTE: the stored Q is the full group order (same bit-length as P), so the
// cofactor is 1. An earlier comment in this file incorrectly said "co = 4" —
// that is mathematically impossible for this curve (4·Q would exceed the
// Hasse bound p+1±2√p). VKO also assigns cofactor 1 here; see vko.go and
// the VKO-63 finding for the analysis.
func curveCryptoProC() *Curve {
	return &Curve{
		P:        hexInt("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B"),
		A:        hexInt("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"),
		B:        hexInt("000000000000000000000000000000000000000000000000000000000000805A"),
		Q:        hexInt("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"),
		X:        hexInt("0000000000000000000000000000000000000000000000000000000000000000"),
		Y:        hexInt("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"),
		Name:     "id-GostR3410-2001-CryptoPro-C-ParamSet",
		Cofactor: 1,
	}
}

// tc26-256-A, co = 4, twisted Edwards (stored as Weierstrass).
// Q is the prime subgroup order (= m/4); the full group order is 4·Q.
func curveTc26256A() *Curve {
	return &Curve{
		P:        hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
		A:        hexInt("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
		B:        hexInt("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
		Q:        hexInt("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
		X:        hexInt("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
		Y:        hexInt("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
		Name:     "id-tc26-gost-3410-12-256-paramSetA",
		Cofactor: cofactor4,
	}
}

// tc26-512-A, co = 1, Weierstrass.
func curveTc26512A() *Curve {
	return &Curve{
		P: hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
		A: hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
		B: hexInt("E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265" +
			"EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
		Q: hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
			"27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
		X: hexInt("0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000003"),
		Y: hexInt("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921" +
			"DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
		Name:     "id-tc26-gost-3410-12-512-paramSetA",
		Cofactor: 1,
	}
}

// tc26-512-B, co = 1, Weierstrass.
func curveTc26512B() *Curve {
	return &Curve{
		P: hexInt("8000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000006F"),
		A: hexInt("8000000000000000000000000000000000000000000000000000000000000000" +
			"000000000000000000000000000000000000000000000000000000000000006C"),
		B: hexInt("687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F" +
			"3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"),
		Q: hexInt("8000000000000000000000000000000000000000000000000000000000000001" +
			"49A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"),
		X: hexInt("0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000002"),
		Y: hexInt("1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335" +
			"DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"),
		Name:     "id-tc26-gost-3410-12-512-paramSetB",
		Cofactor: 1,
	}
}

// tc26-512-C, co = 4, twisted Edwards (stored as Weierstrass).
// Q is the prime subgroup order (= m/4); the full group order is 4·Q.
func curveTc26512C() *Curve {
	return &Curve{
		P: hexInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
		A: hexInt("DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645" +
			"46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"),
		B: hexInt("B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE0" +
			"38CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1"),
		// Q is the prime subgroup order (= m/4) per RFC 7836 App. A.2,
		// matching guide §2.4 tc26-512-C; verified by ScalarMult(Q, G) == ∞.
		Q: hexInt("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" +
			"C98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED"),
		X: hexInt("E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043A" +
			"A27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148"),
		Y: hexInt("F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9B" +
			"E18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"),
		Name:     "id-tc26-gost-3410-12-512-paramSetC",
		Cofactor: cofactor4,
	}
}

// CurveByOID resolves one of the ten supported OID arcs (dotted-decimal
// string) to its parameter set. The 2001 CryptoPro 256-bit sets are identical
// curves to three of the tc26 2012 256-bit sets (§3.4), so those arcs share
// constants but each returns a fresh *Curve.
func CurveByOID(oid string) (*Curve, error) {
	switch oid {
	// CryptoPro 2001, 256-bit (1.2.643.2.2.35.x).
	case "1.2.643.2.2.35.1":
		return curveCryptoProA(), nil
	case "1.2.643.2.2.35.2":
		return curveCryptoProB(), nil
	case "1.2.643.2.2.35.3":
		return curveCryptoProC(), nil

	// TC26 2012, 256-bit (1.2.643.7.1.2.1.1.x).
	case "1.2.643.7.1.2.1.1.1": // tc26-256-A.
		return curveTc26256A(), nil
	case "1.2.643.7.1.2.1.1.2": // tc26-256-B == CryptoPro-A.
		c := curveCryptoProA()

		c.Name = "id-tc26-gost-3410-12-256-paramSetB"

		return c, nil
	case "1.2.643.7.1.2.1.1.3": // tc26-256-C == CryptoPro-B.
		c := curveCryptoProB()

		c.Name = "id-tc26-gost-3410-12-256-paramSetC"

		return c, nil
	case "1.2.643.7.1.2.1.1.4": // tc26-256-D == CryptoPro-C.
		c := curveCryptoProC()

		c.Name = "id-tc26-gost-3410-12-256-paramSetD"

		return c, nil

	// TC26 2012, 512-bit (1.2.643.7.1.2.1.2.x).
	case "1.2.643.7.1.2.1.2.1":
		return curveTc26512A(), nil
	case "1.2.643.7.1.2.1.2.2":
		return curveTc26512B(), nil
	case "1.2.643.7.1.2.1.2.3":
		return curveTc26512C(), nil
	}

	return nil, fmt.Errorf("%w: %q", errUnknownCurveOID, oid)
}

// ---------------------------------------------------------------------------
// Short-Weierstrass affine point arithmetic over GF(P).
// ---------------------------------------------------------------------------.

// Base returns the curve's base point G = (X, Y).
func (c *Curve) Base() Point {
	return Point{X: new(big.Int).Set(c.X), Y: new(big.Int).Set(c.Y)}
}

// IsOnCurve reports whether p satisfies y² ≡ x³ + a·x + b (mod P).
// The point at infinity is considered on the curve.
func (c *Curve) IsOnCurve(p Point) bool {
	if p.IsInfinity() {
		return true
	}

	// Coordinates must be reduced and in range.
	if p.X.Sign() < 0 || p.X.Cmp(c.P) >= 0 || p.Y.Sign() < 0 || p.Y.Cmp(c.P) >= 0 {
		return false
	}

	// left = y² mod P.
	left := new(big.Int).Mul(p.Y, p.Y)
	left.Mod(left, c.P)

	// right = x³ + a·x + b mod P.
	right := new(big.Int).Mul(p.X, p.X)
	right.Mod(right, c.P)
	right.Mul(right, p.X)

	ax := new(big.Int).Mul(c.A, p.X)
	right.Add(right, ax)
	right.Add(right, c.B)
	right.Mod(right, c.P)

	return left.Cmp(right) == 0
}

// Add returns p + q on the curve (affine short-Weierstrass addition).
//
// Precondition: both p and q must be either the point at infinity (nil, nil)
// or reduced, on-curve points (0 ≤ X, Y < P, y²≡x³+ax+b mod P). Passing
// unreduced or off-curve coordinates yields a silently garbage result — the
// arithmetic does not detect the violation. Callers with untrusted input must
// gate with IsOnCurve before calling Add.
func (c *Curve) Add(p, q Point) Point {
	if p.IsInfinity() {
		return clonePoint(q)
	}

	if q.IsInfinity() {
		return clonePoint(p)
	}

	// If x coordinates are equal:.
	if p.X.Cmp(q.X) == 0 {
		// If y's sum is 0 mod P (i.e. q = -p), result is the identity.
		ySum := new(big.Int).Add(p.Y, q.Y)
		ySum.Mod(ySum, c.P)

		if ySum.Sign() == 0 {
			return Point{} // identity.
		}

		// Otherwise p == q → doubling.
		return c.Double(p)
	}

	// lambda = (q.Y - p.Y) / (q.X - p.X) mod P.
	num := new(big.Int).Sub(q.Y, p.Y)
	num.Mod(num, c.P)

	den := new(big.Int).Sub(q.X, p.X)
	den.Mod(den, c.P)
	den.ModInverse(den, c.P)

	lambda := num.Mul(num, den)
	lambda.Mod(lambda, c.P)

	return c.fromLambda(lambda, p, q)
}

// Double returns 2·p on the curve.
//
// Precondition: p must be the point at infinity or a reduced, on-curve point.
// See Add for the garbage-in/garbage-out hazard and the IsOnCurve gate.
func (c *Curve) Double(p Point) Point {
	if p.IsInfinity() {
		return Point{}
	}

	// If y == 0, the tangent is vertical → identity.
	if p.Y.Sign() == 0 {
		return Point{}
	}

	// lambda = (3·x² + a) / (2·y) mod P.
	num := new(big.Int).Mul(p.X, p.X)
	num.Mul(num, big.NewInt(doublingXCoeff))
	num.Add(num, c.A)
	num.Mod(num, c.P)

	den := new(big.Int).Lsh(p.Y, 1) // 2·y.
	den.Mod(den, c.P)
	den.ModInverse(den, c.P)

	lambda := num.Mul(num, den)
	lambda.Mod(lambda, c.P)

	return c.fromLambda(lambda, p, p)
}

// ScalarMult returns k·p via left-to-right double-and-add.
//
// NOT CONSTANT-TIME. The loop branches on the bits of k (k.Bit(i)) and uses
// math/big arithmetic, so both timing and memory-access pattern depend on the
// secret scalar. gost3410sign feeds the per-signature nonce k here and vko/keg
// feed the private key d — both SECRET — so this is a real side-channel
// surface. It is acceptable for a reference/clean-room implementation and for
// verification (public scalars), but a production signer or key-agreement must
// replace this with a constant-time implementation — see SECURITY.md in this
// package for exactly what that entails.
//
// k is not reduced (the caller's responsibility). k <= 0 returns the identity;
// this is a guard, not a definition — callers pass k in [1, Q-1].
//
// Precondition: p must be a reduced, on-curve point (or the identity). Passing
// an off-curve point silently multiplies on the attacker's curve (invalid-curve
// attack shape). Callers with untrusted input must gate with IsOnCurve; see Add.
func (c *Curve) ScalarMult(k *big.Int, p Point) Point {
	if k == nil || k.Sign() <= 0 || p.IsInfinity() {
		return Point{}
	}

	result := Point{} // identity.
	// Iterate bits from most-significant to least-significant.
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = c.Double(result)
		if k.Bit(i) == 1 {
			result = c.Add(result, p)
		}
	}

	return result
}

// fromLambda computes the resulting point from a chord/tangent slope lambda:
//
//	x3 = lambda² - p.X - q.X
//	y3 = lambda·(p.X - x3) - p.Y
func (c *Curve) fromLambda(lambda *big.Int, p, q Point) Point {
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, p.X)
	x3.Sub(x3, q.X)
	x3.Mod(x3, c.P)

	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, c.P)

	return Point{X: x3, Y: y3}
}

func clonePoint(p Point) Point {
	if p.IsInfinity() {
		return Point{}
	}

	return Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}
}
