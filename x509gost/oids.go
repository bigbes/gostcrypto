// Package x509gost provides GOST-aware X.509 certificate parsing and
// signature verification. It builds on the clean-room pure-Go primitives
// via the gostcrypto facade — no build tags, no third-party dependencies.
//
// # References
//
//   - RFC 9215: https://github.com/bigbes/gostcrypto/blob/master/x509gost/rfc/rfc9215.txt
//   - RFC 4491: https://github.com/bigbes/gostcrypto/blob/master/x509gost/rfc/rfc4491.txt
package x509gost

import "encoding/asn1"

// ── Signature algorithm OIDs ─────────────────────────────────────────────────.

// OIDSignatureGOSTR341001 is the GOST R 34.10-2001 combined signature-and-hash
// OID (id-GostR3410-2001-GostR3411 / 1.2.643.2.2.3).
// RFC 4491 §2.1.
var OIDSignatureGOSTR341001 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 3}

// OIDSignatureGOSTR341012_256 is the GOST R 34.10-2012 256-bit combined
// signature-and-hash OID (id-tc26-signwithdigest-gost3410-12-256 /
// 1.2.643.7.1.1.3.2). RFC 7091 §2.
var OIDSignatureGOSTR341012_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 2}

// OIDSignatureGOSTR341012_512 is the GOST R 34.10-2012 512-bit combined
// signature-and-hash OID (id-tc26-signwithdigest-gost3410-12-512 /
// 1.2.643.7.1.1.3.3). RFC 7091 §2.
var OIDSignatureGOSTR341012_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 3, 3}

// ── Public key algorithm OIDs ─────────────────────────────────────────────────.

// OIDPublicKeyGOSTR341001 is the GOST R 34.10-2001 public key OID
// (id-GostR3410-2001 / 1.2.643.2.2.19). RFC 4491 §2.1.
var OIDPublicKeyGOSTR341001 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 19}

// OIDPublicKeyGOSTR341012_256 is the GOST R 34.10-2012 256-bit public key OID
// (id-tc26-gost3410-12-256 / 1.2.643.7.1.1.1.1). RFC 7091 §2.
var OIDPublicKeyGOSTR341012_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}

// OIDPublicKeyGOSTR341012_512 is the GOST R 34.10-2012 512-bit public key OID
// (id-tc26-gost3410-12-512 / 1.2.643.7.1.1.1.2). RFC 7091 §2.
var OIDPublicKeyGOSTR341012_512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 2}

// ── Hash algorithm OIDs ───────────────────────────────────────────────────────.

// OIDHashGOSTR341194 is the GOST R 34.11-94 hash OID
// (id-GostR3411-94 / 1.2.643.2.2.9). RFC 4357.
var OIDHashGOSTR341194 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 9}

// OIDHashStreebog256 is the Streebog-256 hash OID
// (id-tc26-gost3411-12-256 / 1.2.643.7.1.1.2.2). RFC 7091.
var OIDHashStreebog256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}

// OIDHashStreebog512 is the Streebog-512 hash OID
// (id-tc26-gost3411-12-512 / 1.2.643.7.1.1.2.3). RFC 7091.
var OIDHashStreebog512 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 3}

// ── Curve parameter OIDs ──────────────────────────────────────────────────────.

// OIDParamCryptoProA is the CryptoPro-A curve parameter set for GOST R 34.10-2001
// (id-CryptoPro-GostR3410-2001-CryptoPro-A-ParamSet / 1.2.643.2.2.35.1).
// RFC 4357.
var OIDParamCryptoProA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 1}

// OIDParamCryptoProB is the CryptoPro-B curve parameter set
// (1.2.643.2.2.35.2). RFC 4357.
var OIDParamCryptoProB = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 2}

// OIDParamCryptoProC is the CryptoPro-C curve parameter set
// (1.2.643.2.2.35.3). RFC 4357.
var OIDParamCryptoProC = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 3}

// OIDParamTC26_256A is the TC26 GOST R 34.10-2012 256-bit curve paramSetA
// (id-tc26-gost-3410-2012-256-paramSetA / 1.2.643.7.1.2.1.1.1). RFC 7091.
var OIDParamTC26_256A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}

// OIDParamTC26_256B is the TC26 GOST R 34.10-2012 256-bit curve paramSetB
// (id-tc26-gost-3410-2012-256-paramSetB / 1.2.643.7.1.2.1.1.2).
var OIDParamTC26_256B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}

// OIDParamTC26_256C is the TC26 GOST R 34.10-2012 256-bit curve paramSetC
// (id-tc26-gost-3410-2012-256-paramSetC / 1.2.643.7.1.2.1.1.3).
var OIDParamTC26_256C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}

// OIDParamTC26_256D is the TC26 GOST R 34.10-2012 256-bit curve paramSetD
// (id-tc26-gost-3410-2012-256-paramSetD / 1.2.643.7.1.2.1.1.4).
var OIDParamTC26_256D = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}

// OIDParamTC26_512A is the TC26 GOST R 34.10-2012 512-bit curve paramSetA
// (id-tc26-gost-3410-2012-512-paramSetA / 1.2.643.7.1.2.1.2.1). RFC 7091.
var OIDParamTC26_512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}

// OIDParamTC26_512B is the TC26 GOST R 34.10-2012 512-bit curve paramSetB
// (id-tc26-gost-3410-2012-512-paramSetB / 1.2.643.7.1.2.1.2.2).
var OIDParamTC26_512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}

// OIDParamTC26_512C is the TC26 GOST R 34.10-2012 512-bit curve paramSetC
// (id-tc26-gost-3410-2012-512-paramSetC / 1.2.643.7.1.2.1.2.3).
var OIDParamTC26_512C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
