// Package streebog is a clean-room, pure-Go implementation of the Streebog
// hash function (GOST R 34.11-2012, RFC 6986) for both the 256-bit and
// 512-bit output variants.
//
// The implementation follows RFC 6986 directly. All 512-bit state vectors are
// held as little-endian byte buffers ([64]byte with index 0 == a_0, the least
// significant byte, matching the RFC's a_63||...||a_0 numbering reversed). The
// two output sizes share the entire compression machinery and differ only in
// the initialization vector and a final truncation.
//
// # References
//
//   - RFC 6986: https://github.com/bigbes/gostcrypto/blob/master/streebog/rfc/rfc6986.txt
package streebog

import (
	"encoding/binary"
	"hash"
)

// Sizes.
const (
	blockSize = 64 // 512-bit block.
	size256   = 32
	size512   = 64
)

// Packing/encoding widths.
const (
	bytesPerWord = 8 // a 64-bit state word packs 8 little-endian bytes.
	bitsPerByte  = 8 // bit width of a byte.
	byteShift    = 8 // shift to drop the low byte (carry/word extraction).
)

// ---------------------------------------------------------------------------
// Constants (RFC 6986 §6). pi/tau/matrixA are transcribed from §6.2/§6.3/§6.4;
// roundConstants are the §6.5 iteration constants byte-reversed into the
// little-endian working representation (the form XORed directly into state).
// ---------------------------------------------------------------------------.

// pi is the nonlinear bijection Pi' (RFC 6986 §6.2, Table 1).
var pi = [256]byte{
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
	233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
	249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
	5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
	235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
	181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
	21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
	50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
	223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
	224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
	167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
	173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
	7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
	225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
	32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
	89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
}

// tau is the byte permutation Tau (RFC 6986 §6.3, Table 2).
var tau = [64]byte{
	0, 8, 16, 24, 32, 40, 48, 56,
	1, 9, 17, 25, 33, 41, 49, 57,
	2, 10, 18, 26, 34, 42, 50, 58,
	3, 11, 19, 27, 35, 43, 51, 59,
	4, 12, 20, 28, 36, 44, 52, 60,
	5, 13, 21, 29, 37, 45, 53, 61,
	6, 14, 22, 30, 38, 46, 54, 62,
	7, 15, 23, 31, 39, 47, 55, 63,
}

// matrixA holds the 64 rows of the GF(2) matrix A (RFC 6986 §6.4). Row j is a
// 64-bit constant; the linear map l(b) XORs row[63-i] for every set bit b_i of
// the 64-bit input word (b numbered MSB-first b_63..b_0).
var matrixA = [64]uint64{
	0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
	0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
	0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
	0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
	0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
	0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
	0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
	0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
	0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
	0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
	0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
	0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
	0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
	0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
	0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
	0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
}

// roundConstants are C[1]..C[12] (RFC 6986 §6.5) stored little-endian, i.e. the
// RFC MSB-first hex byte-reversed. These are XORed directly into the LE state
// during the key schedule.
var roundConstants = [12][64]byte{
	{
		0x07, 0x45, 0xa6, 0xf2, 0x59, 0x65, 0x80, 0xdd, 0x23, 0x4d, 0x74, 0xcc, 0x36, 0x74, 0x76, 0x05,
		0x15, 0xd3, 0x60, 0xa4, 0x08, 0x2a, 0x42, 0xa2, 0x01, 0x69, 0x67, 0x92, 0x91, 0xe0, 0x7c, 0x4b,
		0xfc, 0xc4, 0x85, 0x75, 0x8d, 0xb8, 0x4e, 0x71, 0x16, 0xd0, 0x45, 0x2e, 0x43, 0x76, 0x6a, 0x2f,
		0x1f, 0x7c, 0x65, 0xc0, 0x81, 0x2f, 0xcb, 0xeb, 0xe9, 0xda, 0xca, 0x1e, 0xda, 0x5b, 0x08, 0xb1,
	},
	{
		0xb7, 0x9b, 0xb1, 0x21, 0x70, 0x04, 0x79, 0xe6, 0x56, 0xcd, 0xcb, 0xd7, 0x1b, 0xa2, 0xdd, 0x55,
		0xca, 0xa7, 0x0a, 0xdb, 0xc2, 0x61, 0xb5, 0x5c, 0x58, 0x99, 0xd6, 0x12, 0x6b, 0x17, 0xb5, 0x9a,
		0x31, 0x01, 0xb5, 0x16, 0x0f, 0x5e, 0xd5, 0x61, 0x98, 0x2b, 0x23, 0x0a, 0x72, 0xea, 0xfe, 0xf3,
		0xd7, 0xb5, 0x70, 0x0f, 0x46, 0x9d, 0xe3, 0x4f, 0x1a, 0x2f, 0x9d, 0xa9, 0x8a, 0xb5, 0xa3, 0x6f,
	},
	{
		0xb2, 0x0a, 0xba, 0x0a, 0xf5, 0x96, 0x1e, 0x99, 0x31, 0xdb, 0x7a, 0x86, 0x43, 0xf4, 0xb6, 0xc2,
		0x09, 0xdb, 0x62, 0x60, 0x37, 0x3a, 0xc9, 0xc1, 0xb1, 0x9e, 0x35, 0x90, 0xe4, 0x0f, 0xe2, 0xd3,
		0x7b, 0x7b, 0x29, 0xb1, 0x14, 0x75, 0xea, 0xf2, 0x8b, 0x1f, 0x9c, 0x52, 0x5f, 0x5e, 0xf1, 0x06,
		0x35, 0x84, 0x3d, 0x6a, 0x28, 0xfc, 0x39, 0x0a, 0xc7, 0x2f, 0xce, 0x2b, 0xac, 0xdc, 0x74, 0xf5,
	},
	{
		0x2e, 0xd1, 0xe3, 0x84, 0xbc, 0xbe, 0x0c, 0x22, 0xf1, 0x37, 0xe8, 0x93, 0xa1, 0xea, 0x53, 0x34,
		0xbe, 0x03, 0x52, 0x93, 0x33, 0x13, 0xb7, 0xd8, 0x75, 0xd6, 0x03, 0xed, 0x82, 0x2c, 0xd7, 0xa9,
		0x3f, 0x35, 0x5e, 0x68, 0xad, 0x1c, 0x72, 0x9d, 0x7d, 0x3c, 0x5c, 0x33, 0x7e, 0x85, 0x8e, 0x48,
		0xdd, 0xe4, 0x71, 0x5d, 0xa0, 0xe1, 0x48, 0xf9, 0xd2, 0x66, 0x15, 0xe8, 0xb3, 0xdf, 0x1f, 0xef,
	},
	{
		0x57, 0xfe, 0x6c, 0x7c, 0xfd, 0x58, 0x17, 0x60, 0xf5, 0x63, 0xea, 0xa9, 0x7e, 0xa2, 0x56, 0x7a,
		0x16, 0x1a, 0x27, 0x23, 0xb7, 0x00, 0xff, 0xdf, 0xa3, 0xf5, 0x3a, 0x25, 0x47, 0x17, 0xcd, 0xbf,
		0xbd, 0xff, 0x0f, 0x80, 0xd7, 0x35, 0x9e, 0x35, 0x4a, 0x10, 0x86, 0x16, 0x1f, 0x1c, 0x15, 0x7f,
		0x63, 0x23, 0xa9, 0x6c, 0x0c, 0x41, 0x3f, 0x9a, 0x99, 0x47, 0x47, 0xad, 0xac, 0x6b, 0xea, 0x4b,
	},
	{
		0x6e, 0x7d, 0x64, 0x46, 0x7a, 0x40, 0x68, 0xfa, 0x35, 0x4f, 0x90, 0x36, 0x72, 0xc5, 0x71, 0xbf,
		0xb6, 0xc6, 0xbe, 0xc2, 0x66, 0x1f, 0xf2, 0x0a, 0xb4, 0xb7, 0x9a, 0x1c, 0xb7, 0xa6, 0xfa, 0xcf,
		0xc6, 0x8e, 0xf0, 0x9a, 0xb4, 0x9a, 0x7f, 0x18, 0x6c, 0xa4, 0x42, 0x51, 0xf9, 0xc4, 0x66, 0x2d,
		0xc0, 0x39, 0x30, 0x7a, 0x3b, 0xc3, 0xa4, 0x6f, 0xd9, 0xd3, 0x3a, 0x1d, 0xae, 0xae, 0x4f, 0xae,
	},
	{
		0x93, 0xd4, 0x14, 0x3a, 0x4d, 0x56, 0x86, 0x88, 0xf3, 0x4a, 0x3c, 0xa2, 0x4c, 0x45, 0x17, 0x35,
		0x04, 0x05, 0x4a, 0x28, 0x83, 0x69, 0x47, 0x06, 0x37, 0x2c, 0x82, 0x2d, 0xc5, 0xab, 0x92, 0x09,
		0xc9, 0x93, 0x7a, 0x19, 0x33, 0x3e, 0x47, 0xd3, 0xc9, 0x87, 0xbf, 0xe6, 0xc7, 0xc6, 0x9e, 0x39,
		0x54, 0x09, 0x24, 0xbf, 0xfe, 0x86, 0xac, 0x51, 0xec, 0xc5, 0xaa, 0xee, 0x16, 0x0e, 0xc7, 0xf4,
	},
	{
		0x1e, 0xe7, 0x02, 0xbf, 0xd4, 0x0d, 0x7f, 0xa4, 0xd9, 0xa8, 0x51, 0x59, 0x35, 0xc2, 0xac, 0x36,
		0x2f, 0xc4, 0xa5, 0xd1, 0x2b, 0x8d, 0xd1, 0x69, 0x90, 0x06, 0x9b, 0x92, 0xcb, 0x2b, 0x89, 0xf4,
		0x9a, 0xc4, 0xdb, 0x4d, 0x3b, 0x44, 0xb4, 0x89, 0x1e, 0xde, 0x36, 0x9c, 0x71, 0xf8, 0xb7, 0x4e,
		0x41, 0x41, 0x6e, 0x0c, 0x02, 0xaa, 0xe7, 0x03, 0xa7, 0xc9, 0x93, 0x4d, 0x42, 0x5b, 0x1f, 0x9b,
	},
	{
		0xdb, 0x5a, 0x23, 0x83, 0x51, 0x44, 0x61, 0x72, 0x60, 0x2a, 0x1f, 0xcb, 0x92, 0xdc, 0x38, 0x0e,
		0x54, 0x9c, 0x07, 0xa6, 0x9a, 0x8a, 0x2b, 0x7b, 0xb1, 0xce, 0xb2, 0xdb, 0x0b, 0x44, 0x0a, 0x80,
		0x84, 0x09, 0x0d, 0xe0, 0xb7, 0x55, 0xd9, 0x3c, 0x24, 0x42, 0x89, 0x25, 0x1b, 0x3a, 0x7d, 0x3a,
		0xde, 0x5f, 0x16, 0xec, 0xd8, 0x9a, 0x4c, 0x94, 0x9b, 0x22, 0x31, 0x16, 0x54, 0x5a, 0x8f, 0x37,
	},
	{
		0xed, 0x9c, 0x45, 0x98, 0xfb, 0xc7, 0xb4, 0x74, 0xc3, 0xb6, 0x3b, 0x15, 0xd1, 0xfa, 0x98, 0x36,
		0xf4, 0x52, 0x76, 0x3b, 0x30, 0x6c, 0x1e, 0x7a, 0x4b, 0x33, 0x69, 0xaf, 0x02, 0x67, 0xe7, 0x9f,
		0x03, 0x61, 0x33, 0x1b, 0x8a, 0xe1, 0xff, 0x1f, 0xdb, 0x78, 0x8a, 0xff, 0x1c, 0xe7, 0x41, 0x89,
		0xf3, 0xf3, 0xe4, 0xb2, 0x48, 0xe5, 0x2a, 0x38, 0x52, 0x6f, 0x05, 0x80, 0xa6, 0xde, 0xbe, 0xab,
	},
	{
		0x1b, 0x2d, 0xf3, 0x81, 0xcd, 0xa4, 0xca, 0x6b, 0x5d, 0xd8, 0x6f, 0xc0, 0x4a, 0x59, 0xa2, 0xde,
		0x98, 0x6e, 0x47, 0x7d, 0x1d, 0xcd, 0xba, 0xef, 0xca, 0xb9, 0x48, 0xea, 0xef, 0x71, 0x1d, 0x8a,
		0x79, 0x66, 0x84, 0x14, 0x21, 0x80, 0x01, 0x20, 0x61, 0x07, 0xab, 0xeb, 0xbb, 0x6b, 0xfa, 0xd8,
		0x94, 0xfe, 0x5a, 0x63, 0xcd, 0xc6, 0x02, 0x30, 0xfb, 0x89, 0xc8, 0xef, 0xd0, 0x9e, 0xcd, 0x7b,
	},
	{
		0x20, 0xd7, 0x1b, 0xf1, 0x4a, 0x92, 0xbc, 0x48, 0x99, 0x1b, 0xb2, 0xd9, 0xd5, 0x17, 0xf4, 0xfa,
		0x52, 0x28, 0xe1, 0x88, 0xaa, 0xa4, 0x1d, 0xe7, 0x86, 0xcc, 0x91, 0x18, 0x9d, 0xef, 0x80, 0x5d,
		0x9b, 0x9f, 0x21, 0x30, 0xd4, 0x12, 0x20, 0xf8, 0x77, 0x1d, 0xdf, 0xbc, 0x32, 0x3c, 0xa4, 0xcd,
		0x7a, 0xb1, 0x49, 0x04, 0xb0, 0x80, 0x13, 0xd2, 0xba, 0x31, 0x16, 0xf1, 0x67, 0xe7, 0x8e, 0x37,
	},
}

// ---------------------------------------------------------------------------
// LP precompute table.
//
// The state is held as [8]uint64, where word[k] packs little-endian bytes
// [8k..8k+7]: word[k] = b[8k] | b[8k+1]<<8 | ... | b[8k+7]<<56.
//
// Because P and L are GF(2)-linear, the combined L(P(·)) decomposes as an XOR
// over the 64 input byte positions:
//
//	LP(a) = XOR over p in 0..63 of lpTable[p][a_byte_p]
//
// where a_byte_p is the byte at little-endian position p. S (the nonlinear pi
// substitution) is NOT folded into the table — pi[0]=0xfc≠0, so LP(0)==0 but
// LPS(0)≠0. S is instead applied at lookup time in lps() (see below).
// lpTable is built in init() by calling linearLP (pure L∘P, no S), making the
// table derivation independently reviewable from the spec constants.
// ---------------------------------------------------------------------------.

// lpTable[p][v] = L(P(b)) where b is the LE buffer holding byte value v at
// position p and zero elsewhere. S is nonlinear (it maps zero bytes to
// pi[0]=0xfc), so it is applied separately at call time; only the linear part
// L(P(.)) is folded into the table, which IS XOR-decomposable per input byte.
var lpTable [64][256][8]uint64

func init() {
	for p := range 64 {
		for v := range 256 {
			var in [64]byte

			in[p] = byte(v)
			lpTable[p][v] = bytesToWords(linearLP(in))
		}
	}
}

// linearLP applies L(P(a)) (no S) on a little-endian [64]byte buffer. Used
// only at init time to build lpTable.
func linearLP(a [64]byte) [64]byte {
	// P: P(a) = a_{tau(63)}||...||a_{tau(0)}, written MSB-first. The bytes a_i
	// are labeled by significance (a_0 = LSB = LE index 0); the output's byte
	// at significance s is a_{tau(s)}. Hence out_le[s] = in_le[tau[s]].
	var p [64]byte

	for s := range 64 {
		p[s] = a[int(tau[s])]
	}

	// L: split into eight 64-bit words (RFC words a_7..a_0; a_0 = LE bytes
	// 0..7) and apply l to each. l(word) XORs matrixA[63-i] for every set bit
	// b_i of the word, where b is numbered MSB-first (b_63 is the word's MSB).
	var out [64]byte

	for w := range 8 {
		word := binary.LittleEndian.Uint64(p[8*w : 8*w+8])

		var acc uint64

		for bit := range 64 {
			// b_i is bit i (LSB-numbered i). Row used is matrixA[63-i].
			if word&(1<<uint(bit)) != 0 {
				acc ^= matrixA[63-bit]
			}
		}

		binary.LittleEndian.PutUint64(out[8*w:8*w+8], acc)
	}

	return out
}

func bytesToWords(b [64]byte) [8]uint64 {
	var w [8]uint64

	for i := range 8 {
		w[i] = binary.LittleEndian.Uint64(b[8*i : 8*i+8])
	}

	return w
}

func wordsToBytes(w [8]uint64) [64]byte {
	var b [64]byte

	for i := range 8 {
		binary.LittleEndian.PutUint64(b[8*i:8*i+8], w[i])
	}

	return b
}

// lps applies L(P(S(x))) via the precomputed linear table. S (pi) is applied
// to each input byte before the table lookup.
func lps(x [8]uint64) [8]uint64 {
	var r [8]uint64

	for p := range 8 {
		word := x[p]
		base := p * bytesPerWord

		for k := range 8 {
			b := pi[byte(word>>uint(byteShift*k))]
			t := &lpTable[base+k][b]

			r[0] ^= t[0]
			r[1] ^= t[1]
			r[2] ^= t[2]
			r[3] ^= t[3]
			r[4] ^= t[4]
			r[5] ^= t[5]
			r[6] ^= t[6]
			r[7] ^= t[7]
		}
	}

	return r
}

func xor512(a, b [8]uint64) [8]uint64 {
	var r [8]uint64

	for i := range 8 {
		r[i] = a[i] ^ b[i]
	}

	return r
}

// e is the keyed permutation E(K, m) (RFC 6986 §8): 13 key additions
// interleaved with 12 LPS rounds. K is the first round key (K_1).
func e(k, m [8]uint64) [8]uint64 {
	state := xor512(m, k)
	for i := range 12 {
		// K_{i+2} = LPS(K_{i+1} XOR C_{i+1}).
		k = lps(xor512(k, roundConstantWords[i]))
		state = xor512(lps(state), k)
	}

	return state
}

// g is the compression function g_N(h, m) = E(LPS(h XOR N), m) XOR h XOR m.
func g(h, m, n [8]uint64) [8]uint64 {
	k := lps(xor512(h, n))
	t := e(k, m)

	return xor512(xor512(t, h), m)
}

// roundConstantWords is roundConstants packed into [8]uint64 form, computed in
// init().
var roundConstantWords [12][8]uint64

func init() {
	for i := range 12 {
		roundConstantWords[i] = bytesToWords(roundConstants[i])
	}
}

// add512 computes (a + b) mod 2^512 over little-endian byte buffers.
func add512(a, b [64]byte) [64]byte {
	var (
		r     [64]byte
		carry uint16
	)

	for i := range 64 {
		s := uint16(a[i]) + uint16(b[i]) + carry

		r[i] = byte(s)
		carry = s >> byteShift
	}

	return r
}

// ---------------------------------------------------------------------------
// hash.Hash implementation.
// ---------------------------------------------------------------------------.

type digest struct {
	h    [8]uint64 // hash state.
	n    [64]byte  // bit counter (little-endian 512-bit).
	sum  [64]byte  // checksum Sigma (little-endian 512-bit).
	buf  [64]byte  // partial block buffer.
	nbuf int       // bytes currently in buf.
	size int       // output size: 32 or 64.
}

// New256 returns a hash.Hash computing the 256-bit Streebog digest.
func New256() hash.Hash {
	d := &digest{size: size256}
	d.Reset()

	return d
}

// New512 returns a hash.Hash computing the 512-bit Streebog digest.
func New512() hash.Hash {
	d := &digest{size: size512}
	d.Reset()

	return d
}

func (d *digest) Reset() {
	var iv [64]byte

	if d.size == size256 {
		for i := range iv {
			iv[i] = 0x01
		}
	}

	d.h = bytesToWords(iv)
	d.n = [64]byte{}
	d.sum = [64]byte{}
	d.buf = [64]byte{}
	d.nbuf = 0
}

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return blockSize }

// block512le is the little-endian constant 512 used to advance the bit counter
// by one full block (512 bits) per stage-2 step.
var block512le = func() [64]byte {
	var b [64]byte

	b[0] = 0x00
	b[1] = 0x02 // 0x0200 = 512.

	return b
}()

func (d *digest) Write(p []byte) (int, error) {
	total := len(p)
	// Fill an existing partial buffer first.
	if d.nbuf > 0 {
		k := copy(d.buf[d.nbuf:], p)

		d.nbuf += k

		p = p[k:]

		if d.nbuf == blockSize {
			d.compress(d.buf)

			d.nbuf = 0
		}
	}

	// Process full blocks directly from p.
	for len(p) >= blockSize {
		var blk [64]byte

		copy(blk[:], p[:blockSize])
		d.compress(blk)

		p = p[blockSize:]
	}

	// Buffer the remainder.
	if len(p) > 0 {
		d.nbuf = copy(d.buf[:], p)
	}

	return total, nil
}

// Sum finalizes a copy of the state (non-destructive) and appends the digest.
func (d *digest) Sum(in []byte) []byte {
	// Snapshot mutable state.
	h := d.h
	n := d.n
	sum := d.sum

	// Stage 3: pad the partial buffer.
	var m [64]byte

	copy(m[:], d.buf[:d.nbuf])

	m[d.nbuf] = 0x01 // single 1 bit immediately above the message.

	mw := bytesToWords(m)

	// g_N at the pre-finalization N.
	h = g(h, mw, bytesToWords(n))
	// N += bit length of the real tail only.
	var tailBits [64]byte

	bits := uint64(d.nbuf) * bitsPerByte
	binary.LittleEndian.PutUint64(tailBits[0:8], bits)

	n = add512(n, tailBits)
	// Sigma += padded block (including the 0x01 and zero fill).
	sum = add512(sum, m)
	// g_0(h, N) then g_0(h, Sigma).
	var zero [8]uint64

	h = g(h, bytesToWords(n), zero)
	h = g(h, bytesToWords(sum), zero)

	out := wordsToBytes(h)
	if d.size == size256 {
		// MSB_256: upper half of the LE buffer.
		return append(in, out[32:64]...)
	}

	return append(in, out[:]...)
}

// compress runs one stage-2 step on a full block.
func (d *digest) compress(blk [64]byte) {
	m := bytesToWords(blk)

	d.h = g(d.h, m, bytesToWords(d.n))
	d.n = add512(d.n, block512le)
	d.sum = add512(d.sum, blk)
}

// Sum256 returns the 256-bit Streebog digest of b.
func Sum256(b []byte) [32]byte {
	d := &digest{size: size256}
	d.Reset()
	d.Write(b) //nolint:errcheck // digest.Write never returns an error.

	var out [32]byte

	copy(out[:], d.Sum(nil))

	return out
}

// Sum512 returns the 512-bit Streebog digest of b.
func Sum512(b []byte) [64]byte {
	d := &digest{size: size512}
	d.Reset()
	d.Write(b) //nolint:errcheck // digest.Write never returns an error.

	var out [64]byte

	copy(out[:], d.Sum(nil))

	return out
}

// Conformance assertions.
var (
	_ hash.Hash = New256()
	_ hash.Hash = New512()
)
