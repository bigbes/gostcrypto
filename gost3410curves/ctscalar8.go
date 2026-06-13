// ctscalar8.go — EXPERIMENT. 8-limb (512-bit) constant-time scalar mult, the
// parallel of ctscalar.go: fixed-window over the complete formulas, fixed-width
// magnitude-oblivious scalar decode. See ctscalar.go for the design notes.

package gost3410curves

import (
	"encoding/binary"
	"math/big"

	"github.com/bigbes/gostcrypto/internal/ct"
)

func scalarToLimbs8(k *big.Int) fe8 {
	var buf [ctLimbs8 * 8]byte

	k.FillBytes(buf[:]) // fixed 64-byte big-endian; k < Q < 2^512 by contract.

	return scalarBytesToLimbs8(buf[:])
}

// scalarBytesToLimbs8 is the 8-limb fully-CT decode (cf. scalarBytesToLimbs).
func scalarBytesToLimbs8(b []byte) fe8 {
	var out fe8
	for i := range ctLimbs8 {
		out[i] = binary.BigEndian.Uint64(b[(ctLimbs8-1-i)*8:])
	}

	return out
}

func (cc *ctCurve8) scalarMult(k *big.Int, p ctPoint8) ctPoint8 {
	return cc.scalarMultLimbs(scalarToLimbs8(k), p)
}

func (cc *ctCurve8) scalarMultLimbs(kl fe8, p ctPoint8) ctPoint8 {
	var tbl [1 << ctWindow]ctPoint8

	tbl[0] = cc.identity()
	tbl[1] = p

	for i := 2; i < len(tbl); i++ {
		tbl[i] = cc.add(tbl[i-1], p)
	}

	nWin := (cc.orderBits + ctWindow - 1) / ctWindow

	result := cc.identity()

	for wi := nWin - 1; wi >= 0; wi-- {
		for range ctWindow {
			result = cc.double(result)
		}

		pos := uint(wi * ctWindow)
		digit := (kl[pos>>6] >> (pos & limbBitsMinus1)) & ((1 << ctWindow) - 1)

		result = cc.add(result, cc.selectWindow(&tbl, digit))
	}

	return result
}

func (cc *ctCurve8) selectWindow(tbl *[1 << ctWindow]ctPoint8, digit uint64) ctPoint8 {
	var r ctPoint8

	for j := range tbl {
		mask := ct.Eq(uint64(j), digit)

		r.x = cmov8(mask, tbl[j].x, r.x)
		r.y = cmov8(mask, tbl[j].y, r.y)
		r.z = cmov8(mask, tbl[j].z, r.z)
	}

	return r
}
