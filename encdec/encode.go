package encdec

import (
	// "fmt"
	// "math"
	// "math/rand"
	"dpr/base"
	// "math/big"
)

func Encode(plain uint16, sk *base.Privkey, p int) *base.Cipher {
	q := sk.Q
	m := len(sk.Z)
	n := len(sk.KeyX)
	var x, b, c uint16
	res := new(base.Cipher)
	for k := 0; k < 1000; k++ {
		bk := false
		res.GenRand(m, n, int(q), p)
		remain := plain
		for i := 0; i < m - 1; i++ {
			a := res.A[i]
			x = 1
			for j := 0; j < n; j++ {
				x = base.MultiGF(x, base.GetHashF(res.X[i][j], sk.KeyX[j], q), q)
			}
			b = x
			c = base.MultiGF(a, b, q)
			c = base.MultiGF(c, sk.Z[i], q)
			if(c == 0) {
				bk = true
				break
			}
			if(remain >= c) {
				remain = uint16(int(remain) - int(c))
			} else {
				remain = uint16(int(remain) + int(q) - int(c))
			}
		}
		if(bk) {
			continue
		}
		x = 1
		for i := 0; i < n; i++ {
			x = base.MultiGF(x, base.GetHashF(res.X[m - 1][i], sk.KeyX[i], q), q)
		}
		x = base.MultiGF(x, sk.Z[m - 1], q)
		b = x
		if(b == 0) {
			continue
		}
		c = base.DivideGF(remain, b, q)
		if(c > 0) {
			res.A[m - 1] = c
			break
		}
	}
	return res
}

func EncodePublic(plain uint16, pk *base.Pubkey, sk *base.Privkey, m int, p int) *base.Cipher {
	q := pk.Q
	n := len(pk.KeyX)
	var x uint16
	res := new(base.Cipher)
	res.GenRand(1, n, int(q), p)
	x = 1
	for i := 0; i < n; i++ {
		x = base.MultiGF(x, base.GetHashF(res.X[0][i], pk.KeyX[i], q), q)
	}
	x = base.MultiGF(x, pk.Z, q)
	res.A[0] = base.DivideGF(plain, x, q)
	res2 := new(base.Cipher)
	res2.GenRand(m, n, int(q), p)
	for i := 0; i < m; i++ {
		ai := res.A[0]
		for j := 0; j < n; j++ {
			xj := res.X[0][j]
			y := pk.ZC.X[i][j]
			res2.X[i][j] = base.GetHT(pk.TK, xj, y, j, p)
			g := pk.TG[i * n + j][xj]
			ai = base.MultiGF(ai, g, q)
		}
		res2.A[i] = base.MultiGF(ai, pk.ZC.A[i], q)
	}
	return res2
}

func DecodePK(cipher *base.Cipher, pk *base.Pubkey) uint16 {
	q := pk.Q
	n := len(pk.KeyX)
	var x, b, c uint16
	res := 0
	a := cipher.A[0]
	x = 1
	for j := 0; j < n; j++ {
		x = base.MultiGF(x, base.GetHashF(cipher.X[0][j], pk.KeyX[j], q), q)
	}
	b = x
	c = base.MultiGF(a, b, q)
	c = base.MultiGF(c, pk.Z, q)
	res += int(c)
	return uint16(res % int(q))
}

func Decode(cipher *base.Cipher, sk *base.Privkey) uint16 {
	q := sk.Q
	m := len(sk.Z)
	n := len(sk.KeyX)
	var x, b, c uint16
	res := 0
	for i := 0; i < m; i++ {
		a := cipher.A[i]
		x = 1
		for j := 0; j < n; j++ {
			x = base.MultiGF(x, base.GetHashF(cipher.X[i][j], sk.KeyX[j], q), q)
		}
		b = x
		c = base.MultiGF(a, b, q)
		c = base.MultiGF(c, sk.Z[i], q)
		res += int(c)
	}
	return uint16(res % int(q))
}

func DecodePart(cipherPart *base.CipherPart, sk *base.Privkey) uint16 {
	q := sk.Q
	n := len(sk.KeyX)
	var x, b, c uint16
	res := 0
	a := cipherPart.A
	x = 1
	for j := 0; j < n; j++ {
		x = base.MultiGF(x, base.GetHashF(cipherPart.X[j], sk.KeyX[j], q), q)
	}
	b = x
	c = base.MultiGF(a, b, q)
	res += int(c)
	return uint16(res % int(q))
}
