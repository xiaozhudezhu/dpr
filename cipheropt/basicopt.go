package cipheropt

import (
	"fmt"
	// "math"
	"math/rand"
	"dpr/base"
	// "dpr/encdec"
	// "time"
)

func No() {
	fmt.Println()
}

func SubstractCipher(c1 *base.Cipher, c2 *base.Cipher, dict *base.Dictionary, q uint16, p int) *base.Cipher {
	c3 := c2.Clone()
	for i := 0; i < len(c2.A); i++ {
		c3.A[i] = q - c2.A[i]
	}
	return AddCipher(c1, c3, dict, q, p)
}

func AddCipher(c1 *base.Cipher, c2 *base.Cipher, dict *base.Dictionary, q uint16, p int) *base.Cipher {
	res := new(base.Cipher)
	m := len(c1.A)
	n := len(c1.X[0])
	res.GenRand(m, n, int(q), p)
	for i := 0; i < m; i++ {
		p1 := c1.GetCipherPart(i)
		p2 := c2.GetCipherPart(i)
		p3 := AddCipherPart(p1, p2, dict, q, p)
		res.SetCipherPart(i, p3)
	}
	return res
}

func AddCipherPart(p1 *base.CipherPart, p2 *base.CipherPart, dict *base.Dictionary, q uint16, p int) *base.CipherPart {
	res := new(base.CipherPart)
	n := len(p1.X)
	res.X = make([]uint16, n)
	a1 := p1.A
	a2 := p2.A
	x11p := uint16(rand.Intn(p))
	res1 := SplitF(dict.CKey, 0, p1.X[0], x11p, dict, q, p)
	x21p := res1[0]
	a1 = base.MultiGF(a1, res1[1], q)
	res2 := SplitF(dict.CKey, 0, p2.X[0], x11p, dict, q, p)
	x22p := res2[0]
	a2 = base.MultiGF(a2, res2[1], q)

	for i := 1; i < n - 1; i++ {
		xi := uint16(rand.Intn(p))
		res.X[i] = xi
		resi1 := MoveF(dict.CKey, i, x21p, p1.X[i], xi, dict, q, p)
		x21p = resi1[0]
		a1 = base.MultiGF(a1, resi1[1], q)
		resi2 := MoveF(dict.CKey, i, x22p, p2.X[i], xi, dict, q, p)
		x22p = resi2[0]
		a2 = base.MultiGF(a2, resi2[1], q)
	}
	a1 = base.MultiGF(a1, dict.G[n - 1][x21p][p1.X[n - 1]], q)
	x21p = base.GetH(dict.CKey, x21p, p1.X[n - 1], uint16(n), p)
	a2 = base.MultiGF(a2, dict.G[n - 1][x22p][p2.X[n - 1]], q)
	x22p = base.GetH(dict.CKey, x22p, p2.X[n - 1], uint16(n), p)

	gd := dict.G[n][x21p][x22p]
	xd1 := x22p
	xd2 := base.GetH(dict.CKey, x21p, x22p, uint16(n + 1), p)
	a2t := int(a2) - int(a1)
	if(a2t < 0) {
		a2 = uint16(a2t + int(q))
	} else {
		a2 = uint16(a2t)
	}
	a1 = base.MultiGF(a1, gd, q)

	res3 := SplitF2(dict.CKey, n + 1, x11p, xd2, dict, q, p)
	x63 := res3[0]
	res.X[n - 1] = x63
	a3 := res3[1]

	a1 = base.MultiGF(a1, dict.G[n + 2][xd1][xd2], q)
	a2 = base.MultiGF(a2, dict.G[n + 3][xd1][xd2], q)
	x13 := xd2

	a3 = base.MultiGF(a3, base.AddGF(a1, a2, q), q)
	res.X[0] = x13
	res.A = a3
	return res
}

func AddCipherPartTarget(p1 *base.CipherPart, p2 *base.CipherPart, dict *base.Dictionary, q int, p int, pt *base.CipherPart) *base.CipherPart {
	res := new(base.CipherPart)
	n := len(p1.X)
	res.A = 0
	res.X = make([]uint16, n)
	for i := 0; i < n; i++ {
		res.X[i] = pt.X[i]
	}
	a1 := p1.A
	a2 := p2.A
	// x11p2 := (p1.X[0] + p1.X[1] + p2.X[0] + p2.X[1] - pt.X[0] + 2 * dict.CKey[n] - 2 * dict.CKey[1] + dict.CKey[n + 1]) % uint16(p)
	// if x11p2 < 0 {
	// 	x11p2 += uint16(p)
	// }
	x11p2 := p1.X[0] + p1.X[1] + p2.X[0] + p2.X[1] + 2 * dict.CKey[n] + dict.CKey[n + 1]
	if x11p2 >= 2 * dict.CKey[1] + pt.X[0] {
		x11p2 = (x11p2 - 2 * dict.CKey[1] - pt.X[0]) % uint16(p)
	} else if x11p2 + uint16(p) >= 2 * dict.CKey[1] + pt.X[0] {
		x11p2 = (x11p2 + uint16(p) - 2 * dict.CKey[1] - pt.X[0]) % uint16(p)
	} else {
		x11p2 = (x11p2 + uint16(2 * p) - 2 * dict.CKey[1] - pt.X[0]) % uint16(p)
	}
	// if x11p2 > pt.X[0] {
	// 	x11p2 = (x11p2 - pt.X[0]) % uint16(p)
	// } else {
	// 	x11p2 = (x11p2 + uint16(p) - pt.X[0]) % uint16(p)
	// }
	x11p := uint16(x11p2 / 2) + 1
	res1 := SplitF(dict.CKey, 0, p1.X[0], x11p, dict, uint16(q), p)
	x21p := res1[0]
	a1 = base.MultiGF(a1, res1[1], uint16(q))
	res2 := SplitF(dict.CKey, 0, p2.X[0], x11p, dict, uint16(q), p)
	x22p := res2[0]
	a2 = base.MultiGF(a2, res2[1], uint16(q))

	a1 = base.MultiGF(a1, dict.G[n - 1][x21p][p1.X[n - 1]], uint16(q))
	x21p = base.GetH(dict.CKey, x21p, p1.X[n - 1], uint16(n), p)
	a2 = base.MultiGF(a2, dict.G[n - 1][x22p][p2.X[n - 1]], uint16(q))
	x22p = base.GetH(dict.CKey, x22p, p2.X[n - 1], uint16(n), p)

	gd := dict.G[n][x21p][x22p]
	xd1 := x22p
	xd2 := base.GetH(dict.CKey, x21p, x22p, uint16(n + 1), p)

	// a2t := uint16(a2) - uint16(a1)
	// if(a2t < 0) {
	// 	a2 = uint16(a2t + uint16(q))
	// } else {
	// 	a2 = uint16(a2t)
	// }
	if a2 < a1 {
		a2 = a2 + uint16(q) - a1
	} else {
		a2 = a2 - a1
	}
	a1 = base.MultiGF(a1, gd, uint16(q))

	res3 := SplitF2(dict.CKey, n + 1, x11p, xd2, dict, uint16(q), p)
	// x11pg := res.X[1] - res3[0]
	// if x11pg < 0 {
	// 	x11pg += uint16(p)
	// }
	x11pg := res.X[1] - res3[0]
	if res.X[1] < res3[0] {
		x11pg = res.X[1] + uint16(p) - res3[0]
	}
	x11pf := base.AddGF(x11p, x11pg, uint16(p))
	a4 := uint16(1)
	if x11p2 % 2 != 0 {
		a4 = dict.G[n * 2 + 5][x11p][x11pf]
	} else {
		a4 = dict.G[n * 2 + 6][x11p][x11pf]
	}
	res3 = SplitF2(dict.CKey, n + 1, x11pf, xd2, dict, uint16(q), p)
	a3 := res3[1]
	a3 = base.MultiGF(a3, a4, uint16(q))

	a1 = base.MultiGF(a1, dict.G[n + 2][xd1][xd2], uint16(q))
	a2 = base.MultiGF(a2, dict.G[n + 3][xd1][xd2], uint16(q))

	a3 = base.MultiGF(a3, base.AddGF(a1, a2, uint16(q)), uint16(q))
	if x11p2 % 2 != 0 {
		a5 := dict.G0[xd2][x11p]
		a3 = base.MultiGF(a3, a5, uint16(q))
	} else {
		a5 := dict.G1[xd2][x11p]
		a3 = base.MultiGF(a3, a5, uint16(q))
	}
	res.A = a3
	return res
}

func MultiplyCipher(c1 *base.Cipher, c2 *base.Cipher, dict *base.Dictionary, q uint16, p int) *base.Cipher {
	res := new(base.Cipher)
	m := len(c1.A)
	n := len(c1.X[0])
	res.GenRandZero(m, n, int(q), p)
	for i := 0; i < m; i++ {
		p1 := c1.GetCipherPart(i)
		for j := 0; j < m; j++ {
			p2 := c2.GetCipherPart(j)
			p3 := MultiplyCipherPart(p1, p2, dict, q, p)
			czij := dict.CS[i * m + j]
			for k := 0; k < m; k++ {
				czijp := czij.GetCipherPart(k)
				resp1 := MultiplyCipherPart(p3, czijp, dict, q, p)
				resp2 := res.GetCipherPart(k)
				resp := AddCipherPart(resp1, resp2, dict, q, p)
				res.SetCipherPart(k, resp)
			}
		}
	}
	return res
}

func MultiplyCipherPart(p1 *base.CipherPart, p2 *base.CipherPart, dict *base.Dictionary, q uint16, p int) *base.CipherPart {
	res := new(base.CipherPart)
	n := len(p1.X)
	res.X = make([]uint16, n)
	a1 := p1.A
	a2 := p2.A

	x11p := base.GetH(dict.CKey, p1.X[n - 1], p2.X[n - 1], uint16(2 * n + 2), p)
	res1 := SplitF(dict.CKey, 0, p1.X[0], x11p, dict, q, p)
	x21p := res1[0]
	a1 = base.MultiGF(a1, res1[1], q)
	res2 := SplitF(dict.CKey, 0, p2.X[0], x11p, dict, q, p)
	x22p := res2[0]
	a2 = base.MultiGF(a2, res2[1], q)

	for i := 1; i < n - 1; i++ {
		xi := uint16(rand.Intn(p))
		res.X[i] = xi
		resi1 := MoveF(dict.CKey, i, x21p, p1.X[i], xi, dict, q, p)
		x21p = resi1[0]
		a1 = base.MultiGF(a1, resi1[1], q)
		resi2 := MoveF(dict.CKey, i, x22p, p2.X[i], xi, dict, q, p)
		x22p = resi2[0]
		a2 = base.MultiGF(a2, resi2[1], q)
	}
	a3 := base.MultiGF(a1, a2, q)

	g1 := dict.G[n + 4][x21p][x22p]
	a4 := base.MultiGF(a3, g1, q)
	wi := base.GetH(dict.CKey, x21p, x22p, uint16(n + 3), p)
	res.X[0] = wi

	for i := 1; i < n - 1; i++ {
		gi := dict.G[n + 4 + i][res.X[i]][wi]
		a4 = base.MultiGF(a4, gi, q)
		wi = base.GetH(dict.CKey, res.X[i], wi, uint16(n + 3 + i), p)
		res.X[i] = wi
	}

	g2 := dict.G[n * 2 + 3][p1.X[n - 1]][p2.X[n - 1]]
	a5 := base.MultiGF(a4, g2, q)
	g3 := dict.G[n * 2 + 4][x11p][wi]
	a6 := base.MultiGF(a5, g3, q)
	res.X[n - 1] = base.GetH(dict.CKey, x11p, wi, uint16(2 * n + 4), p)

	res.A = a6
	return res
}

func SplitF(ck []uint16, n int, x uint16, y uint16, dict *base.Dictionary, q uint16, p int) []uint16 {
	res := make([]uint16, 2)
	z := base.GetHR(ck, x, y, uint16(n + 1), p)
	res[0] = z
	res[1] = base.DivideGF(1, dict.G[n][y][z], q)
	return res
}

func SplitF2(ck []uint16, n int, x uint16, y uint16, dict *base.Dictionary, q uint16, p int) []uint16 {
	res := make([]uint16, 2)
	z := base.GetHR(ck, x, y, uint16(n + 1), p)
	res[0] = z
	res[1] = base.DivideGF(1, dict.G[n][z][y], q)
	return res
}

func MoveF(ck []uint16, n int, x uint16, y uint16, y2 uint16, dict *base.Dictionary, q uint16, p int) []uint16 {
	res := make([]uint16, 2)
	z := base.GetH(ck, x, y, uint16(n + 1), p)
	a1 := dict.G[n][x][y]
	x2 := base.GetHR(ck, z, y2, uint16(n + 1), p)
	a2 := dict.G[n][x2][y2]
	res[0] = x2
	res[1] = base.DivideGF(a1, a2, q)
	return res
}

func Transfer(cipher *base.Cipher, tran *base.DictionaryTransfer, dict *base.Dictionary, p int) *base.Cipher {
	res := new(base.Cipher)
	q := tran.Q
	m := len(cipher.A)
	n := len(cipher.X[0])
	res.GenRandZero(m, n, int(q), p)
	for i := 0; i < m; i++ {
		cpi := res.GetCipherPart(i)
		// cpi.A = 0
		for j := 0; j < m; j++ {
			cpj := cipher.GetCipherPart(j)
			aj := cpj.A
			cpjz := tran.ZS[j].GetCipherPart(i)
			ajz := cpjz.A
			for k := 0; k < n; k++ {
				xjk := cpj.X[k]
				g := tran.G[i * m * n + j * n + k][xjk]
				yk := cpjz.X[k]
				cpjz.X[k] = base.GetHT(tran.TKey, xjk, yk, k, p)
				ajz = base.MultiGF(ajz, g, q)
			}
			cpjz.A = base.MultiGF(aj, ajz, q)
			if j == 0 {
				cpi = cpjz
			} else {
				cpi = AddCipherPart(cpi, cpjz, dict, q, p)
			}			
		}
		res.SetCipherPart(i, cpi)
	}
	return res
}

func TransferFixed(cipher *base.Cipher, tran *base.DictionaryTransfer, dict *base.Dictionary, p int, cipherT *base.Cipher) *base.Cipher {
	res := new(base.Cipher)
	q := dict.Q
	m := len(cipher.A)
	n := len(cipher.X[0])
	res.GenRandZero(m, n, int(q), p)

	res2 := new(base.Cipher)
	res2.IntRandFromCZero2(m, n, int(q), p, cipherT)

	for i := 0; i < m; i++ {
		// cpi := new(base.CipherPart)
		cpi := res.GetCipherPart(i)
		cpt := res2.GetCipherPart(i)
		// cpi.PrintCipher()
		// cpi.A = 0
		for j := 0; j < m; j++ {
			cpj := cipher.GetCipherPart(j)
			// cpj.PrintCipher()
			aj := cpj.A
			cpjz := tran.ZS[j].GetCipherPart(i)
			ajz := cpjz.A
			for k := 0; k < n; k++ {
				xjk := cpj.X[k]
				g := tran.G[i * m * n + j * n + k][xjk]
				yk := cpjz.X[k]
				cpjz.X[k] = base.GetHT(tran.TKey, xjk, yk, k, p)
				// fmt.Printf("%d, ", cpjz.X[k])
				ajz = base.MultiGF(ajz, g, q)
			}
			cpjz.A = base.MultiGF(aj, ajz, q)
			if j == 0 {
				cpi = cpjz
			} else {
				cpi = AddCipherPartTarget(cpi, cpjz, dict, int(q), p, cpt)
			}			
		}
		res.SetCipherPart(i, cpi)
	}
	return res
}

func EqualZero(cipher *base.Cipher, dict *base.DictionaryTransfer) uint16 {
	q := dict.Q
	// fmt.Println(q)
	m := len(dict.Z)
	n := len(dict.MKeyX)
	var x, b, c uint16
	res := 0
	for i := 0; i < m; i++ {
		a := cipher.A[i]
		x = 1
		for j := 0; j < n; j++ {
			x = base.MultiGF(x, base.GetHashF(cipher.X[i][j], dict.MKeyX[j], q), q)
			eij := dict.Ei[j][cipher.X[i][j]]
			if(i > 0 && j == 0) {
				er := dict.Er[cipher.X[0][j]][cipher.X[i][j]]
				eij = base.MultiGF(eij, er, q)
			}
			x = base.MultiGF(x, eij, q)
		}
		b = x
		c = base.MultiGF(a, b, q)
		c = base.MultiGF(c, dict.Z[i], q)
		ez := dict.Ez[i]
		c = base.MultiGF(c, ez, q)
		res += int(c)
	}
	return uint16(res % int(q))
}