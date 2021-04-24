package keygen

import (
	"fmt"
	"math/rand"
	"dpr/base"
	"dpr/encdec"
)

func No() {
	fmt.Println()
}

func GenComputekey(n int, q int, p int) *base.Computekey {
	ck := new(base.Computekey)
	ck.Q = uint16(q)
	ck.Key = make([]uint16, 0)
	for i := 0; i < n * 2 + 6; i++ {
		ck.Key = append(ck.Key, uint16(rand.Intn(p)))
	}
	return ck
}

func GenTransferkey(n int, q int, p int) *base.Transferkey {
	tk := new(base.Transferkey)
	tk.Q = uint16(q)
	tk.Key = make([]uint16, 0)
	for i := 0; i < n; i++ {
		tk.Key = append(tk.Key, uint16(rand.Intn(p)))
	}
	return tk
}

func GenPrivkey(m int, n int, q int) *base.Privkey {
	sk := new(base.Privkey)
	sk.Q = uint16(q)
	sk.KeyX = make([]uint64, 0)
	sk.Z = make([]uint16, 0)
	for i := 0; i < n; i++ {
		sk.KeyX = append(sk.KeyX, uint64(rand.Intn(1000000000)))
	}
	for i := 0; i < m; i++ {
		sk.Z = append(sk.Z, uint16(1 + rand.Intn(q - 1)))
	}
	return sk
}

func GenPrivkeyFPart(n int, q int) *base.Privkey {
	sk := new(base.Privkey)
	sk.Q = uint16(q)
	sk.KeyX = make([]uint64, 0)
	sk.Z = make([]uint16, 0)
	for i := 0; i < n; i++ {
		sk.KeyX = append(sk.KeyX, uint64(rand.Intn(1000000000)))
	}
	return sk
}

func GenPrivkeyZPart(source []byte, m int, q int) *base.Privkey {
	sk := new(base.Privkey)
	sk.Q = uint16(q)
	sk.KeyX = make([]uint64, 0)
	sk.Z = make([]uint16, 0)
	sl := len(source)
	for i := 0; i < m; i++ {
		sk.Z = append(sk.Z, uint16(source[i * q % sl]))
	}
	return sk
}

func GenPubkey(sk *base.Privkey, p int) *base.Pubkey {
	q := sk.Q
	m := len(sk.Z)
	n := len(sk.KeyX)
	pk := new(base.Pubkey)
	pk.Q = q
	pk.KeyX = make([]uint64, 0)
	for i := 0; i < n; i++ {
		pk.KeyX = append(pk.KeyX, uint64(rand.Intn(1000000000)))
	}
	pk.Z = uint16(1 + rand.Intn(int(q) - 1))
	zc := encdec.Encode(pk.Z, sk, p)
	pk.ZC = *zc
	pk.TG = make([][]uint16, m * n)
	pk.TK = make([]uint16, n)
	for i := 0; i < n; i++ {
		pk.TK = append(pk.TK, uint16(rand.Intn(p)))
	}
	ind := 0
	for i := 0; i < m; i++ {
		for j := 0; j < n; j++ {
			x := uint16(0)
			y := zc.X[i][j]
			pk.TG[ind] = make([]uint16, p)
			for x = 0; x < uint16(p); x++ {
				pk.TG[ind][x] = base.MultiDivideGF(base.GetHashF(x, pk.KeyX[j], q), base.GetHashF(y, sk.KeyX[j], q), base.GetHashF(base.GetHT(pk.TK, x, y, j, p), sk.KeyX[j], q), q)
			}
			ind++
		}
		
	}
	return pk
}

func GenMirrkey(sk *base.Privkey, p int) *base.Mirrkey {
	n := int(len(sk.KeyX))
	m := int(len(sk.Z))
	q := int(sk.Q)
	mk := new(base.Mirrkey)
	mk.Q = sk.Q
	mk.KeyX = make([]uint64, 0)
	mk.Z = make([]uint16, 0)
	mk.Ei = make([][]uint16, n)
	mk.Er = make([][]uint16, p)
	mk.Ez = make([]uint16, m)
	for i := 0; i < n; i++ {
		mk.KeyX = append(mk.KeyX, uint64(rand.Intn(1000000000)))
	}
	for i := 0; i < m; i++ {
		mk.Z = append(mk.Z, uint16(1 + rand.Intn(q - 1)))
	}
	keyR1 := uint64(rand.Intn(1000000000))
	for i := 0; i < n; i++ {
		ri := uint16(1 + rand.Intn(q - 1))
		mk.Ei[i] = make([]uint16, 0)
		for j := 0; j < p; j++ {
			rij := ri
			if(i == 0) {
				rij = base.GetHashF(uint16(j), keyR1, uint16(q))
			}
			fij := base.GetHashF(uint16(j), sk.KeyX[i], uint16(q))
			fijp := base.GetHashF(uint16(j), mk.KeyX[i], uint16(q))
			mk.Ei[i] = append(mk.Ei[i], base.MultiDivideGF(rij, fij, fijp, uint16(q)))
		}
	}
	rz := uint16(1 + rand.Intn(q - 1))
	for i := 0; i < m; i++ {
		mk.Ez[i] = base.MultiDivideGF(rz, sk.Z[i], mk.Z[i], uint16(q))
	}
	for i := 0; i < p; i++ {
		mk.Er[i] = make([]uint16, p)
		for j := 0; j < p; j++ {
			mk.Er[i][j] = base.DivideGF(base.GetHashF(uint16(i), keyR1, uint16(q)), base.GetHashF(uint16(j), keyR1, uint16(q)), uint16(q))
		}
	}
	return mk
}

func GenDictionary(sk *base.Privkey, m int, n int, p int) *base.Dictionary {
	// Version 4.3
	q := sk.Q
	dict := new(base.Dictionary)
	dict.Dims = make([]uint16, 3)
	dict.Dims[0] = uint16(n * 2 + 6)
	dict.Dims[1] = uint16(p)
	dict.Dims[2] = uint16(p)
	dict.G = make([][][]uint16, dict.Dims[0])
	dict.CS = make([]base.Cipher, 0)
	for i := 0; i < m; i++ {
		for j := 0; j < m; j++ {
			zz := base.MultiGF(sk.Z[i], sk.Z[j], q)
			czz := encdec.Encode(zz, sk, p)
			dict.CS = append(dict.CS, *czz)
		}
	}
	for i := 0; i < int(dict.Dims[0]); i++ {
		dict.G[i] = make([][]uint16, dict.Dims[1])
		for j := 0; j < int(dict.Dims[1]); j++ {
			dict.G[i][j] = make([]uint16, dict.Dims[2])
		}
	}
	// Computekey
	dict.CKey = make([]uint16, 0)
	for i := 0; i < n * 2 + 6; i++ {
		dict.CKey = append(dict.CKey, uint16(rand.Intn(p)))
	}
	dict.Q = q
	// G
	keys := make([]uint64, 0)
	for i := 0; i < 2 * n + 5; i++ {
		keys = append(keys, uint64(rand.Intn(1000000000)))
	}
	var x, y uint16
	for x = 0; x < uint16(p); x++ {
		for y = 0; y < uint16(p); y++ {
			// Add Part
			g1 := base.MultiDivideGF(base.GetHashF(x, keys[0], q), base.GetHashF(y, keys[1], q), base.GetHashF(base.GetH(dict.CKey, x, y, 1, p), sk.KeyX[0], q), q)
			dict.G[0][x][y] = g1
			for i := 1; i < n; i++ {
				dict.G[i][x][y] = base.MultiDivideGF(base.GetHashF(x, keys[1], q), base.GetHashF(y, sk.KeyX[i], q), base.GetHashF(base.GetH(dict.CKey, x, y, uint16(i + 1), p), keys[i + 1], q), q)
			}
			gd := base.AddDivideGF(base.GetHashF(x, keys[n], q), base.GetHashF(y, keys[n], q), base.GetHash2F(y, base.GetH(dict.CKey, x, y, uint16(n + 1), p), keys[n + 1], keys[n + 2], q), q)
			dict.G[n][x][y] = gd
			g2 := base.MultiDivideGF(base.GetHashF(x, sk.KeyX[n - 1], q), base.GetHashF(y, keys[n + 3], q), base.GetHashF(base.GetH(dict.CKey, x, y, uint16(n + 2), p), keys[0], q), q)
			dict.G[n + 1][x][y] = g2
			g3 := base.MultiDivideGF(base.GetHash2F(x, y, keys[n + 1], keys[n + 2], q), base.GetHashF(y, keys[n + 3], q), base.GetHashF(y, sk.KeyX[0], q), q)
			dict.G[n + 2][x][y] = g3
			g4 := base.MultiDivideGF(base.GetHashF(x, keys[n], q), base.GetHashF(y, keys[n + 3], q), base.GetHashF(y, sk.KeyX[0], q), q)
			dict.G[n + 3][x][y] = g4
			// Multiply Part
			g5 := base.MultiDivideGF(base.GetHashF(x, keys[1], q), base.GetHashF(y, keys[1], q), base.GetHashF(base.GetH(dict.CKey, x, y, uint16(n + 3), p), sk.KeyX[0], q), q)
			dict.G[n + 4][x][y] = base.DivideGF(g5, base.GetHashF(base.GetH(dict.CKey, x, y, uint16(n + 3), p), keys[n + 4], q), q)
			for i := 1; i < n - 1; i++ {
				gi1 := base.MultiGF(base.GetHashF(x, sk.KeyX[i], q), base.GetHashF(x, sk.KeyX[i], q), q)
				gi2 := base.MultiDivideGF(gi1, base.GetHashF(y, keys[n + 3 + i], q), base.GetHashF(base.GetH(dict.CKey, x, y, uint16(n + 3 + i), p), keys[n + 4 + i], q), q)
				gi3 := base.DivideGF(gi2, base.GetHashF(base.GetH(dict.CKey, x, y, uint16(n + 3 + i), p), sk.KeyX[i], q), q)
				dict.G[n + 4 + i][x][y] = gi3
			}
			g6 := base.MultiGF(base.GetHashF(x, sk.KeyX[n - 1], q), base.GetHashF(y, sk.KeyX[n - 1], q), q)
			dict.G[n * 2 + 3][x][y] = base.MultiDivideGF(g6, base.GetHashF(base.GetH(dict.CKey, x, y, uint16(2 * n + 2), p), keys[0], q), base.GetHashF(base.GetH(dict.CKey, x, y, uint16(2 * n + 2), p), keys[2 * n + 2], q), q)
			g7 := base.MultiGF(base.GetHashF(x, keys[2 * n + 2], q), base.GetHashF(y, keys[2 * n + 2], q), q)
			dict.G[n * 2 + 4][x][y] = base.MultiDivideGF(g7, base.GetHashF(x, keys[0], q), base.GetHashF(base.GetH(dict.CKey, x, y, uint16(2 * n + 4), p), sk.KeyX[n - 1], q), q)
		}
	}
	// Mirrkey
	dict.MKeyX = make([]uint64, 0)
	dict.Z = make([]uint16, 0)
	dict.Ei = make([][]uint16, n)
	dict.Er = make([][]uint16, p)
	dict.Ez = make([]uint16, m)
	for i := 0; i < n; i++ {
		dict.MKeyX = append(dict.MKeyX, uint64(rand.Intn(1000000000)))
	}
	for i := 0; i < m; i++ {
		dict.Z = append(dict.Z, uint16(1 + rand.Intn(int(q) - 1)))
	}
	keyR1 := uint64(rand.Intn(1000000000))
	for i := 0; i < n; i++ {
		ri := uint16(1 + rand.Intn(int(q) - 1))
		dict.Ei[i] = make([]uint16, 0)
		for j := 0; j < p; j++ {
			rij := ri
			if(i == 0) {
				rij = base.GetHashF(uint16(j), keyR1, uint16(q))
			}
			fij := base.GetHashF(uint16(j), sk.KeyX[i], uint16(q))
			fijp := base.GetHashF(uint16(j), dict.MKeyX[i], uint16(q))
			dict.Ei[i] = append(dict.Ei[i], base.MultiDivideGF(rij, fij, fijp, uint16(q)))
		}
	}
	rz := uint16(1 + rand.Intn(int(q) - 1))
	for i := 0; i < m; i++ {
		dict.Ez[i] = base.MultiDivideGF(rz, sk.Z[i], dict.Z[i], uint16(q))
	}
	for i := 0; i < p; i++ {
		dict.Er[i] = make([]uint16, p)
		for j := 0; j < p; j++ {
			dict.Er[i][j] = base.DivideGF(base.GetHashF(uint16(i), keyR1, uint16(q)), base.GetHashF(uint16(j), keyR1, uint16(q)), uint16(q))
		}
	}
	return dict
}

func GenDictionaryTransfer(sk1 *base.Privkey, sk2 *base.Privkey, m int, n int, p int) *base.DictionaryTransfer {
	q := sk1.Q
	dict := new(base.DictionaryTransfer)
	dict.Dims = make([]uint16, 2)
	dict.Dims[0] = uint16(m * m * n)
	dict.Dims[1] = uint16(p)
	dict.G = make([][]uint16, dict.Dims[0])
	dict.ZS = make([]base.Cipher, m)
	for i := 0; i < m; i++ {
		dict.ZS[i] = *encdec.Encode(sk1.Z[i], sk2, p)
	}
	// Transferkey
	dict.TKey = make([]uint16, 0)
	for i := 0; i < n; i++ {
		dict.TKey = append(dict.TKey, uint16(rand.Intn(p)))
	}
	dict.Q = q
	// G
	ind := 0
	for i := 0; i < m; i++ {
		for j := 0; j < m; j++ {
			for k := 0; k < n; k++ {
				var x, y uint16
				y = dict.ZS[j].X[i][k]
				dict.G[ind] = make([]uint16, p)
				for x = 0; x < uint16(p); x++ {
					dict.G[ind][x] = base.MultiDivideGF(base.GetHashF(x, sk1.KeyX[k], q), base.GetHashF(y, sk2.KeyX[k], q), base.GetHashF(base.GetHT(dict.TKey, x, y, k, p), sk2.KeyX[k], q), q)
				}
				ind++
			}
		}
	}
	return dict
}