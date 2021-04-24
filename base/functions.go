package base

import (
	// "math"
	// "math/rand"
	"fmt"
	// "encoding/hex"
	"encoding/binary"
	// "crypto/sha256"
	// "crypto/md5"
	"dpr/sm3"
)

func No() {
	fmt.Println()
}

func MultiGF(x uint16, y uint16, q uint16) uint16 {
	res := uint16((int(x) * int(y)) % int(q))
	return res
}

func AddGF(x uint16, y uint16, q uint16) uint16 {
	res := uint16((int(x) + int(y)) % int(q))
	return res
}

func DivideGF(x uint16, y uint16, q uint16) uint16 {
	r := ReverseGF(y, q)
	res := MultiGF(r, x, q)
	return res
}

func ReverseGF(x uint16, q uint16) uint16 {
	res := int16(0)
	res2 := make([]int16, 0)
	qi := int16(q)
	xi := int16(x)
	if(xi == 0) {
		return uint16(0)
	}
	for ;; {
		resi := int16(qi - qi / xi * xi)
		if(resi == 0) {
			break
		} else {
			res2 = append(res2, int16(qi / xi))
			qi = xi
			xi = resi
		}
	}
	if(len(res2) >= 2) {
		a1 := int16(1)
		a2 := -1 * res2[len(res2) - 1]
		for i := len(res2) - 2; i >= 0; i-- {
			t := a1
			a1 = a2
			a2 = t - a2 * res2[i]
		}
		if(len(res2) % 2 == 0) {
			res = a2
		} else {
			res = a2	
		}
	} else if(len(res2) == 1) {
		a2 := -1 * res2[len(res2) - 1]
		res = a2
	} else {
		if(x == 1) {
			res = 1
		}
	}
	if(res < 0) {
		res = res + int16(q)
	}
	return uint16(res)
}

func DivideGFD(x uint16, y uint16, q uint16) []uint16 {
	res := make([]uint16, 2)
	res[0] = 0
	res[1] = 0
	for i := 1; i < int(q); i++ {
		for j := 1; j < int(q); j++ {
			if(MultiGF(uint16(j), y, q) == MultiGF(uint16(i), x, q)) {
				res[0] = uint16(i)
				res[1] = uint16(j)
			}
		}
	}
	return res
}

func MultiDivideGF(x uint16, y uint16, z uint16, q uint16) uint16 {
	xy := MultiGF(x, y, q)
	res := DivideGF(xy, z, q)
	return res
}

func AddDivideGF(x uint16, y uint16, z uint16, q uint16) uint16 {
	xy := AddGF(x, y, q)
	res := DivideGF(xy, z, q)
	return res
}

func GetHashF(x uint16, key uint64, q uint16) uint16 {
	return GetHashFSM3(x, key, q)
}

func GetHash2F(x uint16, y uint16, key1 uint64, key2 uint64, q uint16) uint16 {
	p1 := GetHashFSM3(x, key1, q)
	p2 := GetHashFSM3(y, key2, q)
	return MultiGF(p1, p2, q)
}

func GetHashFSM3(x uint16, key uint64, q uint16) uint16 {
	d := sm3.New()
	d.Write(int64ToBytes(int64(key) + int64(x)))
	hash := d.Sum(nil)
	v := bytesToUint8SM3(hash, q)
	return v
}

func GetSM3(str string) []byte {
	d := sm3.New()
	d.Write([]byte(str))
	return d.Sum(nil)
}

func int64ToBytes(i int64) []byte {
    var buf = make([]byte, 8)
    binary.BigEndian.PutUint64(buf, uint64(i))
    return buf
}

func bytesToUint8SM3(buf []byte, q uint16) uint16 {
	fx := binary.LittleEndian.Uint64(buf[:])
	v := uint16(fx % uint64(q - 1) + 1)
    return v
}

func Uint16ToBytes(n uint16) []byte {
   return []byte{
      byte(n % 16),
      byte(n / 16),
   }
}

func GetH(ck []uint16, x uint16, y uint16, n uint16, p int) uint16 {
	n2 := ck[n]
	res := int(x) + int(y) + int(n2)
	for ;; {
		if(res >= p) {
			res -= p
		} else {
			break
		}
	}
	return uint16(res)
}

func GetHR(ck []uint16, x uint16, y uint16, n uint16, p int) uint16 {
	n2 := ck[n]
	res := int(x) - int(y) - int(n2)
	for ;; {
		if(res < 0) {
			res += p
		} else {
			break
		}
	}
	return uint16(res)
}

func GetHT(tk []uint16, x uint16, y uint16, n int, p int) uint16 {
	n2 := tk[n]
	res := int(x) + int(y) + int(n2)
	for ;; {
		if(res >= p) {
			res -= p
		} else {
			break
		}
	}
	return uint16(res)
}
