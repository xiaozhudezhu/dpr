
package main

import (
	// "encoding/json"
	"fmt"
	"time"
	// "math"
	// "os"
	// "io/ioutil"
	"math/rand"
	// "strconv"
	"dpr/base"
	"dpr/encdec"
	"dpr/keygen"
	"dpr/cipheropt"
	// "github.com/syndtr/goleveldb/leveldb"
	// "math/big"
	// "reflect"
	// "encoding/asn1"
	// "strings"
)

func main() {
	sk := new(base.Privkey)
	sk2 := new(base.Privkey)

	m := 2
	n := 2
	q := 521
	p := 128

	GenSKFpart(time.Now().UnixNano(), n, q, "test_0415_1.skf")
	sk.FromFile("test_0415_1.skf")
	sk.PrintKey()

	GenSKZpart(time.Now().UnixNano(), base.GetSM3("hello world"), m, q, "test_0415_1.skz")
	sk.FromFile("test_0415_1.skz")
	sk.PrintKey()

	ComposeSK("test_0415_1.skf", "test_0415_1.skz", "test_0415_1.stk")
	sk.FromFile("test_0415_1.stk")
	sk.PrintKey()

	GenSK(time.Now().UnixNano(), m, n, q, "test_0415_1.stk")
	sk.FromFile("test_0415_1.stk")
	sk.PrintKey()

	GenDictionary("test_0415_1.stk", m, n, p, "test_0415_1.dict")
	dict := new(base.Dictionary)
	dict.FromFile("test_0415_1.dict")

	res := EncString("Hello World!", "test_0415_1.stk", p)
	fmt.Println(string(res))
	fmt.Println(len(res))
	// fmt.Println(len(res))
	res2 := DecString(res, "test_0415_1.stk")
	fmt.Println(res2)

	GenSK(time.Now().UnixNano(), m, n, q, "test_0415_2.stk")
	sk2.FromFile("test_0415_2.stk")
	sk2.PrintKey()

	GenDictionary("test_0415_2.stk", m, n, p, "test_0415_2.dict")
	dict2 := new(base.Dictionary)
	dict2.FromFile("test_0415_2.dict")

	GenTransferDictSS("test_0415_1.stk", "test_0415_2.stk", m, n, p, "test_0415_1-2.tran")
	tran := new(base.DictionaryTransfer)
	tran.FromFile("test_0415_1-2.tran")

	m1 := uint16(rand.Intn(256))
	fmt.Println(m1)
	c1 := encdec.Encode(m1, sk, p)
	p1 := encdec.Decode(c1, sk)
	fmt.Println(p1)
	c2 := cipheropt.Transfer(c1, tran, dict2, p)
	p2 := encdec.Decode(c2, sk2)
	fmt.Println(p2)

	// fmt.Println(len(res))
	res3 := TranSS(res, "test_0415_1-2.tran", "test_0415_2.dict", p)
	// fmt.Println(res3)
	res4 := DecString(res3, "test_0415_2.stk")
	fmt.Println(res4)

	m3 := uint16(rand.Intn(256))
	fmt.Println(m3)
	c3 := encdec.Encode(m3, sk, p)
	p3 := encdec.Decode(c3, sk)
	fmt.Println(p3)
	fmt.Println(m1 + m3)
	c4 := cipheropt.AddCipher(c1, c3, dict, uint16(q), p)
	p4 := encdec.Decode(c4, sk)
	fmt.Println(p4)
	if m1 > m3 {
		fmt.Println(m1 - m3)
	} else {
		fmt.Println(m1 + uint16(q) - m3)
	}
	c5 := cipheropt.SubstractCipher(c1, c3, dict, uint16(q), p)
	p5 := encdec.Decode(c5, sk)
	fmt.Println(p5)

	res5 := EncString("Hello World!", "test_0415_1.stk", p)
	fmt.Println(DecString(res5, "test_0415_1.stk"))
	eq := EqualString(res, res5, "test_0415_1.dict", p)
	fmt.Println(eq)

	sk.FromFile("test_0415_1.stk")
	GenPK(time.Now().UnixNano(), "test_0415_1.stk", p, "test_0415_1.pck")
	pk := new(base.Pubkey)
	pk.FromFile("test_0415_1.pck")
	// fmt.Println(pk)
	m6 := uint16(rand.Intn(256))
	fmt.Println(m6)
	c6 := encdec.EncodePublic(m6, pk, sk, m, p)
	p6 := encdec.Decode(c6, sk)
	fmt.Println(p6)
}

func GenSKFpart(seed int64, n int, q int, filename string) {
	rand.Seed(seed)
	sk := keygen.GenPrivkeyFPart(n, q)
	sk.ToFile(filename)
}

func GenSKZpart(seed int64, hashstr []byte, m int, q int, filename string) {
	rand.Seed(seed)
	sk := keygen.GenPrivkeyZPart(hashstr, m, q)
	sk.ToFile(filename)
}

func ComposeSK(fpart string, zpart string, filename string) {
	sk1 := new(base.Privkey)
	sk1.FromFile(fpart)
	sk2 := new(base.Privkey)
	sk2.FromFile(zpart)
	sk1.Z = sk2.Z
	sk1.ToFile(filename)
}

func GenSK(seed int64, m int, n int, q int, filename string) {
	rand.Seed(seed)
	sk := keygen.GenPrivkey(m, n, q)
	sk.ToFile(filename)
}

func GenPK(seed int64, skfile string, p int, filename string) {
	rand.Seed(seed)
	sk := new(base.Privkey)
	sk.FromFile(skfile)
	pk := keygen.GenPubkey(sk, p)
	pk.ToFile(filename)
}

func GenDictionary(skfile string, m int, n int, p int, filename string) {
	sk := new(base.Privkey)
	sk.FromFile(skfile)
	dict := new(base.Dictionary)
	dict = keygen.GenDictionary(sk, m, n, p)
	dict.ToFile(filename)
}

func GenTransferDictSS(sk_out string, sk_in string, m int, n int, p int, filename string) {
	sk1 := new(base.Privkey)
	sk1.FromFile(sk_out)
	sk2 := new(base.Privkey)
	sk2.FromFile(sk_in)
	dictTrans := new(base.DictionaryTransfer)
	dictTrans = keygen.GenDictionaryTransfer(sk1, sk2, m, n, p)
	dictTrans.ToFile(filename)
}

func EncString(message string, skfile string, p int) []byte {
	res := make([]byte, 0)
	sk := new(base.Privkey)
	sk.FromFile(skfile)
	messBytes := []byte(message)
	for i := 0; i < len(messBytes); i++ {
		ci := encdec.Encode(uint16(messBytes[i]), sk, p)
		cibin := ci.Marshal()
		l := len(cibin)
		res = append(res, uint8(1))
		res = append(res, base.Uint16ToBytes(uint16(l))[0])
		res = append(res, base.Uint16ToBytes(uint16(l))[1])
		for j := 0; j < l; j++ {
			res = append(res, cibin[j])
		}
	}
	return res
}

func encAsyncString(message string, pkfile string, p int) string {
	// to be added
	return ""
}

func DecString(cipher []byte, skfile string) string {
	res := make([]byte, 0)
	sk := new(base.Privkey)
	sk.FromFile(skfile)
	cs := bytesToCiphers(cipher)
	for i := 0; i < len(cs); i++ {
		ci := cs[i]
		res = append(res, byte(encdec.Decode(ci, sk)))
	}
	return string(res)
}

func TranSS(cipher []byte, tranfile string, dictfile string, p int) []byte {
	res := make([]byte, 0)
	tran := new(base.DictionaryTransfer)
	tran.FromFile(tranfile)
	dict := new(base.Dictionary)
	dict.FromFile(dictfile)
	cs := bytesToCiphers(cipher)
	for i := 0; i < len(cs); i++ {
		ci := cs[i]
		ci2 := cipheropt.Transfer(ci, tran, dict, p)
		ci2bin := ci2.Marshal()
		l2 := len(ci2bin)
		res = append(res, uint8(1))
		res = append(res, base.Uint16ToBytes(uint16(l2))[0])
		res = append(res, base.Uint16ToBytes(uint16(l2))[1])
		for j := 0; j < l2; j++ {
			res = append(res, ci2bin[j])
		}
	}
	return res
}

func bytesToCiphers(cipher []byte) []*base.Cipher {
	res := make([]*base.Cipher, 0)
	for i := 0; i < len(cipher); {
		ci := new(base.Cipher)
		cibin := make([]byte, 0)
		l := 0
		if int(cipher[i]) != 1 {
			break
		} else {
			lbin := make([]byte, 2)
			lbin[0] = cipher[i + 1]
			lbin[1] = cipher[i + 2]
			l = int(lbin[0]) + int(lbin[1]) * 16
			// fmt.Println(l)
		}
		for j := 0; j < l; j++ {
			cibin = append(cibin, cipher[i + 3 + j])
		}
		ci.Unmarshal(cibin)
		res = append(res, ci)		
		i += 3 + l
	}
	return res
}

func EqualString(c1 []byte, c2 []byte, dictfile string, p int) bool {
	cs1 := bytesToCiphers(c1)
	cs2 := bytesToCiphers(c2)
	if(len(cs1) != len(cs2)) {
		return false
	}
	dict := new(base.Dictionary)
	dict.FromFile(dictfile)
	q := dict.Q
	for i := 0; i < len(cs1); i++ {
		ci := cipheropt.SubstractCipher(cs1[i], cs2[i], dict, q, p)
		mi := cipheropt.EqualZero(ci, dict)
		if mi != 0 {
			return false
		}
	}
	return true
}