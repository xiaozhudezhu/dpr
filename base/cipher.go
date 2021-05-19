package base

import (
	"fmt"
	"strconv"
	"math/rand"
	"encoding/asn1"
	"encoding/base64"
	"os"
	"io/ioutil"
)

type Cipher struct {
	X [][]uint16
	A []uint16
}

func (cipher *Cipher) GenRand(m int, n int, q int, p int) {
	cipher.A = make([]uint16, 0)
	cipher.X = make([][]uint16, 0)
	for i := 0; i < m; i++ {
		cipher.A = append(cipher.A, uint16(rand.Intn(q)))
		currX := make([]uint16, 0)
		for j := 0; j < n; j++ {
			currX = append(currX, uint16(rand.Intn(p)))
		}
		cipher.X = append(cipher.X, currX)
	}
}

func (cipher *Cipher) GenRandZero(m int, n int, q int, p int) {
	cipher.A = make([]uint16, 0)
	cipher.X = make([][]uint16, 0)
	for i := 0; i < m; i++ {
		cipher.A = append(cipher.A, uint16(0))
		currX := make([]uint16, 0)
		for j := 0; j < n; j++ {
			currX = append(currX, 1 + uint16(rand.Intn(p - 1)))
		}
		cipher.X = append(cipher.X, currX)
	}
}

func (cipher *Cipher) IntRandFromCZero2(m int, n int, q int, p int, ci *Cipher) {
	cipher.A = make([]uint16, 0)
	cipher.X = make([][]uint16, 0)
	for i := 0; i < m; i++ {
		cipher.A = append(cipher.A, 0)
		currX := make([]uint16, 0)
		for j := 0; j < n; j++ {
			xij := AddGF(ci.A[i], ci.X[i][j], uint16(q))
			xij = xij % uint16(p)
			currX = append(currX, xij)
		}
		cipher.X = append(cipher.X, currX)
	}
}

func (cipher *Cipher) IntRandFromC(m int, n int, q int, p int, ci *Cipher) {
	cipher.A = make([]uint16, 0)
	cipher.X = make([][]uint16, 0)
	for i := 0; i < m; i++ {
		cipher.A = append(cipher.A, uint16(rand.Intn(q)))
		currX := make([]uint16, 0)
		for j := 0; j < n; j++ {
			currX = append(currX, ci.X[i][j])
		}
		cipher.X = append(cipher.X, currX)
	}
}

func (cipher *Cipher) IntRandFromC2(m int, n int, q int, p int, ci *Cipher) {
	cipher.A = make([]uint16, 0)
	cipher.X = make([][]uint16, 0)
	// ci.PrintCipher()
	for i := 0; i < m; i++ {
		cipher.A = append(cipher.A, uint16(rand.Intn(q)))
		currX := make([]uint16, 0)
		for j := 0; j < n; j++ {
			xij := AddGF(ci.A[i], ci.X[i][j], uint16(q))
			xij = xij % uint16(p)
			currX = append(currX, xij)
		}
		cipher.X = append(cipher.X, currX)
	}
}

func (cipher *Cipher) IntRandFromCL(m int, n int, q int, p int, ci *Cipher) {
	cipher.A = make([]uint16, 0)
	cipher.X = make([][]uint16, 0)
	for i := 0; i < m; i++ {
		cipher.A = append(cipher.A, ci.A[i])
		currX := make([]uint16, 0)
		for j := 0; j < n; j++ {
			currX = append(currX, ci.X[i][j])
		}
		cipher.X = append(cipher.X, currX)
	}
	ci.A[len(ci.A) - 1] = uint16(rand.Intn(q))
}

func (cipher *Cipher) Marshal() []byte {
	res, err := asn1.Marshal(Cipher{cipher.X, cipher.A})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (cipher *Cipher) MarshalA() []byte {
	res, err := asn1.Marshal(cipher.A)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (cipher *Cipher) MarshalAL() []byte {
	res, err := asn1.Marshal(cipher.A[len(cipher.A) - 1])
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (cipher *Cipher) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, cipher)
	if err != nil {
		fmt.Println(err)
	}
}

func (cipher *Cipher) UnmarshalA(bin []byte) {
	_, err := asn1.Unmarshal(bin, &cipher.A)
	if err != nil {
		fmt.Println(err)
	}
}

func (cipher *Cipher) UnmarshalAL(bin []byte) {
	_, err := asn1.Unmarshal(bin, &cipher.A[len(cipher.A) - 1])
	if err != nil {
		fmt.Println(err)
	}
}

func (cipher *Cipher) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(cipher.Marshal())
	}
}

func (cipher *Cipher) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		cipher.Unmarshal(str)
	}
}

func (cipher *Cipher) ToString() string {
	res := "["
	for i := 0; i < len(cipher.A); i++ {
		res += "[" + strconv.FormatInt(int64(cipher.A[i]), 10) + ","
		for j := 0; j < len(cipher.X[i]); j++ {
			res += strconv.FormatInt(int64(cipher.X[i][j]), 10) + ","
		}
		res = res[0: len(res) - 1] + "],"
	}
	res = res[0: len(res) - 1] + "]"
	return res
}

func (cipher *Cipher) PrintCipher() {
	fmt.Println(cipher.ToString())
}

func (cipher *Cipher) Serialize() string {
	return base64.StdEncoding.EncodeToString(cipher.Marshal())
}

func (cipher *Cipher) Deserialize(cstr string) {
	bin, _ := base64.StdEncoding.DecodeString(cstr)
	cipher.Unmarshal(bin)
}

func (cipher *Cipher) GetCipherPart(ind int) *CipherPart {
	cipherPart := new(CipherPart)
	cipherPart.A = cipher.A[ind]
	cipherPart.X = make([]uint16, 0)
	for i := 0; i < len(cipher.X[ind]); i++ {
		cipherPart.X = append(cipherPart.X, cipher.X[ind][i])
	}
	return cipherPart
}

func (cipher *Cipher) SetCipherPart(ind int, cipherPart *CipherPart) {
	cipher.A[ind] = cipherPart.A
	for i := 0; i < len(cipherPart.X); i++ {
		cipher.X[ind][i] = cipherPart.X[i]
	}
}

func (cipher *Cipher) Clone() *Cipher {
	res := new(Cipher)
	res.A = make([]uint16, len(cipher.A))
	res.X = make([][]uint16, len(cipher.X))
	for i := 0; i < len(cipher.A); i++ {
		res.A[i] = cipher.A[i]
	}
	for i := 0; i < len(cipher.X); i++ {
		res.X[i] = make([]uint16, len(cipher.X[i]))
		for j := 0; j < len(cipher.X[i]); j++ {
			res.X[i][j] = cipher.X[i][j]
		}
	}
	return res
}