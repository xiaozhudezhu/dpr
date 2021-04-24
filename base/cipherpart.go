package base

import (
	"fmt"
	"strconv"
)

type CipherPart struct {
	X []uint16
	A uint16
}

func (cipherPart *CipherPart) ToString() string {
	res := "[" + strconv.FormatInt(int64(cipherPart.A), 10) + ","
	for i := 0; i < len(cipherPart.X); i++ {
		res += strconv.FormatInt(int64(cipherPart.X[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "]"
	return res
}

func (cipherPart *CipherPart) PrintCipher() {
	fmt.Println(cipherPart.ToString())
}

func (cipherPart *CipherPart) Copy() *CipherPart {
	res := new(CipherPart)
	res.A = cipherPart.A
	res.X = make([]uint16, 0)
	for i := 0; i < len(cipherPart.X); i++ {
		res.X = append(res.X, cipherPart.X[i])
	}
	return res
}