package base

import (
	"fmt"
	// "encoding/json"
	"strconv"
	"encoding/asn1"
	"os"
	"io/ioutil"
	// "bytes"
	// "encoding/binary"
)

type Pubkey struct {
	KeyX []uint64
	Z uint16
	ZC Cipher
	Q uint16
	TG [][]uint16
	TK []uint16
}

func (pk *Pubkey) ToString() string {
	var res string
	res = "[" + strconv.FormatInt(int64(pk.Q), 10) + ",["
	if len(pk.KeyX) == 0 {
		res += " "
	}
	for i := 0; i < len(pk.KeyX); i++ {
		res += strconv.FormatInt(int64(pk.KeyX[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "],["
	res += strconv.FormatInt(int64(pk.Z), 10) + "],["
	res += pk.ZC.ToString() + "]]"
	return res
}

func (pk *Pubkey) PrintKey() {
	fmt.Println(pk.ToString())
}

func (pk *Pubkey) Marshal() []byte {
	res, err := asn1.Marshal(Pubkey{pk.KeyX, pk.Z, pk.ZC, pk.Q, pk.TG, pk.TK})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (pk *Pubkey) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, pk)
	if err != nil {
		fmt.Println(err)
	}
}

func (pk *Pubkey) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(pk.Marshal())
	}
}

func (pk *Pubkey) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		pk.Unmarshal(str)
	}
}