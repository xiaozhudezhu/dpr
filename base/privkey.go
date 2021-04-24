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

type Privkey struct {
	KeyX []uint64
	Z []uint16
	Q uint16
}

func (sk *Privkey) ToString() string {
	var res string
	res = "[" + strconv.FormatInt(int64(sk.Q), 10) + ",["
	if len(sk.KeyX) == 0 {
		res += " "
	}
	for i := 0; i < len(sk.KeyX); i++ {
		res += strconv.FormatInt(int64(sk.KeyX[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "],["
	if len(sk.Z) == 0 {
		res += " "
	}
	for i := 0; i < len(sk.Z); i++ {
		res += strconv.FormatInt(int64(sk.Z[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "]]"
	return res
}

func (sk *Privkey) PrintKey() {
	fmt.Println(sk.ToString())
}

func (sk *Privkey) Marshal() []byte {
	res, err := asn1.Marshal(Privkey{sk.KeyX, sk.Z, sk.Q})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (sk *Privkey) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, sk)
	if err != nil {
		fmt.Println(err)
	}
}

func (sk *Privkey) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(sk.Marshal())
	}
}

func (sk *Privkey) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		sk.Unmarshal(str)
	}
}