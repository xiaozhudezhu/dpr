package base

import (
	"fmt"
	// "encoding/json"
	"strconv"
	// "os"
	// "io/ioutil"
	// "bytes"
	// "encoding/binary"
	"encoding/asn1"
	"os"
	"io/ioutil"
)

type Mirrkey struct {
	KeyX []uint64
	Z []uint16
	Q uint16
	Ei, Er [][]uint16
	Ez []uint16
}

func (mk *Mirrkey) ToString() string {
	var res string
	res = "[" + strconv.FormatInt(int64(mk.Q), 10) + ",["
	for i := 0; i < len(mk.KeyX); i++ {
		res += strconv.FormatInt(int64(mk.KeyX[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "],["
	for i := 0; i < len(mk.Z); i++ {
		res += strconv.FormatInt(int64(mk.Z[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "],["
	for i := 0; i < len(mk.Ei); i++ {
		for j := 0; j < len(mk.Ei[i]); j++ {
			res += strconv.FormatInt(int64(mk.Ei[i][j]), 10) + ","
		}
		res = res[0: len(res) - 1] + "],["
	}
	for i := 0; i < len(mk.Er); i++ {
		for j := 0; j < len(mk.Er[i]); j++ {
			res += strconv.FormatInt(int64(mk.Er[i][j]), 10) + ","
		}
		res = res[0: len(res) - 1] + "],["
	}
	for i := 0; i < len(mk.Ez); i++ {
		res += strconv.FormatInt(int64(mk.Ez[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "]"
	return res
}

func (mk *Mirrkey) PrintKey() {
	fmt.Println(mk.ToString())
}

func (mk *Mirrkey) Marshal() []byte {
	res, err := asn1.Marshal(Mirrkey{mk.KeyX, mk.Z, mk.Q, mk.Ei, mk.Er, mk.Ez})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (mk *Mirrkey) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, mk)
	if err != nil {
		fmt.Println(err)
	}
}

func (mk *Mirrkey) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(mk.Marshal())
	}
}

func (mk *Mirrkey) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		mk.Unmarshal(str)
	}
}