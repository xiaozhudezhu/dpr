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

type Computekey struct {
	Key []uint16
	Q uint16
}

func (ck *Computekey) ToString() string {
	var res string
	res = "[" + strconv.FormatInt(int64(ck.Q), 10) + ",["
	for i := 0; i < len(ck.Key); i++ {
		res += strconv.FormatInt(int64(ck.Key[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "]]"
	return res
}

func (ck *Computekey) PrintKey() {
	fmt.Println(ck.ToString())
}

func (ck *Computekey) Marshal() []byte {
	res, err := asn1.Marshal(Computekey{ck.Key, ck.Q})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (ck *Computekey) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, ck)
	if err != nil {
		fmt.Println(err)
	}
}

func (ck *Computekey) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(ck.Marshal())
	}
}

func (ck *Computekey) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		ck.Unmarshal(str)
	}
}