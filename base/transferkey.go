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

type Transferkey struct {
	Key []uint16
	Q uint16
}

func (tk *Transferkey) ToString() string {
	var res string
	res = "[" + strconv.FormatInt(int64(tk.Q), 10) + ",["
	for i := 0; i < len(tk.Key); i++ {
		res += strconv.FormatInt(int64(tk.Key[i]), 10) + ","
	}
	res = res[0: len(res) - 1] + "]]"
	return res
}

func (tk *Transferkey) PrintKey() {
	fmt.Println(tk.ToString())
}

func (tk *Transferkey) Marshal() []byte {
	res, err := asn1.Marshal(Transferkey{tk.Key, tk.Q})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (tk *Transferkey) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, tk)
	if err != nil {
		fmt.Println(err)
	}
}

func (tk *Transferkey) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(tk.Marshal())
	}
}

func (tk *Transferkey) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		tk.Unmarshal(str)
	}
}