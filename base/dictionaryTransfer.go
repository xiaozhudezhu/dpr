package base

import (
	"fmt"
	// "bytes"
	// "encoding/binary"
	"encoding/asn1"
	"os"
	"io/ioutil"
)

type DictionaryTransfer struct {
	Dims []uint16
	G [][]uint16
	// G0 [][]uint16
	// G1 [][]uint16
	ZS []Cipher
	// Transferkey
	TKey []uint16
	Q uint16
	// Mirrkey	
	MKeyX []uint64
	Z []uint16
	Ei, Er [][]uint16
	Ez []uint16
}

func (dict *DictionaryTransfer) Marshal() []byte {
	// res, err := asn1.Marshal(DictionaryTransfer{dict.Dims, dict.G, dict.G0, dict.G1, dict.ZS, dict.TKey, dict.Q, dict.MKeyX, dict.Z, dict.Ei, dict.Er, dict.Ez})
	res, err := asn1.Marshal(DictionaryTransfer{dict.Dims, dict.G, dict.ZS, dict.TKey, dict.Q, dict.MKeyX, dict.Z, dict.Ei, dict.Er, dict.Ez})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (dict *DictionaryTransfer) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, dict)
	if err != nil {
		fmt.Println(err)
	}
}

func (dict *DictionaryTransfer) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(dict.Marshal())
	}
}

func (dict *DictionaryTransfer) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		dict.Unmarshal(str)
	}
}