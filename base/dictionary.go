package base

import (
	"fmt"
	// "bytes"
	// "encoding/binary"
	"encoding/asn1"
	"os"
	"io/ioutil"
)

type Dictionary struct {
	Dims []uint16
	G [][][]uint16
	CS []Cipher
	// Computekey
	CKey []uint16
	Q uint16
	// Mirrkey	
	MKeyX []uint64
	Z []uint16
	Ei, Er [][]uint16
	Ez []uint16
}

func (dict *Dictionary) Marshal() []byte {
	res, err := asn1.Marshal(Dictionary{dict.Dims, dict.G, dict.CS, dict.CKey, dict.Q, dict.MKeyX, dict.Z, dict.Ei, dict.Er, dict.Ez})
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return res
}

func (dict *Dictionary) Unmarshal(bin []byte) {
	_, err := asn1.Unmarshal(bin, dict)
	if err != nil {
		fmt.Println(err)
	}
}

func (dict *Dictionary) ToFile(fileName string) {
	file, err := os.Create(fileName)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		file.Write(dict.Marshal())
	}
}

func (dict *Dictionary) FromFile(fileName string) {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	defer file.Close()
	if err != nil {
		fmt.Println(err)
	} else {
		str, _ := ioutil.ReadAll(file)
		dict.Unmarshal(str)
	}
}