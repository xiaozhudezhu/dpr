package main

// #include <stdlib.h>
import "C"
import "unsafe"

import (
	// "fmt"
	"time"
	// "math/rand"
	"dpr/base"
	// "dpr/encdec"
	// "dpr/keygen"
	// "dpr/cipheropt"
	"encoding/base64"
	"dpr/lib"
)

var p int = 128;
var m int = 2;
var n int = 2
var q int = 521;

func main() {
	sk := new(base.Privkey)
	GenSKFpart(time.Now().UnixNano(), "test_0428_1.skf")
	sk.FromFile("test_0428_1.skf")
	sk.PrintKey()

	GenDictionary("test_0428_1.skf", "test_0428_1.dict")
	dict := new(base.Dictionary)
	dict.FromFile("test_0428_1.dict")
}

//export GenSKFpart
func GenSKFpart(seed int64, filename string) {
	lib.GenSKFpart(seed, n, m, q, filename)
}

//export GenSKZpart
func GenSKZpart(seed int64, hashstr string, filename string) {
	lib.GenSKZpart(seed, base.GetSM3(hashstr), m, q, filename);
}

//export ComposeSK
func ComposeSK(fpart string, zpart string, filename string) {
	lib.ComposeSK(fpart, zpart, filename)
}

//export GenSK
func GenSK(seed int64, filename string) {
	lib.GenSK(seed, m, n, q, filename)
}

//export GenPK
func GenPK(seed int64, skfile string, filename string) {
	lib.GenPK(seed, skfile, p, filename)
}

//export GenDictionary
func GenDictionary(skfile string, filename string) {
	lib.GenDictionary(skfile, m, n, p, filename)
}

//export GenTransferDictSS
func GenTransferDictSS(sk_out string, sk_in string, filename string) {
	lib.GenTransferDictSS(sk_out, sk_in, m, n, p, filename)
}

//export EncString
func EncString(message string, skfile string) *C.char {
	res := lib.EncString(message, skfile, p)
	base_res := base64.StdEncoding.EncodeToString(res)
	res2 := C.CString(base_res)
	return res2
}

//export DecString
func DecString(cipher string, skfile string) *C.char {
	cipherbyte, err := base64.StdEncoding.DecodeString(cipher)
    if err != nil {
        return nil
    }
	res := lib.DecString(cipherbyte, skfile)
	res2 := C.CString(string(res))
	//defer C.free(unsafe.Pointer(res2))
	return res2
}

//export TranSS
func TranSS(cipher string, tranfile string, dictfile string) *C.char {
	cipherbyte, err := base64.StdEncoding.DecodeString(cipher)
    if err != nil {
        return nil
    }
	res := lib.TranSS(cipherbyte, tranfile, dictfile, p)
	base_res := base64.StdEncoding.EncodeToString(res)
	res2 := C.CString(base_res)
	//defer C.free(unsafe.Pointer(res2))
	return res2
}

//export EqualString
func EqualString(c1 string, c2 string, dictfile string, tranfile string) bool {
	c1byte, err := base64.StdEncoding.DecodeString(c1)
    if err != nil {
        return false
    }
	c2byte, err2 := base64.StdEncoding.DecodeString(c2)
    if err2 != nil {
        return false
    }
	res := lib.EqualString(c1byte, c2byte, dictfile, tranfile, p)
	return res
}

//export SM3
func SM3(str string) *C.char {
	res := lib.SM3(str)
	res2 := C.CString(res)
	return res2
}

//export freePoint
func freePoint(cs *C.void) {
	C.free(unsafe.Pointer(cs))
}