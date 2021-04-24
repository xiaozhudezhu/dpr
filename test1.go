package main

import (
	"os"
)

func main() {
	
	PathExists("file")
	os.Mkdir("file", os.ModePerm);
	os.Create("file/1.txt");
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}