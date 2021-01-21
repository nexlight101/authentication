package main

import (
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	f, err := os.Open("sample-file.txt")
	if err != nil {
		log.Fatalln("Could not open file ", err)
	}

	defer f.Close()
	// Create a hash
	h := sha512.New()
	// copy the file contents to the hash - hashing the file
	_, err = io.Copy(h, f)
	if err != nil {
		log.Fatalln("Could not copy file ", err)
	}

	// Print the contents of the hash
	fmt.Printf("%x\n", h.Sum(nil))
}
