package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/bcrypt"
)

const password = "ilovedogs"

func main() {
	msg := "This is totally fun get hands-on and learning it from the groud up. Thank you for sharing this info with me and helping me learn."

	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalln("Couldn't bcrypt password", err)
	}
	bs = bs[:16]

	wtr := &bytes.Buffer{}
	encWriter, err := encryptWriter(wtr, bs)
	if err != nil {
		log.Fatalln(err)
	}

	_, err = io.WriteString(encWriter, msg)
	if err != nil {
		log.Fatalln(err)
	}

	encrypted := wtr.String()

	fmt.Println("Before base64", encrypted)

	// result, err := enDecode(bs, msg)
	// if err != nil {
	// 	log.Fatalln("Couldn't aes decode message", err)
	// }
	// fmt.Println("Before base64", string(result))

	result2, err := enDecode(bs, encrypted)

	if err != nil {
		log.Fatalln("Couldn't aes decode message", err)
	}

	fmt.Println(string(result2))

	// encodedMSG := encode(msg)
	// decodedMSG, err := decode(encodedMSG)

	// if err != nil {
	// 	fmt.Printf("Problem decoding: %v\n", err)
	// }
	// fmt.Println(decodedMSG)
}

// encode base64 encodes a string and returns a encoded string
func encode(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
}

// enDecode aes encodes a input byte slice and returns a encoded byte slice and an error
func enDecode(key []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Couldn't newCipher %w", err)
	}

	// initialization vector
	iv := make([]byte, aes.BlockSize)

	// Randomize
	// _, err = io.ReadFull(rand.Reader, iv)
	// if err != nil {
	// 	log.Fatalln(err)
	// }

	// cipher stream required as input to stream writer
	s := cipher.NewCTR(b, iv)
	// Create a buffer to store the input as it will be used in a stream
	buff := &bytes.Buffer{}
	// Create a cipher stream writer
	sw := cipher.StreamWriter{
		S: s,
		W: buff,
	}
	// write the cipher of the message
	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("couldn't write stream %w", err)
	}

	return buff.Bytes(), nil
}

// decode decodes a base64 encoded msg into a string
// and returns a message and an error
func rdecode(encodedMSG string) (string, error) {
	decodedMSG, err := base64.URLEncoding.DecodeString(encodedMSG)
	if err != nil {
		return "", fmt.Errorf("Problem decoding: %w", err)
	}
	return string(decodedMSG), nil
}

// decode decodes a base64 encoded msg into a string
// and returns a message and an error
func decode(encodedMSG string) (string, error) {
	decodedMSG, err := base64.URLEncoding.DecodeString(encodedMSG)
	if err != nil {
		return "", fmt.Errorf("Problem decoding: %w", err)
	}
	return string(decodedMSG), nil
}

// encryptWriter Creates an encrpyted writer
func encryptWriter(wtr io.Writer, key []byte) (io.Writer, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Couldn't newCipher %w", err)
	}

	// initialization vector
	iv := make([]byte, aes.BlockSize)

	// cipher stream required as input to stream writer
	s := cipher.NewCTR(b, iv)
	// Create a cipher stream writer
	return cipher.StreamWriter{
		S: s,
		W: wtr,
	}, nil
}
