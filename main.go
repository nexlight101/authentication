package main

import (
	"encoding/base64"
	"fmt"
)

func main() {
	msg := "This is totally fun get hands-on and learning it from the groud up. Thank you for sharing this info with me and helping me learn."
	encodedMSG := encode(msg)
	decodedMSG, err := decode(encodedMSG)

	if err != nil {
		fmt.Printf("Problem decoding: %v\n", err)
	}
	fmt.Println(decodedMSG)
}

// encode base64 encodes a string and returns a encoded string
func encode(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
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
