package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var key = []byte{}

func main() {
	pass := "123456789"

	//Generate 64 bit key for use with hmac signing (Never do this!!!, use random generator)
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}

	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	err = comparePassword(pass, hashedPass)
	if err != nil {
		log.Fatalf("Not logged in %v", err)
	}
	log.Println("Logged in!")
}

// hashPassword hashes a password takes in password as string and returns hash as slice of bytes
func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

// comparePassword compares a password to a stored hashed password takes in a password as a string
// and a hashed password as slice of bytes and returns error
func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}
	return nil
}

// signMessage signs a message with HMAC takes in slice of bytes
// retuns signed message slice of bytes and error
func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
	}
	// You need to use h.Sum to get your encoded message into a byte slice and you need to provide nil
	// to not modify your encoded message
	signature := h.Sum(nil)
	return signature, nil
}

// checkSig compares signature from received message to original signature
func checkSig(msg, sig []byte) (bool, error) {
	// Generate new signature from message
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Could not sign message signature in checkSig: %w", err)
	}

	// Compare if original signature same as new signature
	same := hmac.Equal(newSig, sig)
	return same, nil
}
