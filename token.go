package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// MyCustomClaims struct to customize standard claims
type MyCustomClaims struct {
	SID string `json:"sid"`
	jwt.StandardClaims
}

// createJWT Creates the JWT signed token and takes in a SID as string and returns an JWT token(string) and error
func createJWT(SID string) (string, error) {
	// Create custom claims value
	claims := MyCustomClaims{
		SID,
		jwt.StandardClaims{
			ExpiresAt: expire,
		},
	}
	// Create a jwt tokenizer
	tokenizer := jwt.NewWithClaims(jwt.SigningMethodHS512, &claims)
	// create a token and sign it with your key
	ss, err := tokenizer.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error in SignedString while signing: %w", err)
	}
	return ss, nil
}

// Valid overrides the valid function check that the token is valid
func (u MyCustomClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		fmt.Println("The token expired")
		return fmt.Errorf("Token has expired")
	}
	if u.SID == "" {
		fmt.Println("Invalid session ID")
		return fmt.Errorf("Invalid session ID")
	}
	return nil
}

// parseJWT Parses a jwt token takes in a signed token as a string and returns a *MyCustomClaims and error
func parseJWT(signedToken string) (string, error) {
	// check signature - this is weird!! you don't need an instance just a type of MyCustomClaims
	// this firstly uses the token(in the callback function) and then verifies it in the same step.
	t, err := jwt.ParseWithClaims(signedToken, &MyCustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		// according to jwt advisory you need to check if your signing method remained the same in callback.
		// the signing method are carried inside the unverified token. The Method field of the token type carries Alg() from
		// the SigningMethod used.
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("error in parseJWT while parsing token ")
		}
		return key, nil
	})
	// Is the token valid?  It is populated when you Parse/Verify a token - only checks if the claims has not expired
	if err == nil && t.Valid { //there was no error and the token is valid
		// need to assert VerifiedToken of *MyCustomeClaims type!! You know what you passed in when you created it.
		// Claims type interface with valid method only
		claims := t.Claims.(*MyCustomClaims)
		return claims.SID, nil
	}
	// important to check the error first nill pointer value see running video
	return "", errors.New("error while verifying token")

}

// getHMAC Creates the HMAC signature, takes in a sessionID as string and returns an HMAC token
func getHMAC(sessionID string) string {
	h := hmac.New(sha512.New, key)
	h.Write([]byte(sessionID))
	fmt.Printf("%x\n", h.Sum(nil))
	// return signature and sessionID with separator
	return fmt.Sprintf("%x", h.Sum(nil)) + "|" + sessionID
}

// parseHMAC parses a HMAC (ss) as string and returns a sID as a string
func parseHMAC(ss string) (string, error) {
	xS := strings.SplitN(ss, "|", 2)
	if len(xS) < 2 {
		err := errors.New("Error in parseHMAC while splitting")
		return "", err
	}
	signature := xS[0]
	sID := xS[1]
	// check if this is a sessionID
	if _, ok := sessions[sID]; !ok {
		err := errors.New("Error in parseHMAC while verifying session")
		return "", err
	}
	// Create HMAC from sessionID to verify against
	h := hmac.New(sha512.New, key) // create hasher
	h.Write([]byte(sID))           // sign the sessionid
	newSig := h.Sum(nil)           // store the hash as byte slice
	// decode signature from hex - it was stores as a hex string - to byte slice
	oldSig, err := hex.DecodeString(signature)
	if err != nil {
		err = errors.New("Error in parseHMAC while decoding")
		return "", err
	}
	// Compare the new signature to the old one
	if !hmac.Equal(oldSig, newSig) {
		fmt.Printf("passed in signature: %v\n newly generated signature: %v\n", oldSig, newSig)
		fmt.Println()
		err := errors.New("Error in parseHMAC while comparing")
		return "", err
	}
	return sID, nil
}
