package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

// UserClaims is a custom claims struct containing StandardClaims type
type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

// key struct for holding keys
// You need to Delete all week old keys periodically
// Typically use a db to store these and a cron job to create one every hour
// and delete weekly
type key struct {
	key     []byte
	created time.Time
}

var (
	// For storing keys to rotate key:string value:[]byte
	keys = map[string]key{}
	// Stores the current key id
	currentKid = ""
)

// generateNewKey genarates a new key and stores it in the key map
func genarateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating key %w", err)
	}
	uid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating kid: %w", err)
	}

	keys[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}
	currentKid = uid.String()
	return nil
}

// ***************** JWT code ***************

// Valid tests if UserClaims are valid
func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}
	return nil
}

// createToken creates a jwt token
func createToken(c *UserClaims) (string, error) {
	// sign my token with a signing method(jwt.SigningMethodHS512) and my UserClaims type
	// This creates a signer(t)
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	// Get the signed token into a string type by using the signer's string method and the provided key
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Could not sign token in createToken: %w", err)
	}
	return signedToken, nil
}

// parseToken evaluate a received token for validity
func parseToken(signedToken string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}
		kid, ok := t.Header["kid"].(string) // assert the interface value is a string
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}
		return k.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while parsing token %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}
	return t.Claims.(*UserClaims), nil
}

// ***************** end JWT code ***************
func main() {
	pass := "123456789"

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

// ***************** Password code ***************

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

// ***************** end Password code ***************

// ***************** HMAC code ***************
// signMessage signs a message with HMAC takes in slice of bytes
// retuns signed message slice of bytes and error
func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, keys[currentKid].key) // Craete a signer by specifing the hash algorythm(sha512.New function) and the key.
	_, err := h.Write(msg)                          // Use the write method(sign) of the signer(h) to sign msg.
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

// ***************** end JWT code ***************
