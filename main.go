package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	uuid "github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

// MyCustomClaims struct to customize standard claims
type MyCustomClaims struct {
	SID string `json:"sid"`
	jwt.StandardClaims
}

type user struct {
	email    string
	password string
	first    string
	age      int
}

var (
	// TPL pointer to templates
	tpl *template.Template

	key = []byte("I love thursdays when it rains 8723 inches")

	expire  = time.Now().Add(5 * time.Minute).Unix()
	message = ""
	u       = user{}
	cookie  = &http.Cookie{}
	// sessionID = "" // sessionID used for HMAC signature
	// Create session map: session key uuid(string) value email string
	sessions = map[string]string{}
)

// NewController provides new controller for template processing
func NewController(t *template.Template) *Controller {
	return &Controller{t}
}

func main() {
	//Parse all templates
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
	// Get a template controller value.
	c := NewController(tpl)
	// Create user

	http.HandleFunc("/", c.index)
	http.HandleFunc("/submit", c.procces)
	http.HandleFunc("/register", c.register)
	http.HandleFunc("/login", c.login)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// index displays root page: /
func (c *Controller) index(w http.ResponseWriter, r *http.Request) {
	var isEqual bool = false
	// is there a cookie?
	cookie, err := r.Cookie("myCookie")
	if err != nil {
		cookie = &http.Cookie{}
	}
	if cookie.Value != "" {
		// 	// Check Valid JWT token
		// 	jwtToken := cookie.Value
		// 	fmt.Println(jwtToken)
		// 	_, err = parseJWT(jwtToken)
		// 	if err != nil {
		// 		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not verify JWT token: %w", err)))
		// 		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		// 		return
		// 	}

		// Get the HMACToken back from cookie value
		signedToken := cookie.Value
		// Parse the sessionID from the signed token
		sID, err := parseJWT(signedToken)
		if err != nil {
			message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not retrieve sessionID: %w", err)))
			http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
			return
		}

		u.email = sessions[sID]

		isEqual = true
	}
	// Create logged in message
	message = "Not logged in"
	// Check if someone registered
	if u.email != "" {
		message = "Successfully registered and not logged in"
	}
	if isEqual && cookie.Value != "" {
		message = "Logged in as " + u.email
	}

	// populate the template struct with values
	templateData := struct {
		Message string
		Cookie  string
	}{
		Message: message,
		Cookie:  cookie.Value,
	}
	c.tpl.ExecuteTemplate(w, "index.gohtml", templateData)

}

// register registeres a user -POST:/register
func (c *Controller) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	fmt.Println(email)
	if email == "" {
		message = url.QueryEscape("You need to supply an email")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	u.email = email
	fmt.Println("email provided: ", u.email)

	u.first = r.FormValue("first")
	if u.first == "" {
		message = url.QueryEscape("You need to supply a first name")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	fmt.Println(password)
	if password == "" {
		message = url.QueryEscape("Invalid password")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	passwordH, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not hash: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	u.password = string(passwordH)

	fmt.Println("password hashed provided: ", u.password)

	age := r.FormValue("age")
	fmt.Println(age)
	if age != "" {
		ageCov, err := strconv.Atoi(age)
		if err != nil {
			message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Please provide a legitimate age: %w", err)))
			http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
			return
		}
		u.age = ageCov
		fmt.Println("age provided: ", u.age)

	}

	// //generate uuid
	// sID, err := uuid.NewV4()
	// if err != nil {
	// 	message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create session: %w", err)))
	// 	http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
	// 	return
	// }

	// // Create session
	// sessions[sID.String()] = u.email

	// Redirect to root
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// login logs a user in POST: /login
func (c *Controller) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	fmt.Println("Login route activated!")
	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	if password == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// See if someone is registered
	if email == "" {
		message = url.QueryEscape("You need to register to login")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	// test if the user email is the correct email
	if email != u.email {
		message = url.QueryEscape("You need to register to login")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	fmt.Println("Registration Confirmed!")

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(u.password), []byte(password)); err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Incorrect email or password: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	//generate uuid
	sID, err := uuid.NewV4()
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create session: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	// Create session
	sessions[sID.String()] = u.email
	// Create HMAC hash from sessionID
	JWTToken, err := createJWT(sID.String())
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create session: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// HMACID := getHMAC(sID.String())
	// Create cookie
	cookie = &http.Cookie{
		Name:  "myCookie",
		Value: JWTToken,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/", http.StatusSeeOther)

}

// procces POST root for form: /submit
func (c *Controller) procces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	email := r.FormValue("email")
	fmt.Println(email)
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// HMACToken := getHMAC(email)

	// Generate the JWT token
	jwtToken, err := createJWT("sID")
	fmt.Printf("JWT token created as: %v\n", jwtToken)
	fmt.Println()
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not Create JWT token: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}

	// Create cookie
	cookie = &http.Cookie{
		Name:  "myCookie",
		Value: jwtToken,
	}

	// Set the cookie
	http.SetCookie(w, cookie)
	// Redirect to root
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
