package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
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

var (
	// TPL pointer to templates
	tpl *template.Template

	key = []byte("I love thursdays when it rains 8723 inches")

	expire  = time.Now().Add(5 * time.Minute).Unix()
	message = ""
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
	http.HandleFunc("/", c.index)
	http.HandleFunc("/submit", c.procces)
	log.Fatal(http.ListenAndServe(":8080", nil))

}

// index displays root page: /
func (c *Controller) index(w http.ResponseWriter, r *http.Request) {
	var isEqual bool = false
	cookie, err := r.Cookie("myCookie")
	if err != nil {
		cookie = &http.Cookie{}
	}
	if cookie.Value != "" {
		// Check Valid JWT token
		jwtToken := cookie.Value
		fmt.Println(jwtToken)
		_, err = parseJWT(jwtToken)
		if err != nil {
			message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not verify JWT token: %w", err)))
			http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
			return
		}

		isEqual = true
	}
	// // Separate cookie value into HMAC code and email
	// xs := strings.SplitN(cookie.Value, "|", 2)
	// // Check that we actually have the two parts
	// if len(xs) == 2 {
	// 	cCode := xs[0]
	// 	cEmail := xs[1]
	// 	// Generate a new HMAC token from the received email(cEmail)
	// 	// code := getHMAC(cEmail)

	// 	// Compare original HMAC code to newly generated HMAC code
	// 	isEqual = hmac.Equal([]byte(cCode), []byte(code))

	// }

	// Create logged in message
	message = "Not logged in"
	if isEqual && cookie.Value != "" {
		message = "Logged in"
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
	cookie := &http.Cookie{
		Name:  "myCookie",
		Value: jwtToken,
	}

	// Set the cookie
	http.SetCookie(w, cookie)
	// Redirect to root
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getHMAC Creates the HMAC takes in a msg as string and returns an HMAC token
func getHMAC(msg string) string {
	h := hmac.New(sha512.New, key)
	h.Write([]byte(msg))
	fmt.Printf("%x\n", h.Sum(nil))
	return fmt.Sprintf("%x", h.Sum(nil))
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

// Valid overrides the valid function
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
