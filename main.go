package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	key = []byte("I love thursdays when it rains 8723 inches")
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/submit", procces)
	http.ListenAndServe(":8080", nil)

}

// index displays root page: /
func index(w http.ResponseWriter, r *http.Request) {

	c, err := r.Cookie("myCookie")
	if err != nil {
		c = &http.Cookie{}
	}

	isEqual := true
	// Separate cookie value into HMAC code and email
	xs := strings.SplitN(c.Value, "|", 2)
	// Check that we actually have the two parts
	if len(xs) == 2 {
		cCode := xs[0]
		cEmail := xs[1]
		// Generate a new HMAC token from the received email(cEmail)
		code := getHMAC(cEmail)
		// Compare original HMAC code to newly generated HMAC code
		isEqual = hmac.Equal([]byte(cCode), []byte(code))

	}

	// Create logged in message
	message := "Not logged in"
	if isEqual && c.Value != "" {
		message = "Logged in"
	}
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Document</title>
	</head>
	<body>
		<p>Cookie value: ` + c.Value + `</p>
		<p>Message:` + message + `</p>
		<form action="/submit" method="POST">
			<input type="email" name="email">
			<input type="submit">
		</form>
	</body>
	</html>`
	io.WriteString(w, html)
}

// procces POST root for form: /submit
func procces(w http.ResponseWriter, r *http.Request) {
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

	HMACToken := getHMAC(email)

	// Create cookie
	c := &http.Cookie{
		Name:  "myCookie",
		Value: HMACToken + "|" + email,
	}

	// Set the cookie
	http.SetCookie(w, c)
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
