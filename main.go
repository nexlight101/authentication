package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"io"
	"net/http"
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

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Document</title>
	</head>
	<body>
		<p>Cookie value: ` + c.Value + `</p>
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
	return string(h.Sum(nil))
}
