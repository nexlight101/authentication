package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/submit", procces)
	http.ListenAndServe(":8080", nil)

}

// index displays root page: /
func index(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Document</title>
	</head>
	<body>
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

	// Create cookie
	c := &http.Cookie{
		Name:  "myCookie",
		Value: email,
	}

	// Set the cookie
	http.SetCookie(w, c)
	// Redirect to root
	http.Redirect(w, r, "/", http.StatusSeeOther)

}
