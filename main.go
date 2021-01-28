package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	uuid "github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
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
	// Create session map: session key sessionID(consists of an uuid(string)) value email string
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
	http.HandleFunc("/logout", c.logout)
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

		// Get the JWTToken back from cookie value
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

// logout logs a user out POST: /logout
func (c *Controller) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	fmt.Println("Logout route activated")
	// Check if there is an existing cookie
	if cookie.Value != "" {
		sessionID := cookie.Value
		delete(sessions, sessionID)
		// check if session is deleted
		if _, ok := sessions[sessionID]; ok {
			fmt.Println("Did not deleted session ", sessionID)
		}
		cookie.MaxAge = -1
		cookie.Value = ""
		http.SetCookie(w, cookie)
		fmt.Printf("Cookie value in logout: %v\n", cookie.Value)
	}
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
