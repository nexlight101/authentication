package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/github"
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

// JSON LAYOUT{"data":{"viewer":{"id":"..."}}}
// githubResponse for github response {"query": "query {viewer {id}}"}
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

// {
//     "user_id" : "amzn1.account.K2LI23KL2LK2"
//     "email" : "johndoe@gmail.com",
//     "name" : "John Doe",
//     "postal_code": "98101",
// }
// amazonResponse for amazon response
type amazonResponse struct {
	UserID     string `json:"user_id"`
	Emial      string `json:"email"`
	Name       string `json:"name"`
	PostalCode string `json:"postal_code"`
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
	// Create github oauth2 config
	githubOauthConfig = &oauth2.Config{
		ClientID:     "9bed2901acec3e73faa2",
		ClientSecret: "132699ece246b9a77f3e2f5df9242160d9115936",
		Endpoint:     github.Endpoint,
	}
	// Create amazon oauth2 config
	amazonOauthConfig = &oauth2.Config{
		ClientID:     "amzn1.application-oa2-client.37d1e287b52748609d4900773e238c93",
		ClientSecret: "686dcb70ceb1f941cf6bac17b11c1104de605e8ffc7bf6b8117fc6781339c4f0",
		Endpoint:     amazon.Endpoint,
		RedirectURL:  "http://localhost:8080/oauth2/amazon/receive", // On live site use only https
		Scopes:       []string{"profile"},
	}

	// githubID
	githubID string
	// amazonID
	amazonID string
	// oauth2Connections Key is Oauth2 provider id and value is user ID
	oauth2Connections = map[string]string{}
	// stateConnections to cater for names and timeouts for Oauth connections
	// key state:string value expiration time: time.Time
	stateConnections = map[string]time.Time{}
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

	// Handle Oauth routes
	http.HandleFunc("/oauth2/github/login", c.startGithubOauth)
	http.HandleFunc("/oauth2/github/receive", c.completeGithubOauth)
	http.HandleFunc("/oauth2/amazon/login", c.startAmazonOauth)
	http.HandleFunc("/oauth2/amazon/receive", c.completeAmazonOauth)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ***************************** Oauth2 routes ***************************
// startGithubOauth handle the Github route. To origanize the github login page
func (c *Controller) startGithubOauth(w http.ResponseWriter, r *http.Request) {
	//generate uuid
	state, err := uuid.NewV4()
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create state: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	stateConnections[state.String()] = time.Now().Add(60 * time.Minute)
	redirectURL := githubOauthConfig.AuthCodeURL(state.String()) // The state("0000") will be a unique identifier per login attempt
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// completeGithubOauth handle the Github route. To origanize the github login page:/oauth2/github/receive
func (c *Controller) completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	fmt.Println("/oauth2/github/receive activated!")
	expireTime, ok := stateConnections[state]
	if !ok {
		message = url.QueryEscape("Could not find state")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Check if state has not expired
	if expireTime.Before(time.Now()) {
		message = url.QueryEscape("State expired")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Retrieve a token
	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	// Get token source
	ts := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)
	// Create a reader from a string using strings package

	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	// POST to the github graphql route
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	// decode github response
	var gr githubResponse
	err = json.NewDecoder(resp.Body).Decode(&gr)
	if err != nil {
		http.Error(w, "Github invalid response", http.StatusInternalServerError)
		return
	}
	githubID = gr.Data.Viewer.ID
	fmt.Printf("GithubID: %v \n", githubID)
	_, ok = oauth2Connections[githubID]
	if !ok { // New user register him
		// new user - create account
		// Jipo the email address to bypass registration temperary
		u.email = "piettie@uk.gov"
		oauth2Connections[githubID] = u.email
	}
	login(w, r)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startAmazonOauth handle the Amazon route. To origanize the amazon login page
func (c *Controller) startAmazonOauth(w http.ResponseWriter, r *http.Request) {
	//generate uuid to make state name unique
	state, err := uuid.NewV4()
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create state: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Assign an expiry time(1 hour) to the state
	stateConnections[state.String()] = time.Now().Add(60 * time.Minute)
	redirectURL := amazonOauthConfig.AuthCodeURL(state.String()) // The state("0000") will be a unique identifier per login attempt
	// Now redirect to amazon to start the Oauth procces
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// completeAmazonOauth handle the Amazon route. To origanize the Amazon login page:/oauth2/amazon/receive
func (c *Controller) completeAmazonOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	fmt.Println("/oauth2/amazon/receive activated!")
	expireTime, ok := stateConnections[state]
	if !ok {
		message = url.QueryEscape("Could not find state")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Check if state has not expired
	if expireTime.Before(time.Now()) {
		message = url.QueryEscape("State expired")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Retrieve a token
	token, err := amazonOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	// Get token source
	ts := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)
	// Create a reader from a string using strings package

	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	// POST to the github graphql route
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	// decode amazon response
	var gr amazonResponse
	err = json.NewDecoder(resp.Body).Decode(&gr)
	if err != nil {
		http.Error(w, "Amazon invalid response", http.StatusInternalServerError)
		return
	}
	amazonID = gr.UserID
	fmt.Printf("amazonID: %v \n", amazonID)
	_, ok = oauth2Connections[amazonID]
	if !ok { // New user register him
		// new user - create account
		// Jipo the email address to bypass registration temperary
		u.email = "piettie@uk.gov"
		oauth2Connections[amazonID] = u.email
	}
	login(w, r)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ***************************** End Oauth2 routes ***************************

// index displays root page: /
func (c *Controller) index(w http.ResponseWriter, r *http.Request) {
	var isEqual bool = false
	// is there a cookie?
	cookie, err := r.Cookie("myCookie")
	if err != nil {
		cookie = &http.Cookie{}
	}
	if cookie.Value != "" {
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

	// Log the user in
	login(w, r)
	// // Create session
	// sessions[sID.String()] = u.email
	// // Create HMAC hash from sessionID
	// JWTToken, err := createJWT(sID.String())
	// if err != nil {
	// 	message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create session: %w", err)))
	// 	http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
	// 	return
	// }
	// // HMACID := getHMAC(sID.String())
	// // Create cookie
	// cookie = &http.Cookie{
	// 	Name:  "myCookie",
	// 	Value: JWTToken,
	// }
	// http.SetCookie(w, cookie)

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

// ****************************** login ******************************
// login logs a user in
func login(w http.ResponseWriter, r *http.Request) {
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
		Path:  "/",
	}
	http.SetCookie(w, cookie)
}

// ****************************** End login ******************************
