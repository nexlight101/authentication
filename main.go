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
	email    string // Use email as userID
	password string
	first    string
	age      int
	provider string
	oauthID  string // If oauth then store ID
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
	Email      string `json:"email"`
	Name       string `json:"name"`
	PostalCode string `json:"postal_code"`
}

const (
	amazonURL string = "https://api.amazon.com/user/profile"
	graphql   string = "https://api.github.com/graphql"
)

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
	// decode amazon response
	aR = amazonResponse{}
	// decode github response
	gR = githubResponse{}

	// githubID
	githubID string
	// amazonID
	amazonID string
	// sToken signed version of oauth provider ID
	sToken string
	// oauth2Connections Holds the known oauth2 users, key is Oauth2 provider id and value is user ID
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
	http.HandleFunc("/oauth2/github/login", c.startGithubOauth)      // Log with github
	http.HandleFunc("/oauth2/github/receive", c.completeGithubOauth) // GET the github response back
	http.HandleFunc("/oauth2/amazon/login", c.startAmazonOauth)      // Log with amazon
	http.HandleFunc("/oauth2/amazon/receive", c.completeAmazonOauth) // GET the amazon response back
	http.HandleFunc("/partial-register", c.oauth2PartialRegister)    // GET route to display registration form
	http.HandleFunc("/oauth2/register", c.oauth2Register)            // POST route to read registration form

	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ***************************** Oauth2 routes ***************************
// oauth2PartialRegister GET route: handles the registration of an oauth user:/partial-register
func (c *Controller) oauth2PartialRegister(w http.ResponseWriter, r *http.Request) {
	var (
		name  string
		email string
	)
	switch u.provider {
	case "Amazon":
		name = aR.Name
		email = aR.Email
	case "Github":
		name = ""
		email = ""
	}
	// populate the template struct with values
	templateData := struct {
		ID       string
		Name     string
		Email    string
		Provider string
	}{
		ID:       sToken,
		Name:     name,
		Email:    email,
		Provider: u.provider,
	}
	c.tpl.ExecuteTemplate(w, "oauthRegister.gohtml", templateData)
}

// oauth2Register POST route      : handles the registration of an oauth user:/ouath2/register
func (c *Controller) oauth2Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	fmt.Println("Oauth2 register route has started")
	// Extract all from values and populate the user struct
	u.email = r.FormValue("email")
	fmt.Println(u.email)
	if u.email == "" {
		message = url.QueryEscape("You need to supply an email")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	fmt.Println("email provided: ", u.email)
	u.first = r.FormValue("first")
	if u.first == "" {
		message = url.QueryEscape("You need to supply a first name")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
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
	// Retrieve the hidden ID(oauthID in signed token form JWT(JSon Web Token))
	oauthID := r.FormValue("id")
	// Parse the provider ID from the retrieved token
	id, err := parseJWT(oauthID)
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Cannot parse token: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	u.oauthID = id
	// Store the provider ID with the email(userID) in the oauthconnectiongs map
	oauth2Connections[u.oauthID] = u.email
	login(w, r)
	fmt.Printf("Provider userID: %s \nProvider Email: %v \n", id, u.email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startGithubOauth handles the Github route. To origanize the github login page
func (c *Controller) startGithubOauth(w http.ResponseWriter, r *http.Request) {
	// Check if method is POST
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	//generate uuid
	state, err := uuid.NewV4()
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create state: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Assign an expiry time(1 hour) to the state
	stateConnections[state.String()] = time.Now().Add(60 * time.Minute)
	redirectURL := githubOauthConfig.AuthCodeURL(state.String()) // The state("0000") will be a unique identifier per login attempt
	// Now redirect to amazon to start the Oauth procces
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// completeGithubOauth handle the Github route. To origanize the github login page:/oauth2/github/receive
func (c *Controller) completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	fmt.Println("/oauth2/github/receive activated!")
	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		message = url.QueryEscape("Invalid response from Amazon")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
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
	// Retrieve a token by exchanging our code for a token
	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	// Get token source this includes the shortterm token and refreshed token
	// token sourse will automatically refresh your token to be current
	ts := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)
	// Create a reader from a string using strings package

	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	// POST to the github graphql route
	resp, err := client.Post(graphql, "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("Json response from Github: %v\n", resp.Body)
	err = json.NewDecoder(resp.Body).Decode(&gR)
	if err != nil {
		http.Error(w, "Github invalid response", http.StatusInternalServerError)
		return
	}
	githubID = gR.Data.Viewer.ID
	fmt.Printf("GithubID: %v \n", githubID)
	u.email, ok = oauth2Connections[githubID]
	if !ok { // New user register him
		// new user - create account
		// Sign the Github's userID
		sToken, err = createJWT(githubID)
		if err != nil {
			message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not sign provider ID: %w", err)))
			http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
			return
		}

		// Populate the provider field in user struct
		u.provider = "Github"
		// Register the new user
		http.Redirect(w, r, "/partial-register", http.StatusSeeOther)
		return
	}
	login(w, r)
	fmt.Printf("Github userID: %s \nGithub Email: %v \n", gR.Data.Viewer.ID, u.email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startAmazonOauth handle the Amazon route. To origanize the amazon login page:/oauth2/amazon/login
func (c *Controller) startAmazonOauth(w http.ResponseWriter, r *http.Request) {
	// Check if method is POST
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	//generate uuid to make state name unique
	state, err := uuid.NewV4()
	if err != nil {
		message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not create state: %w", err)))
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	// Assign an expiry time(1 hour) to the state
	stateConnections[state.String()] = time.Now().Add(60 * time.Minute)
	redirectURL := amazonOauthConfig.AuthCodeURL(state.String())
	// Now redirect to amazon to start the Oauth procces
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// completeAmazonOauth handle the Amazon route. To origanize the Amazon login page:/oauth2/amazon/receive
func (c *Controller) completeAmazonOauth(w http.ResponseWriter, r *http.Request) {
	fmt.Println("/oauth2/amazon/receive activated!")
	code := r.FormValue("code")
	state := r.FormValue("state")
	if code == "" || state == "" {
		message = url.QueryEscape("Invalid response from Amazon")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
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
	// Retrieve a token by exchanging our code for a token
	token, err := amazonOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Couldn't login", http.StatusInternalServerError)
		return
	}

	// Get token source this includes the shortterm token and refreshed token
	// token sourse will automatically refresh your token to be current
	ts := amazonOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)
	// Query Amazon to get client information
	resp, err := client.Get(amazonURL)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	// Check for invalid status codes
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		message = url.QueryEscape("Bad status on amazon GET")
		http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
		return
	}
	fmt.Printf("Json response from amazon: %v\n", resp.Body)

	err = json.NewDecoder(resp.Body).Decode(&aR)
	if err != nil {
		http.Error(w, "Amazon invalid response", http.StatusInternalServerError)
		return
	}
	amazonID = aR.UserID
	fmt.Printf("amazonID: %v \n", amazonID)
	// Check if there is a connection for this amazon ID
	u.email, ok = oauth2Connections[amazonID]
	if !ok { // New user register him
		// new user - create account
		// Sign the amazon's userID
		sToken, err = createJWT(amazonID)
		if err != nil {
			message = url.QueryEscape(fmt.Sprintf("%v", fmt.Errorf("Could not sign provider ID: %w", err)))
			http.Redirect(w, r, "/?message="+message, http.StatusSeeOther)
			return
		}

		// Populate the provider field in user struct
		u.provider = "Amazon"

		// Register the new user
		http.Redirect(w, r, "/partial-register", http.StatusSeeOther)
		return

	}
	login(w, r)
	fmt.Printf("Amazon userID: %s \nAmazon Email: %v \n", aR.UserID, u.email)
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

// login logs a user in and creates a session
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
