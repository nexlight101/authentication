package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

type person struct {
	First string
}

// TPL pointer to templates
var tpl *template.Template

// xp slice of person
var xp []person

// Controller struct for template controller
type Controller struct {
	tpl *template.Template
}

// NewController provides new controller for template processing
func NewController(t *template.Template) *Controller {
	return &Controller{t}
}

func main() {

	//Parse all templates
	tpl = template.Must(template.ParseGlob("templates/*.gohtml"))
	// Get a template controller value.
	c := NewController(tpl)

	p1 := person{
		First: "Jenny",
	}

	p2 := person{
		First: "Tim",
	}

	xp = []person{p1, p2}
	// handle the root page :/
	http.HandleFunc("/", c.index)
	// http.HandleFunc("/decode", c.decode)

	// xp1 := []person{}
	// err = json.Unmarshal(bs, &xp1)
	// if err != nil {
	// 	log.Panicf("Couldn't unmarshal data %v", err)
	// }
	// fmt.Printf("persons in go format: %v\n", xp1)

	log.Fatal(http.ListenAndServe(":8080", nil))

}

// jM marshal takes slice of person, returns json byte slice
func jM(xp []person) []byte {
	bs, err := json.Marshal(xp)
	if err != nil {
		log.Panicf("Couldn't marshal data %v", err)
	}
	fmt.Printf("persons in json format: %s\n", string(bs))
	return bs
}

// jD decodes json request data to go person struct slice
func jD(req *http.Request) []person {
	xp2 := []person{}
	// Decode requet body
	err := json.NewDecoder(req.Body).Decode(&xp2)
	if err != nil {
		log.Panicf("Couldn't marshal data %v", err)
	}
	fmt.Printf("persons : %v\n", xp2)
	return xp2
}

// index is the landing page: /
func (c Controller) index(w http.ResponseWriter, req *http.Request) {
	// populate the template struct with empty values

	templateData := struct {
		JSONS string
	}{
		JSONS: string(jM(xp)),
	}
	c.tpl.ExecuteTemplate(w, "index.gohtml", templateData)
}

// // Decode root: /decode
// func (c Controller) decode(w http.ResponseWriter, req *http.Request) {
// 	// populate the template struct with empty values

// 	fmt.Println("Persons ", jD(req))
// }
