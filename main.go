package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type person struct {
	First string
}

func main() {
	p1 := person{
		First: "Jenny",
	}

	p2 := person{
		First: "James",
	}

	xp := []person{p1, p2}

	bs, err := json.Marshal(xp)
	if err != nil {
		log.Panicf("Couldn't marshal data %v", err)
	}
	fmt.Printf("persons in json format: %s\n", string(bs))

	xp1 := []person{}
	err = json.Unmarshal(bs, &xp1)
	if err != nil {
		log.Panicf("Couldn't unmarshal data %v", err)
	}
	fmt.Printf("persons in go format: %v\n", xp1)
}
