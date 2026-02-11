package main

import (
	"log"

	"github.com/porthorian/openauth"
)

func main() {
	client, err := openauth.New(&openauth.AuthService{}, openauth.Config{})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Client: %+v", client)
}
