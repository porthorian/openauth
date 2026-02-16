package main

import (
	"context"
	"log"

	"github.com/porthorian/openauth"
)

func main() {
	ctx := context.Background()
	client, err := openauth.New(&openauth.AuthService{}, openauth.Config{})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Client: %+v", client)

	prince, err := client.AuthPassword(ctx, openauth.PasswordInput{})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Principal: %+v", prince)
}
