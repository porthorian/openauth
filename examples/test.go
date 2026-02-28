package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/porthorian/openauth"
)

func main() {
	dsn := os.Getenv("OPENAUTH_POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("OPENAUTH_POSTGRES_DSN is required")
	}

	client, err := openauth.NewDefault(openauth.Config{
		Logger: logr.Discard(),
		Runtime: openauth.RuntimeConfig{
			Storage: openauth.StorageConfig{
				Backend: openauth.StorageBackendPostgres,
				Postgres: openauth.PostgresConfig{
					DriverName:      "pgx",
					DSN:             dsn,
					MaxOpenConns:    10,
					MaxIdleConns:    5,
					ConnMaxLifetime: 30 * time.Minute,
					ConnMaxIdleTime: 5 * time.Minute,
					PingTimeout:     5 * time.Second,
				},
			},
			Cache: openauth.CacheConfig{
				Backend: openauth.CacheBackendNone,
			},
			KeyStore: openauth.KeyStoreConfig{
				Backend: openauth.KeyStoreBackendNone,
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("client close error: %v", err)
		}
	}()

	log.Printf("Client initialized with configured runtime: %+v", client)
	userID := "b8575451-3261-4ed3-a5ea-ae0d19754ebd"
	pwd := "test1234"
	log.Printf("Testing authorization for user ID: %s", userID)
	ctx := context.Background()
	err = client.CreateAuth(ctx, openauth.CreateAuthInput{
		UserID: userID,
		Value:  pwd,
	})
	if err != nil {
		log.Printf("CreateAuth error: %v", err)
		return
	}

	princ, err := client.Authorize(ctx, openauth.AuthInput{
		UserID: userID,
		Type:   openauth.InputTypePassword,
		Value:  pwd,
	})
	if err != nil {
		log.Printf("Authorize error: %v", err)
		return
	}
	log.Printf("Authorize result: %+v", princ)
}
