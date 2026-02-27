package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
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

	princ, err := client.AuthPassword(context.Background(), openauth.PasswordInput{
		UserID:   uuid.NewString(),
		Password: "test1234",
	})
	if err != nil {
		log.Printf("AuthPassword error: %v", err)
		return
	}
	log.Printf("AuthPassword result: %+v", princ)
}
