package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/porthorian/openauth"
)

func main() {
	dsn := os.Getenv("OPENAUTH_POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("OPENAUTH_POSTGRES_DSN is required")
	}

	cacheBackend := openauth.CacheBackend(envOrDefault("OPENAUTH_CACHE_BACKEND", string(openauth.CacheBackendMemory)))

	client, err := openauth.NewDefault(openauth.Config{
		Logger: logr.Discard(),
		Runtime: openauth.RuntimeConfig{
			Storage: openauth.StorageConfig{
				Backend: openauth.StorageBackendPostgres,
				Postgres: openauth.PostgresConfig{
					DriverName:      envOrDefault("OPENAUTH_POSTGRES_DRIVER", "pgx"),
					DSN:             dsn,
					MaxOpenConns:    10,
					MaxIdleConns:    5,
					ConnMaxLifetime: 30 * time.Minute,
					ConnMaxIdleTime: 5 * time.Minute,
					PingTimeout:     5 * time.Second,
				},
			},
			Cache: openauth.CacheConfig{
				Backend: cacheBackend,
				Redis: openauth.RedisCacheConfig{
					Address:     os.Getenv("OPENAUTH_REDIS_ADDR"),
					Username:    os.Getenv("OPENAUTH_REDIS_USER"),
					Password:    os.Getenv("OPENAUTH_REDIS_PASSWORD"),
					Database:    envIntOrDefault("OPENAUTH_REDIS_DB", 0),
					Namespace:   envOrDefault("OPENAUTH_REDIS_NAMESPACE", "openauth"),
					DialTimeout: 3 * time.Second,
				},
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
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envIntOrDefault(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
