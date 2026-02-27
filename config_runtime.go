package openauth

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	memorycache "github.com/porthorian/openauth/pkg/cache/memory"
	rediscache "github.com/porthorian/openauth/pkg/cache/redis"
	"github.com/porthorian/openauth/pkg/storage/postgres"
)

type StorageBackend string

const (
	StorageBackendNone     StorageBackend = "none"
	StorageBackendPostgres StorageBackend = "postgres"
	StorageBackendSQLite   StorageBackend = "sqlite"
)

type KeyStoreBackend string

const (
	KeyStoreBackendNone KeyStoreBackend = "none"
)

type CacheBackend string

const (
	CacheBackendNone   CacheBackend = "none"
	CacheBackendMemory CacheBackend = "memory"
	CacheBackendRedis  CacheBackend = "redis"
)

type RuntimeConfig struct {
	Storage  StorageConfig
	Cache    CacheConfig
	KeyStore KeyStoreConfig
}

type StorageConfig struct {
	Backend  StorageBackend
	Postgres PostgresConfig
}

type PostgresConfig struct {
	DriverName      string
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	PingTimeout     time.Duration
	OpenDB          func(driverName string, dsn string) (*sql.DB, error)
}

type CacheConfig struct {
	Backend CacheBackend
	Memory  MemoryCacheConfig
	Redis   RedisCacheConfig
}

type MemoryCacheConfig struct{}

type RedisCacheConfig struct {
	Address     string
	Username    string
	Password    string
	Database    int
	Namespace   string
	DialTimeout time.Duration
}

type KeyStoreConfig struct {
	Backend KeyStoreBackend
	URI     string
}

func (c Config) initialize(ctx context.Context) (func() error, Config, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	config := c
	config.Logger = resolveLogger(config.Logger)

	if err := validateKeyStoreBackend(config.Runtime.KeyStore.Backend); err != nil {
		return nil, Config{}, err
	}

	closeStorage, config, err := initializeStorage(ctx, config)
	if err != nil {
		return nil, Config{}, err
	}

	closeCache, config, err := initializeCache(config)
	if err != nil {
		_ = closeStorage()
		return nil, Config{}, err
	}

	return joinClosers(closeStorage, closeCache), config, nil
}

func initializeStorage(ctx context.Context, config Config) (func() error, Config, error) {
	backend := config.Runtime.Storage.Backend
	if backend == "" {
		backend = StorageBackendNone
	}

	switch backend {
	case StorageBackendNone:
		return noopCloser, config, nil
	case StorageBackendPostgres:
		return initializePostgres(ctx, config)
	case StorageBackendSQLite:
		return nil, Config{}, fmt.Errorf("openauth config: runtime.storage.backend %q is not implemented yet", StorageBackendSQLite)
	default:
		return nil, Config{}, fmt.Errorf("openauth config: unsupported runtime.storage.backend %q", backend)
	}
}

func initializeCache(config Config) (func() error, Config, error) {
	backend := config.Runtime.Cache.Backend
	if backend == "" {
		backend = CacheBackendNone
	}

	switch backend {
	case CacheBackendNone:
		return noopCloser, config, nil
	case CacheBackendMemory:
		return initializeMemoryCache(config)
	case CacheBackendRedis:
		return initializeRedisCache(config)
	default:
		return nil, Config{}, fmt.Errorf("openauth config: unsupported runtime.cache.backend %q", backend)
	}
}

func initializeMemoryCache(config Config) (func() error, Config, error) {
	adapter := memorycache.NewAdapter()

	if config.CacheStore.Token == nil {
		config.CacheStore.Token = adapter
	}
	if config.CacheStore.Principal == nil {
		config.CacheStore.Principal = adapter
	}
	if config.CacheStore.Permission == nil {
		config.CacheStore.Permission = adapter
	}

	config.Logger.V(1).Info("initialized memory cache backend")
	return noopCloser, config, nil
}

func initializeRedisCache(config Config) (func() error, Config, error) {
	redisConfig := config.Runtime.Cache.Redis
	if redisConfig.Address == "" {
		return nil, Config{}, fmt.Errorf("openauth config: runtime.cache.redis.address is required")
	}
	if redisConfig.DialTimeout <= 0 {
		redisConfig.DialTimeout = 5 * time.Second
	}

	adapter := rediscache.NewAdapter(rediscache.Config{
		Address:     redisConfig.Address,
		Username:    redisConfig.Username,
		Password:    redisConfig.Password,
		Database:    redisConfig.Database,
		Namespace:   redisConfig.Namespace,
		DialTimeout: redisConfig.DialTimeout,
	})

	if config.CacheStore.Token == nil {
		config.CacheStore.Token = adapter
	}
	if config.CacheStore.Principal == nil {
		config.CacheStore.Principal = adapter
	}
	if config.CacheStore.Permission == nil {
		config.CacheStore.Permission = adapter
	}

	config.Runtime.Cache.Redis = redisConfig
	config.Logger.V(1).Info("initialized redis cache backend", "address", redisConfig.Address, "database", redisConfig.Database, "namespace", redisConfig.Namespace)
	return noopCloser, config, nil
}

func initializePostgres(ctx context.Context, config Config) (func() error, Config, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	pgConfig := config.Runtime.Storage.Postgres
	if pgConfig.DSN == "" {
		return nil, Config{}, fmt.Errorf("openauth config: runtime.storage.postgres.dsn is required")
	}

	if pgConfig.DriverName == "" {
		pgConfig.DriverName = "pgx"
	}
	if pgConfig.PingTimeout <= 0 {
		pgConfig.PingTimeout = 5 * time.Second
	}
	if pgConfig.OpenDB == nil {
		pgConfig.OpenDB = sql.Open
	}

	db, err := pgConfig.OpenDB(pgConfig.DriverName, pgConfig.DSN)
	if err != nil {
		return nil, Config{}, fmt.Errorf("openauth config: failed to open postgres database: %w", err)
	}

	if pgConfig.MaxOpenConns > 0 {
		db.SetMaxOpenConns(pgConfig.MaxOpenConns)
	}
	if pgConfig.MaxIdleConns > 0 {
		db.SetMaxIdleConns(pgConfig.MaxIdleConns)
	}
	if pgConfig.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(pgConfig.ConnMaxLifetime)
	}
	if pgConfig.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(pgConfig.ConnMaxIdleTime)
	}

	pingCtx, cancel := context.WithTimeout(ctx, pgConfig.PingTimeout)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, Config{}, fmt.Errorf("openauth config: failed to ping postgres database: %w", err)
	}

	adapter, err := postgres.NewAdapter(db)
	if err != nil {
		_ = db.Close()
		return nil, Config{}, fmt.Errorf("openauth config: failed to initialize postgres adapter: %w", err)
	}

	if config.AuthStore.Auth == nil {
		config.AuthStore.Auth = adapter
	}
	if config.AuthStore.SubjectAuth == nil {
		config.AuthStore.SubjectAuth = adapter
	}
	if config.AuthStore.AuthLog == nil {
		config.AuthStore.AuthLog = adapter
	}
	if config.AuthdStore.Role == nil {
		config.AuthdStore.Role = adapter
	}
	if config.AuthdStore.Permission == nil {
		config.AuthdStore.Permission = adapter
	}

	closeResource := func() error {
		return db.Close()
	}

	config.Runtime.Storage.Postgres = pgConfig
	config.Logger.V(1).Info("initialized postgres storage backend", "driver", pgConfig.DriverName, "max_open_conns", pgConfig.MaxOpenConns, "max_idle_conns", pgConfig.MaxIdleConns)
	return closeResource, config, nil
}

func validateKeyStoreBackend(backend KeyStoreBackend) error {
	if backend == "" || backend == KeyStoreBackendNone {
		return nil
	}
	return fmt.Errorf("openauth config: unsupported runtime.keystore.backend %q", backend)
}

func joinClosers(closers ...func() error) func() error {
	return func() error {
		var errs []error

		for i := len(closers) - 1; i >= 0; i-- {
			if closers[i] == nil {
				continue
			}
			if err := closers[i](); err != nil {
				errs = append(errs, err)
			}
		}

		return stderrors.Join(errs...)
	}
}

func noopCloser() error {
	return nil
}
