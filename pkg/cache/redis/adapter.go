package redis

import (
	"context"
	"errors"
	"time"

	"github.com/porthorian/openauth/pkg/cache"
)

var (
	ErrNotImplemented = errors.New("redis cache adapter: not implemented")
)

type Config struct {
	Address     string
	Username    string
	Password    string
	Database    int
	Namespace   string
	DialTimeout time.Duration
}

type Adapter struct {
	config Config
}

var _ cache.TokenCache = (*Adapter)(nil)
var _ cache.PrincipalCache = (*Adapter)(nil)
var _ cache.PermissionCache = (*Adapter)(nil)

func NewAdapter(config Config) *Adapter {
	return &Adapter{config: config}
}

func (a *Adapter) SetToken(ctx context.Context, key string, snapshot cache.PrincipalSnapshot, ttl time.Duration) error {
	return ErrNotImplemented
}

func (a *Adapter) GetToken(ctx context.Context, key string) (cache.PrincipalSnapshot, bool, error) {
	return cache.PrincipalSnapshot{}, false, ErrNotImplemented
}

func (a *Adapter) DeleteToken(ctx context.Context, key string) error {
	return ErrNotImplemented
}

func (a *Adapter) SetPrincipal(ctx context.Context, key string, snapshot cache.PrincipalSnapshot, ttl time.Duration) error {
	return ErrNotImplemented
}

func (a *Adapter) GetPrincipal(ctx context.Context, key string) (cache.PrincipalSnapshot, bool, error) {
	return cache.PrincipalSnapshot{}, false, ErrNotImplemented
}

func (a *Adapter) DeletePrincipal(ctx context.Context, key string) error {
	return ErrNotImplemented
}

func (a *Adapter) SetPermissionMask(ctx context.Context, key string, permissionMask uint64, ttl time.Duration) error {
	return ErrNotImplemented
}

func (a *Adapter) GetPermissionMask(ctx context.Context, key string) (uint64, bool, error) {
	return 0, false, ErrNotImplemented
}

func (a *Adapter) DeletePermissionMask(ctx context.Context, key string) error {
	return ErrNotImplemented
}
