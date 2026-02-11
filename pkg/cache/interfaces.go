package cache

import (
	"context"
	"time"
)

type PrincipalSnapshot struct {
	Subject        string
	Tenant         string
	RoleMask       uint64
	PermissionMask uint64
	Claims         map[string]any
	ExpiresAt      time.Time
}

type TokenCache interface {
	SetToken(ctx context.Context, key string, snapshot PrincipalSnapshot, ttl time.Duration) error
	GetToken(ctx context.Context, key string) (PrincipalSnapshot, bool, error)
	DeleteToken(ctx context.Context, key string) error
}

type PrincipalCache interface {
	SetPrincipal(ctx context.Context, key string, snapshot PrincipalSnapshot, ttl time.Duration) error
	GetPrincipal(ctx context.Context, key string) (PrincipalSnapshot, bool, error)
	DeletePrincipal(ctx context.Context, key string) error
}

type PermissionCache interface {
	SetPermissionMask(ctx context.Context, key string, permissionMask uint64, ttl time.Duration) error
	GetPermissionMask(ctx context.Context, key string) (uint64, bool, error)
	DeletePermissionMask(ctx context.Context, key string) error
}
