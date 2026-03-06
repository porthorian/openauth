package cache

import (
	"context"
	"time"

	"github.com/porthorian/openauth/pkg/authz"
)

type PrincipalSnapshot struct {
	Subject        string
	Tenant         string
	RoleMask       authz.RoleMask
	PermissionMask authz.PermissionMask
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
	SetPermissionMask(ctx context.Context, key string, permissionMask authz.PermissionMask, ttl time.Duration) error
	GetPermissionMask(ctx context.Context, key string) (authz.PermissionMask, bool, error)
	DeletePermissionMask(ctx context.Context, key string) error
}

type Dependencies struct {
	Token      TokenCache
	Principal  PrincipalCache
	Permission PermissionCache
}
