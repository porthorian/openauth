package openauth

import (
	"context"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

type Claims map[string]any
type Principal struct {
	Subject         string    // Use Subject as the canonical user/service identifier so policies, cache keys, and audit trails all map to one identity.
	Tenant          string    // Use Tenant to enforce multi-tenant isolation so the same Subject can be scoped safely per customer/org boundary.
	RoleMask        uint64    // Use RoleMask for fast role-based checks when you want coarse permissions (ex viewer/editor/admin) without repeated DB lookups.
	PermissionMask  uint64    // Use PermissionMask for fine-grained action checks when direct grants/overrides must be enforced at request time.
	Claims          Claims    // Claims carries contextual identity attributes needed for policy evaluation and token enrichment.
	AuthenticatedAt time.Time // AuthenticatedAt preserves auth time for freshness controls, TTL policies, and auditing.
}

type InputType string

const (
	InputTypePassword InputType = "password"
	InputTypeToken    InputType = "token"
)

type AuthInput struct {
	UserID   string
	Type     InputType
	Value    string
	Metadata map[string]string
}

type CreateAuthInput struct {
	UserID    string
	Value     string
	ExpiresAt *time.Time
	Metadata  map[string]string
}

type Authenticator interface {
	Authorize(ctx context.Context, input AuthInput) (Principal, error)
	CreateAuth(ctx context.Context, input CreateAuthInput) error
	ValidateToken(ctx context.Context, token string) (Principal, error)
}

func (a AuthInput) GetMaterialType() storage.AuthMaterialType {
	switch a.Type {
	case InputTypePassword:
		return storage.AuthMaterialTypePassword
	case InputTypeToken:
		// TODO: consider supporting multiple token types (e.g. bearer, mac) and encoding them in the input type or metadata for more flexible token handling
		return ""
	}
	return ""
}

func (a CreateAuthInput) Normalize() CreateAuthInput {
	userID := strings.TrimSpace(a.UserID)
	value := strings.TrimSpace(a.Value)

	var expiresAt *time.Time
	if a.ExpiresAt != nil {
		exp := a.ExpiresAt.UTC()
		if exp.After(time.Now().UTC()) {
			expiresAt = &exp
		}
	}

	return CreateAuthInput{
		UserID:    userID,
		Value:     value,
		ExpiresAt: expiresAt,
		Metadata:  a.Metadata,
	}
}
