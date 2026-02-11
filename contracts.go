package openauth

import (
	"context"
	"time"
)

type Claims map[string]any

type PasswordInput struct {
	UserID   string
	Password string
	Metadata map[string]string
}

type TokenInput struct {
	UserID   string
	Token    string
	Metadata map[string]string
}

type Principal struct {
	Subject         string    // Use Subject as the canonical user/service identifier so policies, cache keys, and audit trails all map to one identity.
	Tenant          string    // Use Tenant to enforce multi-tenant isolation so the same Subject can be scoped safely per customer/org boundary.
	RoleMask        uint64    // Use RoleMask for fast role-based checks when you want coarse permissions (ex viewer/editor/admin) without repeated DB lookups.
	PermissionMask  uint64    // Use PermissionMask for fine-grained action checks when direct grants/overrides must be enforced at request time.
	Claims          Claims    // Claims carries contextual identity attributes needed for policy evaluation and token enrichment.
	AuthenticatedAt time.Time // AuthenticatedAt preserves auth time for freshness controls, TTL policies, and auditing.
}

type Authenticator interface {
	AuthPassword(ctx context.Context, input PasswordInput) (Principal, error)
	AuthToken(ctx context.Context, input TokenInput) (Principal, error)
	ValidateToken(ctx context.Context, token string) (Principal, error)
}
