package openauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/authz"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type Claims map[string]any
type RoleMask = authz.RoleMask
type PermissionMask = authz.PermissionMask
type PermissionDefinition = authz.PermissionDefinition
type RoleDefinition = authz.RoleDefinition

type AuthorizationRegistry struct {
	Permissions []PermissionDefinition
	Roles       []RoleDefinition
}

type AuthorizationConfig struct {
	Registry      AuthorizationRegistry
	DefaultTenant string
}

type Principal struct {
	Subject         string // Use Subject as the canonical user/service identifier so policies, cache keys, and audit trails all map to one identity.
	Tenant          string // Use Tenant to enforce multi-tenant isolation so the same Subject can be scoped safely per customer/org boundary.
	RoleMask        RoleMask
	PermissionMask  PermissionMask
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
	Tenant   string
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

type SetSubjectRolesInput struct {
	Subject  string
	Tenant   string
	RoleKeys []string
}

type SetSubjectPermissionOverridesInput struct {
	Subject   string
	Tenant    string
	GrantKeys []string
	DenyKeys  []string
}

type AuthorizationManager interface {
	SetSubjectRoles(ctx context.Context, input SetSubjectRolesInput) error
	SetSubjectPermissionOverrides(ctx context.Context, input SetSubjectPermissionOverridesInput) error
}

type AuthorizationChecker interface {
	HasAllRoles(principal Principal, roleKeys ...string) (bool, error)
	HasAnyRoles(principal Principal, roleKeys ...string) (bool, error)
	RequireAllRoles(principal Principal, roleKeys ...string) error
	RequireAnyRoles(principal Principal, roleKeys ...string) error
	HasAllPermissions(principal Principal, permissionKeys ...string) (bool, error)
	HasAnyPermissions(principal Principal, permissionKeys ...string) (bool, error)
	RequireAllPermissions(principal Principal, permissionKeys ...string) error
	RequireAnyPermissions(principal Principal, permissionKeys ...string) error
}

func (a InputType) GetMaterialType() storage.AuthMaterialType {
	switch a {
	case InputTypePassword:
		return storage.AuthMaterialTypePassword
	case InputTypeToken:
		// TODO: consider supporting multiple token types (e.g. bearer, mac) and encoding them in the input type or metadata for more flexible token handling
		return ""
	}
	return ""
}

func (a AuthInput) GetMaterialType() storage.AuthMaterialType {
	return a.Type.GetMaterialType()
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

func (a CreateAuthInput) Validate() error {
	if a.UserID == "" {
		return oerrors.New(oerrors.CodeInvalidCredentials, "user_id is required")
	}

	if a.Value == "" {
		return oerrors.New(oerrors.CodeInvalidCredentials, "auth value is required")
	}

	if a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now().UTC()) {
		return oerrors.New(oerrors.CodeInvalidCredentials, "expires_at must be in the future")
	}

	return nil
}

func (input SetSubjectRolesInput) Normalize() SetSubjectRolesInput {
	return SetSubjectRolesInput{
		Subject:  strings.TrimSpace(input.Subject),
		Tenant:   strings.TrimSpace(input.Tenant),
		RoleKeys: normalizeStringKeys(input.RoleKeys),
	}
}

func (input SetSubjectRolesInput) Validate() error {
	if strings.TrimSpace(input.Subject) == "" {
		return oerrors.New(oerrors.CodeInvalidCredentials, "subject is required")
	}
	return nil
}

func (input SetSubjectPermissionOverridesInput) Normalize() SetSubjectPermissionOverridesInput {
	return SetSubjectPermissionOverridesInput{
		Subject:   strings.TrimSpace(input.Subject),
		Tenant:    strings.TrimSpace(input.Tenant),
		GrantKeys: normalizeStringKeys(input.GrantKeys),
		DenyKeys:  normalizeStringKeys(input.DenyKeys),
	}
}

func (input SetSubjectPermissionOverridesInput) Validate() error {
	if strings.TrimSpace(input.Subject) == "" {
		return oerrors.New(oerrors.CodeInvalidCredentials, "subject is required")
	}
	return nil
}

func normalizeStringKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}

	dedup := make(map[string]struct{}, len(keys))
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, exists := dedup[trimmed]; exists {
			continue
		}
		dedup[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func mapInputValidationError(err error) error {
	if err == nil {
		return nil
	}
	var typed *oerrors.Error
	if errors.As(err, &typed) {
		return err
	}
	return oerrors.Wrap(oerrors.CodeInvalidCredentials, "invalid input", err)
}
