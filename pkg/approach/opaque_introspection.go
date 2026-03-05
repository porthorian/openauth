package approach

import (
	"context"
	"errors"
	"strings"

	"github.com/porthorian/openauth/pkg/protocol/oauth"
	"github.com/porthorian/openauth/pkg/session"
)

var (
	ErrNilIntrospector = errors.New("approach: introspector is nil")
	ErrInactiveToken   = errors.New("approach: token is inactive")
)

type OpaqueIntrospectionConfig struct {
	Name         string
	Introspector oauth.Introspector
	ClaimMapper  oauth.ClaimMapper
	TenantClaim  string
}

type OpaqueIntrospectionHandler struct {
	name         string
	introspector oauth.Introspector
	claimMapper  oauth.ClaimMapper
	tenantClaim  string
}

var _ Handler = (*OpaqueIntrospectionHandler)(nil)

func NewOpaqueIntrospectionHandler(config OpaqueIntrospectionConfig) (*OpaqueIntrospectionHandler, error) {
	if config.Introspector == nil {
		return nil, ErrNilIntrospector
	}

	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = NameOpaqueIntrospection
	}

	tenantClaim := strings.TrimSpace(config.TenantClaim)
	if tenantClaim == "" {
		tenantClaim = defaultTenantClaim
	}

	return &OpaqueIntrospectionHandler{
		name:         name,
		introspector: config.Introspector,
		claimMapper:  config.ClaimMapper,
		tenantClaim:  tenantClaim,
	}, nil
}

func (h *OpaqueIntrospectionHandler) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

func (h *OpaqueIntrospectionHandler) Validate(ctx context.Context, token string) (Result, error) {
	if h == nil || h.introspector == nil {
		return Result{}, ErrNilIntrospector
	}

	response, err := h.introspector.Introspect(ctx, token)
	if err != nil {
		return Result{}, err
	}
	if !response.Active {
		return Result{}, ErrInactiveToken
	}

	subject := strings.TrimSpace(response.Subject)
	if subject == "" {
		return Result{}, ErrMissingSubjectClaim
	}

	claims := cloneMapClaims(response.Claims)
	if h.claimMapper != nil {
		mappedClaims, mapErr := h.claimMapper.MapClaims(ctx, cloneMapClaims(claims))
		if mapErr != nil {
			return Result{}, mapErr
		}
		claims = cloneMapClaims(mappedClaims)
	}

	expiresAt := response.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		if _, hasExp := claims["exp"]; hasExp {
			parsedExp, parseErr := claimUnixTime(session.Claims(claims), "exp")
			if parseErr != nil {
				return Result{}, parseErr
			}
			expiresAt = parsedExp
		}
	}

	tenant, _ := claimString(session.Claims(claims), h.tenantClaim)
	return Result{
		Subject:   subject,
		Tenant:    tenant,
		Claims:    claims,
		ExpiresAt: expiresAt,
	}, nil
}

func cloneMapClaims(claims map[string]any) map[string]any {
	if len(claims) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(claims))
	for key, value := range claims {
		cloned[key] = value
	}
	return cloned
}
