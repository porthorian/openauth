package approach

import (
	"context"
	"errors"
	"strings"

	"github.com/porthorian/openauth/pkg/session"
)

const defaultPhantomMarkerClaim = "openauth_phantom"

var ErrInvalidPhantomToken = errors.New("approach: token is not a valid phantom token")

type PhantomTokenConfig struct {
	Name        string
	Validator   session.TokenValidator
	TenantClaim string
	MarkerClaim string
}

type PhantomTokenHandler struct {
	name        string
	validator   session.TokenValidator
	tenantClaim string
	markerClaim string
}

var _ Handler = (*PhantomTokenHandler)(nil)

func NewPhantomTokenHandler(config PhantomTokenConfig) (*PhantomTokenHandler, error) {
	if config.Validator == nil {
		return nil, ErrNilTokenValidator
	}

	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = NamePhantomToken
	}

	tenantClaim := strings.TrimSpace(config.TenantClaim)
	if tenantClaim == "" {
		tenantClaim = defaultTenantClaim
	}

	markerClaim := strings.TrimSpace(config.MarkerClaim)
	if markerClaim == "" {
		markerClaim = defaultPhantomMarkerClaim
	}

	return &PhantomTokenHandler{
		name:        name,
		validator:   config.Validator,
		tenantClaim: tenantClaim,
		markerClaim: markerClaim,
	}, nil
}

func (h *PhantomTokenHandler) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

func (h *PhantomTokenHandler) Validate(ctx context.Context, token string) (Result, error) {
	if h == nil || h.validator == nil {
		return Result{}, ErrNilTokenValidator
	}

	claims, err := h.validator.ValidateToken(ctx, token)
	if err != nil {
		return Result{}, err
	}

	isPhantom, ok := claimBool(claims, h.markerClaim)
	if !ok || !isPhantom {
		return Result{}, ErrInvalidPhantomToken
	}

	subject, ok := claimString(claims, "sub")
	if !ok {
		return Result{}, ErrMissingSubjectClaim
	}

	expiresAt, err := claimUnixTime(claims, "exp")
	if err != nil {
		return Result{}, err
	}

	tenant, _ := claimString(claims, h.tenantClaim)
	return Result{
		Subject:   subject,
		Tenant:    tenant,
		Claims:    cloneResultClaims(claims),
		ExpiresAt: expiresAt,
	}, nil
}
