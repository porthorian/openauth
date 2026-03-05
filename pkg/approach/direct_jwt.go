package approach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/session"
)

const defaultTenantClaim = "tenant"

var (
	ErrNilTokenValidator      = errors.New("approach: token validator is nil")
	ErrMissingSubjectClaim    = errors.New("approach: subject claim is missing")
	ErrInvalidExpirationClaim = errors.New("approach: expiration claim is invalid")
)

type DirectJWTConfig struct {
	Name        string
	Validator   session.TokenValidator
	TenantClaim string
}

type DirectJWTHandler struct {
	name        string
	validator   session.TokenValidator
	tenantClaim string
}

var _ Handler = (*DirectJWTHandler)(nil)

func NewDirectJWTHandler(config DirectJWTConfig) (*DirectJWTHandler, error) {
	if config.Validator == nil {
		return nil, ErrNilTokenValidator
	}

	name := strings.TrimSpace(config.Name)
	if name == "" {
		name = NameDirectJWT
	}

	tenantClaim := strings.TrimSpace(config.TenantClaim)
	if tenantClaim == "" {
		tenantClaim = defaultTenantClaim
	}

	return &DirectJWTHandler{
		name:        name,
		validator:   config.Validator,
		tenantClaim: tenantClaim,
	}, nil
}

func (h *DirectJWTHandler) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

func (h *DirectJWTHandler) Validate(ctx context.Context, token string) (Result, error) {
	if h == nil || h.validator == nil {
		return Result{}, ErrNilTokenValidator
	}

	claims, err := h.validator.ValidateToken(ctx, token)
	if err != nil {
		return Result{}, err
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

func claimString(claims session.Claims, key string) (string, bool) {
	raw, found := claims[key]
	if !found {
		return "", false
	}

	switch typed := raw.(type) {
	case string:
		value := strings.TrimSpace(typed)
		if value == "" {
			return "", false
		}
		return value, true
	case fmt.Stringer:
		value := strings.TrimSpace(typed.String())
		if value == "" {
			return "", false
		}
		return value, true
	default:
		return "", false
	}
}

func claimBool(claims session.Claims, key string) (bool, bool) {
	raw, found := claims[key]
	if !found {
		return false, false
	}

	switch typed := raw.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err != nil {
			return false, false
		}
		return parsed, true
	default:
		return false, false
	}
}

func claimUnixTime(claims session.Claims, key string) (time.Time, error) {
	raw, found := claims[key]
	if !found {
		return time.Time{}, fmt.Errorf("%w: missing %s", ErrInvalidExpirationClaim, key)
	}

	seconds, err := toInt64(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s", ErrInvalidExpirationClaim, key)
	}

	return time.Unix(seconds, 0).UTC(), nil
}

func toInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case float64:
		return int64(typed), nil
	case float32:
		return int64(typed), nil
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed, nil
		}
		parsedFloat, err := typed.Float64()
		if err != nil {
			return 0, err
		}
		return int64(parsedFloat), nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, errors.New("empty string")
		}
		if parsed, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return parsed, nil
		}
		parsedFloat, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, err
		}
		return int64(parsedFloat), nil
	default:
		return 0, errors.New("value is not numeric")
	}
}

func cloneResultClaims(claims session.Claims) map[string]any {
	if len(claims) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(claims))
	for key, value := range claims {
		cloned[key] = value
	}
	return cloned
}
