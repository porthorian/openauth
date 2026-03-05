package approach

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/porthorian/openauth/pkg/protocol/oauth"
)

type staticIntrospector struct {
	response oauth.IntrospectionResponse
	err      error
}

func (s staticIntrospector) Introspect(ctx context.Context, token string) (oauth.IntrospectionResponse, error) {
	_ = ctx
	_ = token
	if s.err != nil {
		return oauth.IntrospectionResponse{}, s.err
	}
	return s.response, nil
}

type staticClaimMapper struct {
	claims map[string]any
	err    error
}

func (m staticClaimMapper) MapClaims(ctx context.Context, claims map[string]any) (map[string]any, error) {
	_ = ctx
	_ = claims
	if m.err != nil {
		return nil, m.err
	}
	return m.claims, nil
}

func TestNewOpaqueIntrospectionHandlerRequiresIntrospector(t *testing.T) {
	_, err := NewOpaqueIntrospectionHandler(OpaqueIntrospectionConfig{})
	if !errors.Is(err, ErrNilIntrospector) {
		t.Fatalf("expected ErrNilIntrospector, got: %v", err)
	}
}

func TestOpaqueIntrospectionHandlerValidateInactiveToken(t *testing.T) {
	handler, err := NewOpaqueIntrospectionHandler(OpaqueIntrospectionConfig{
		Introspector: staticIntrospector{
			response: oauth.IntrospectionResponse{
				Active: false,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewOpaqueIntrospectionHandler returned error: %v", err)
	}

	_, err = handler.Validate(context.Background(), "opaque-token")
	if !errors.Is(err, ErrInactiveToken) {
		t.Fatalf("expected ErrInactiveToken, got: %v", err)
	}
}

func TestOpaqueIntrospectionHandlerValidate(t *testing.T) {
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)

	handler, err := NewOpaqueIntrospectionHandler(OpaqueIntrospectionConfig{
		Introspector: staticIntrospector{
			response: oauth.IntrospectionResponse{
				Active:    true,
				Subject:   "user-1",
				ExpiresAt: expiresAt,
				Claims: map[string]any{
					"tenant": "acme",
					"scope":  "read write",
				},
			},
		},
		ClaimMapper: staticClaimMapper{
			claims: map[string]any{
				"tenant": "mapped-tenant",
				"role":   "admin",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewOpaqueIntrospectionHandler returned error: %v", err)
	}

	result, err := handler.Validate(context.Background(), "opaque-token")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if result.Subject != "user-1" {
		t.Fatalf("unexpected subject: %q", result.Subject)
	}
	if result.Tenant != "mapped-tenant" {
		t.Fatalf("unexpected tenant: %q", result.Tenant)
	}
	if !result.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("unexpected expires_at: got=%s want=%s", result.ExpiresAt, expiresAt)
	}
	if got, ok := result.Claims["role"].(string); !ok || got != "admin" {
		t.Fatalf("expected mapped role claim, got=%v", result.Claims["role"])
	}
}

func TestOpaqueIntrospectionHandlerValidateFromExpClaim(t *testing.T) {
	exp := time.Now().UTC().Add(5 * time.Minute).Unix()

	handler, err := NewOpaqueIntrospectionHandler(OpaqueIntrospectionConfig{
		Introspector: staticIntrospector{
			response: oauth.IntrospectionResponse{
				Active:  true,
				Subject: "user-1",
				Claims: map[string]any{
					"tenant": "acme",
					"exp":    exp,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewOpaqueIntrospectionHandler returned error: %v", err)
	}

	result, err := handler.Validate(context.Background(), "opaque-token")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if result.ExpiresAt.Unix() != exp {
		t.Fatalf("unexpected expires_at unix: got=%d want=%d", result.ExpiresAt.Unix(), exp)
	}
}

func TestOpaqueIntrospectionHandlerValidateMissingSubject(t *testing.T) {
	handler, err := NewOpaqueIntrospectionHandler(OpaqueIntrospectionConfig{
		Introspector: staticIntrospector{
			response: oauth.IntrospectionResponse{
				Active: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewOpaqueIntrospectionHandler returned error: %v", err)
	}

	_, err = handler.Validate(context.Background(), "opaque-token")
	if !errors.Is(err, ErrMissingSubjectClaim) {
		t.Fatalf("expected ErrMissingSubjectClaim, got: %v", err)
	}
}
