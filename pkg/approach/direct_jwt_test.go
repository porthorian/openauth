package approach

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/porthorian/openauth/pkg/session"
	sessionjwt "github.com/porthorian/openauth/pkg/session/jwt"
)

type staticValidator struct {
	claims session.Claims
	err    error
}

func (v staticValidator) ValidateToken(ctx context.Context, token string) (session.Claims, error) {
	_ = ctx
	_ = token
	if v.err != nil {
		return nil, v.err
	}
	return v.claims, nil
}

func TestNewDirectJWTHandlerRequiresValidator(t *testing.T) {
	_, err := NewDirectJWTHandler(DirectJWTConfig{})
	if !errors.Is(err, ErrNilTokenValidator) {
		t.Fatalf("expected ErrNilTokenValidator, got: %v", err)
	}
}

func TestDirectJWTHandlerValidate(t *testing.T) {
	now := time.Date(2026, 3, 4, 13, 0, 0, 0, time.UTC)
	manager, err := sessionjwt.NewManager(sessionjwt.Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: "HS256",
			Material:  []byte("test-secret-signing-key"),
		},
		ClockSkew: 0,
		Now: func() time.Time {
			return now
		},
	})
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	token, err := manager.IssueToken(context.Background(), "user-1", session.Claims{
		"tenant": "acme",
		"role":   "admin",
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	handler, err := NewDirectJWTHandler(DirectJWTConfig{
		Validator: manager,
	})
	if err != nil {
		t.Fatalf("NewDirectJWTHandler returned error: %v", err)
	}

	result, err := handler.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if result.Subject != "user-1" {
		t.Fatalf("unexpected subject: %q", result.Subject)
	}
	if result.Tenant != "acme" {
		t.Fatalf("unexpected tenant: %q", result.Tenant)
	}
	if result.ExpiresAt.IsZero() {
		t.Fatalf("expected non-zero ExpiresAt")
	}
}

func TestDirectJWTHandlerValidateMissingSubject(t *testing.T) {
	handler, err := NewDirectJWTHandler(DirectJWTConfig{
		Validator: staticValidator{
			claims: session.Claims{
				"exp": time.Now().UTC().Add(time.Minute).Unix(),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewDirectJWTHandler returned error: %v", err)
	}

	_, err = handler.Validate(context.Background(), "token-value")
	if !errors.Is(err, ErrMissingSubjectClaim) {
		t.Fatalf("expected ErrMissingSubjectClaim, got: %v", err)
	}
}

func TestDirectJWTHandlerValidateInvalidExpiration(t *testing.T) {
	handler, err := NewDirectJWTHandler(DirectJWTConfig{
		Validator: staticValidator{
			claims: session.Claims{
				"sub": "user-1",
				"exp": "not-a-number",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewDirectJWTHandler returned error: %v", err)
	}

	_, err = handler.Validate(context.Background(), "token-value")
	if !errors.Is(err, ErrInvalidExpirationClaim) {
		t.Fatalf("expected ErrInvalidExpirationClaim, got: %v", err)
	}
}
