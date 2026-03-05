package approach

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/porthorian/openauth/pkg/session"
	sessionjwt "github.com/porthorian/openauth/pkg/session/jwt"
)

func TestNewPhantomTokenHandlerRequiresValidator(t *testing.T) {
	_, err := NewPhantomTokenHandler(PhantomTokenConfig{})
	if !errors.Is(err, ErrNilTokenValidator) {
		t.Fatalf("expected ErrNilTokenValidator, got: %v", err)
	}
}

func TestPhantomTokenHandlerValidate(t *testing.T) {
	now := time.Date(2026, 3, 4, 14, 0, 0, 0, time.UTC)
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
		"tenant":           "acme",
		"default_role":     "reader",
		"openauth_phantom": true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	handler, err := NewPhantomTokenHandler(PhantomTokenConfig{
		Validator: manager,
	})
	if err != nil {
		t.Fatalf("NewPhantomTokenHandler returned error: %v", err)
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

func TestPhantomTokenHandlerValidateRejectsMissingMarker(t *testing.T) {
	now := time.Date(2026, 3, 4, 14, 0, 0, 0, time.UTC)
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
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	handler, err := NewPhantomTokenHandler(PhantomTokenConfig{
		Validator: manager,
	})
	if err != nil {
		t.Fatalf("NewPhantomTokenHandler returned error: %v", err)
	}

	_, err = handler.Validate(context.Background(), token)
	if !errors.Is(err, ErrInvalidPhantomToken) {
		t.Fatalf("expected ErrInvalidPhantomToken, got: %v", err)
	}
}

func TestPhantomTokenHandlerValidateRejectsFalseMarker(t *testing.T) {
	now := time.Date(2026, 3, 4, 14, 0, 0, 0, time.UTC)
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
		"tenant":           "acme",
		"openauth_phantom": false,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	handler, err := NewPhantomTokenHandler(PhantomTokenConfig{
		Validator: manager,
	})
	if err != nil {
		t.Fatalf("NewPhantomTokenHandler returned error: %v", err)
	}

	_, err = handler.Validate(context.Background(), token)
	if !errors.Is(err, ErrInvalidPhantomToken) {
		t.Fatalf("expected ErrInvalidPhantomToken, got: %v", err)
	}
}
