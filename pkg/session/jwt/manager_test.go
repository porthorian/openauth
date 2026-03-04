package jwt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/porthorian/openauth/pkg/session"
)

func TestIssueAndValidateToken(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		Issuer:    "openauth.test",
		Audience:  []string{"api"},
		ClockSkew: 0,
		Now: func() time.Time {
			return now
		},
	})

	token, err := manager.IssueToken(context.Background(), "user-1", session.Claims{
		"role": "admin",
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	claims, err := manager.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}

	if got := strings.TrimSpace(mustString(t, claims["sub"])); got != "user-1" {
		t.Fatalf("unexpected sub claim: %q", got)
	}

	if got := strings.TrimSpace(mustString(t, claims["iss"])); got != "openauth.test" {
		t.Fatalf("unexpected iss claim: %q", got)
	}

	if got := strings.TrimSpace(mustString(t, claims["role"])); got != "admin" {
		t.Fatalf("unexpected role claim: %q", got)
	}
}

func TestValidateTokenRejectsExpiredToken(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		ClockSkew: 0,
		Now: func() time.Time {
			return now
		},
	})

	token, err := manager.IssueToken(context.Background(), "user-1", nil, time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	now = now.Add(2 * time.Minute)
	_, err = manager.ValidateToken(context.Background(), token)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestValidateTokenRejectsIssuerMismatch(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	signer := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		Issuer: "issuer-a",
		Now: func() time.Time {
			return now
		},
	})

	validator := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		Issuer: "issuer-b",
		Now: func() time.Time {
			return now
		},
	})

	token, err := signer.IssueToken(context.Background(), "user-1", nil, time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	_, err = validator.ValidateToken(context.Background(), token)
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got: %v", err)
	}
}

func TestValidateTokenRejectsAudienceMismatch(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	signer := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		Audience: []string{"aud-a"},
		Now: func() time.Time {
			return now
		},
	})

	validator := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		Audience: []string{"aud-b"},
		Now: func() time.Time {
			return now
		},
	})

	token, err := signer.IssueToken(context.Background(), "user-1", nil, time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	_, err = validator.ValidateToken(context.Background(), token)
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience, got: %v", err)
	}
}

func TestValidateTokenRejectsTamperedSignature(t *testing.T) {
	manager := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
	})

	token, err := manager.IssueToken(context.Background(), "user-1", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token structure")
	}
	parts[1] = tamperSegment(parts[1])
	tampered := strings.Join(parts, ".")

	_, err = manager.ValidateToken(context.Background(), tampered)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got: %v", err)
	}
}

func TestIssueTokenRejectsReservedClaims(t *testing.T) {
	manager := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
	})

	_, err := manager.IssueToken(context.Background(), "user-1", session.Claims{
		"exp": time.Now().Unix(),
	}, time.Minute)
	if !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("expected ErrReservedClaim, got: %v", err)
	}
}

func TestValidateTokenWithResolver(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	signer := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		Now: func() time.Time {
			return now
		},
	})

	validator := newTestManager(t, Config{
		KeyResolver: staticResolver{
			keys: map[string]session.Key{
				"key-1": {
					ID:        "key-1",
					Algorithm: algorithmHS256,
					Material:  []byte("test-secret-signing-key"),
				},
			},
		},
		Now: func() time.Time {
			return now
		},
	})

	token, err := signer.IssueToken(context.Background(), "user-1", nil, time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	_, err = validator.ValidateToken(context.Background(), token)
	if err != nil {
		t.Fatalf("ValidateToken returned error: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	now := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	manager := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
		ClockSkew: 0,
		Now: func() time.Time {
			return now
		},
	})

	sessionToken, err := manager.IssueSession(context.Background(), "user-1", 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueSession returned error: %v", err)
	}

	ok, err := manager.ValidateSession(context.Background(), sessionToken)
	if err != nil {
		t.Fatalf("ValidateSession returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected session to validate")
	}

	if err := manager.RevokeSession(context.Background(), sessionToken); err != nil {
		t.Fatalf("RevokeSession returned error: %v", err)
	}

	ok, err = manager.ValidateSession(context.Background(), sessionToken)
	if err != nil {
		t.Fatalf("ValidateSession after revoke returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected revoked session to fail validation")
	}
}

func TestValidateSessionRejectsNonSessionToken(t *testing.T) {
	manager := newTestManager(t, Config{
		SigningKey: session.Key{
			ID:        "key-1",
			Algorithm: algorithmHS256,
			Material:  []byte("test-secret-signing-key"),
		},
	})

	token, err := manager.IssueToken(context.Background(), "user-1", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken returned error: %v", err)
	}

	ok, err := manager.ValidateSession(context.Background(), token)
	if !errors.Is(err, ErrInvalidSessionToken) {
		t.Fatalf("expected ErrInvalidSessionToken, got: %v", err)
	}
	if ok {
		t.Fatalf("expected non-session token validation to return false")
	}
}

func newTestManager(t *testing.T, config Config) *Manager {
	t.Helper()

	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}

	return manager
}

func mustString(t *testing.T, value any) string {
	t.Helper()

	typed, ok := value.(string)
	if !ok {
		t.Fatalf("expected string claim value, got: %T", value)
	}

	return typed
}

func tamperSegment(segment string) string {
	if segment == "" {
		return "x"
	}

	if segment[0] == 'a' {
		return "b" + segment[1:]
	}
	return "a" + segment[1:]
}

type staticResolver struct {
	keys map[string]session.Key
}

func (r staticResolver) ResolveKey(ctx context.Context, keyID string) (session.Key, error) {
	_ = ctx

	if keyID == "" {
		for _, key := range r.keys {
			return key, nil
		}
	}

	key, ok := r.keys[keyID]
	if !ok {
		return session.Key{}, errors.New("key not found")
	}

	return key, nil
}
