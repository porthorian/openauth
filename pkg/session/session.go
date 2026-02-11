package session

import (
	"context"
	"time"
)

type Claims map[string]any

type Key struct {
	ID        string
	Algorithm string
	Material  []byte
}

type KeyResolver interface {
	ResolveKey(ctx context.Context, keyID string) (Key, error)
}

type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (Claims, error)
}

type TokenIssuer interface {
	IssueToken(ctx context.Context, subject string, claims Claims, ttl time.Duration) (string, error)
}

type SessionManager interface {
	IssueSession(ctx context.Context, subject string, ttl time.Duration) (string, error)
	ValidateSession(ctx context.Context, sessionID string) (bool, error)
	RevokeSession(ctx context.Context, sessionID string) error
}
