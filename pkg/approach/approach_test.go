package approach

import (
	"context"
	"errors"
	"testing"
	"time"
)

type staticHandler struct {
	name   string
	result Result
	err    error
}

func (h staticHandler) Name() string {
	return h.name
}

func (h staticHandler) Validate(ctx context.Context, token string) (Result, error) {
	_ = ctx
	_ = token
	if h.err != nil {
		return Result{}, h.err
	}
	return h.result, nil
}

func TestNewRegistryRejectsDuplicateName(t *testing.T) {
	_, err := NewRegistry(
		staticHandler{name: NameDirectJWT},
		staticHandler{name: NameDirectJWT},
	)
	if !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("expected ErrDuplicateName, got: %v", err)
	}
}

func TestRegistryValidate(t *testing.T) {
	expected := Result{
		Subject:   "user-1",
		Tenant:    "default",
		Claims:    map[string]any{"role": "admin"},
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}

	registry, err := NewRegistry(staticHandler{
		name:   NameDirectJWT,
		result: expected,
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	result, err := registry.Validate(context.Background(), NameDirectJWT, "token-value")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if result.Subject != expected.Subject {
		t.Fatalf("unexpected subject: got=%q want=%q", result.Subject, expected.Subject)
	}
	if result.Tenant != expected.Tenant {
		t.Fatalf("unexpected tenant: got=%q want=%q", result.Tenant, expected.Tenant)
	}
}

func TestRegistryValidateUnknownHandler(t *testing.T) {
	registry, err := NewRegistry(staticHandler{name: NameDirectJWT})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	_, err = registry.Validate(context.Background(), NamePhantomToken, "token-value")
	if !errors.Is(err, ErrHandlerNotFound) {
		t.Fatalf("expected ErrHandlerNotFound, got: %v", err)
	}
}

func TestRegistryValidateNilRegistry(t *testing.T) {
	var registry *Registry
	_, err := registry.Validate(context.Background(), NameDirectJWT, "token-value")
	if !errors.Is(err, ErrNilRegistry) {
		t.Fatalf("expected ErrNilRegistry, got: %v", err)
	}
}
