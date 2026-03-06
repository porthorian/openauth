package openauth

import (
	"context"
	"errors"
	"testing"

	oerrors "github.com/porthorian/openauth/pkg/errors"
)

type constructorAuthStub struct{}

func (s constructorAuthStub) Authorize(ctx context.Context, input AuthInput) (Principal, error) {
	_ = ctx
	_ = input
	return Principal{}, nil
}

func (s constructorAuthStub) CreateAuth(ctx context.Context, input CreateAuthInput) error {
	_ = ctx
	_ = input
	return nil
}

func (s constructorAuthStub) ValidateToken(ctx context.Context, token string) (Principal, error) {
	_ = ctx
	_ = token
	return Principal{}, nil
}

type constructorManagerStub struct{}

func (s constructorManagerStub) SetSubjectRoles(ctx context.Context, input SetSubjectRolesInput) error {
	_ = ctx
	_ = input
	return nil
}

func (s constructorManagerStub) SetSubjectPermissionOverrides(ctx context.Context, input SetSubjectPermissionOverridesInput) error {
	_ = ctx
	_ = input
	return nil
}

type constructorCheckerStub struct{}

func (s constructorCheckerStub) HasAllRoles(principal Principal, roleKeys ...string) (bool, error) {
	_ = principal
	_ = roleKeys
	return true, nil
}

func (s constructorCheckerStub) HasAnyRoles(principal Principal, roleKeys ...string) (bool, error) {
	_ = principal
	_ = roleKeys
	return true, nil
}

func (s constructorCheckerStub) RequireAllRoles(principal Principal, roleKeys ...string) error {
	_ = principal
	_ = roleKeys
	return nil
}

func (s constructorCheckerStub) RequireAnyRoles(principal Principal, roleKeys ...string) error {
	_ = principal
	_ = roleKeys
	return nil
}

func (s constructorCheckerStub) HasAllPermissions(principal Principal, permissionKeys ...string) (bool, error) {
	_ = principal
	_ = permissionKeys
	return true, nil
}

func (s constructorCheckerStub) HasAnyPermissions(principal Principal, permissionKeys ...string) (bool, error) {
	_ = principal
	_ = permissionKeys
	return true, nil
}

func (s constructorCheckerStub) RequireAllPermissions(principal Principal, permissionKeys ...string) error {
	_ = principal
	_ = permissionKeys
	return nil
}

func (s constructorCheckerStub) RequireAnyPermissions(principal Principal, permissionKeys ...string) error {
	_ = principal
	_ = permissionKeys
	return nil
}

func TestNewBuildsClientWithExplicitDependencies(t *testing.T) {
	called := false
	auth := &constructorAuthStub{}
	manager := &constructorManagerStub{}
	checker := &constructorCheckerStub{}

	client, err := New(Config{}, func(resolved Config) (ClientDependencies, error) {
		called = true
		_ = resolved
		return ClientDependencies{
			Authenticator:        auth,
			AuthorizationManager: manager,
			AuthorizationChecker: checker,
		}, nil
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if !called {
		t.Fatalf("expected auth builder to be called")
	}
	if client == nil {
		t.Fatalf("expected client")
	}
	if client.auth != auth {
		t.Fatalf("expected authenticator from builder to be set")
	}
	if client.authzManager != manager {
		t.Fatalf("expected authorization manager from builder to be set")
	}
	if client.authzChecker != checker {
		t.Fatalf("expected authorization checker from builder to be set")
	}
}

func TestNewRejectsNilBuilder(t *testing.T) {
	_, err := New(Config{}, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, oerrors.ErrMissingAuthenticator) {
		t.Fatalf("expected missing authenticator error, got %v", err)
	}
}

func TestNewClientWithBuilderClosesOnBuilderError(t *testing.T) {
	closed := false
	buildErr := errors.New("builder failed")

	_, err := newClientWithBuilder(
		Config{},
		func() error {
			closed = true
			return nil
		},
		func(resolved Config) (ClientDependencies, error) {
			_ = resolved
			return ClientDependencies{}, buildErr
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, buildErr) {
		t.Fatalf("expected builder error, got %v", err)
	}
	if !closed {
		t.Fatalf("expected closeResource to be called")
	}
}

func TestNewClientWithBuilderClosesOnNilAuthenticator(t *testing.T) {
	closed := false

	_, err := newClientWithBuilder(
		Config{},
		func() error {
			closed = true
			return nil
		},
		func(resolved Config) (ClientDependencies, error) {
			_ = resolved
			return ClientDependencies{}, nil
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, oerrors.ErrMissingAuthenticator) {
		t.Fatalf("expected missing authenticator error, got %v", err)
	}
	if !closed {
		t.Fatalf("expected closeResource to be called")
	}
}

func TestNewAuthOnlyBundleReturnsNotImplementedForAuthz(t *testing.T) {
	client, err := New(Config{}, func(resolved Config) (ClientDependencies, error) {
		_ = resolved
		return ClientDependencies{
			Authenticator: &constructorAuthStub{},
		}, nil
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	err = client.SetSubjectRoles(context.Background(), SetSubjectRolesInput{Subject: "subject-1"})
	if !oerrors.IsCode(err, oerrors.CodeNotImplemented) {
		t.Fatalf("expected not_implemented error for SetSubjectRoles, got %v", err)
	}

	_, err = client.HasAllPermissions(Principal{}, "read")
	if !oerrors.IsCode(err, oerrors.CodeNotImplemented) {
		t.Fatalf("expected not_implemented error for HasAllPermissions, got %v", err)
	}

	_, err = client.HasAnyRoles(Principal{}, "viewer")
	if !oerrors.IsCode(err, oerrors.CodeNotImplemented) {
		t.Fatalf("expected not_implemented error for HasAnyRoles, got %v", err)
	}
}

func TestClientRoleCheckDelegatesToChecker(t *testing.T) {
	client, err := New(Config{}, func(resolved Config) (ClientDependencies, error) {
		_ = resolved
		return ClientDependencies{
			Authenticator:        &constructorAuthStub{},
			AuthorizationChecker: &constructorCheckerStub{},
		}, nil
	})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	ok, err := client.HasAllRoles(Principal{}, "viewer")
	if err != nil {
		t.Fatalf("HasAllRoles returned error: %v", err)
	}
	if !ok {
		t.Fatalf("expected role check to pass")
	}
}

func TestNewDefaultSmoke(t *testing.T) {
	client, err := NewDefault(Config{})
	if err != nil {
		t.Fatalf("NewDefault returned error: %v", err)
	}
	if client == nil {
		t.Fatalf("expected client")
	}
	if client.auth == nil {
		t.Fatalf("expected authenticator to be set")
	}
	if client.authzManager == nil {
		t.Fatalf("expected authorization manager to be set")
	}
	if client.authzChecker == nil {
		t.Fatalf("expected authorization checker to be set")
	}
}
