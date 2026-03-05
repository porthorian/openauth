package httptransport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/porthorian/openauth"
)

type staticValidator struct {
	principal openauth.Principal
	err       error
	called    bool
	token     string
}

func (v *staticValidator) Validate(ctx context.Context, token string) (openauth.Principal, error) {
	_ = ctx
	v.called = true
	v.token = token
	if v.err != nil {
		return openauth.Principal{}, v.err
	}
	return v.principal, nil
}

func TestMiddlewareBearerSuccess(t *testing.T) {
	validator := &staticValidator{principal: openauth.Principal{Subject: "user-1"}}
	nextCalled := false

	handler := Middleware(validator, DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Fatalf("expected principal in context")
		}
		if principal.Subject != "user-1" {
			t.Fatalf("unexpected principal value: %#v", principal)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token-123")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected next handler to be called")
	}
	if !validator.called {
		t.Fatalf("expected validator to be called")
	}
	if validator.token != "token-123" {
		t.Fatalf("unexpected token: %q", validator.token)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
}

func TestMiddlewareRejectsMissingToken(t *testing.T) {
	validator := &staticValidator{principal: openauth.Principal{Subject: "user-1"}}
	nextCalled := false

	handler := Middleware(validator, DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Fatalf("did not expect next handler to be called")
	}
	if validator.called {
		t.Fatalf("did not expect validator to be called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("expected WWW-Authenticate header")
	}
}

func TestMiddlewareRejectsInvalidAuthorizationHeader(t *testing.T) {
	validator := &staticValidator{principal: openauth.Principal{Subject: "user-1"}}

	handler := Middleware(validator, DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Token abc")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if validator.called {
		t.Fatalf("did not expect validator to be called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
}

func TestMiddlewareUsesCookieFallback(t *testing.T) {
	validator := &staticValidator{principal: openauth.Principal{Subject: "user-1"}}
	cfg := DefaultConfig()
	cfg.CookieName = "access_token"

	handler := Middleware(validator, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "cookie-token"})
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !validator.called {
		t.Fatalf("expected validator to be called")
	}
	if validator.token != "cookie-token" {
		t.Fatalf("unexpected token: %q", validator.token)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
}

func TestMiddlewareUsesCustomHeaderRawToken(t *testing.T) {
	validator := &staticValidator{principal: openauth.Principal{Subject: "user-1"}}
	cfg := DefaultConfig()
	cfg.TokenHeader = "X-Auth-Token"

	handler := Middleware(validator, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Auth-Token", "custom-token")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !validator.called {
		t.Fatalf("expected validator to be called")
	}
	if validator.token != "custom-token" {
		t.Fatalf("unexpected token: %q", validator.token)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
}

func TestMiddlewareSkipper(t *testing.T) {
	validator := &staticValidator{principal: openauth.Principal{Subject: "user-1"}, err: errors.New("should not be called")}
	cfg := DefaultConfig()
	cfg.Skipper = func(r *http.Request) bool {
		_ = r
		return true
	}

	nextCalled := false
	handler := Middleware(validator, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected next handler to be called")
	}
	if validator.called {
		t.Fatalf("did not expect validator to be called")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
}

func TestMiddlewareNilValidator(t *testing.T) {
	handler := Middleware(nil, DefaultConfig())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status code: %d", rr.Code)
	}
}

func TestPrincipalFromContextMissing(t *testing.T) {
	ctx := context.Background()

	_, ok := PrincipalFromContext(ctx)
	if ok {
		t.Fatalf("expected missing principal to return ok=false")
	}
}

func TestPrincipalFromContextTypeMismatch(t *testing.T) {
	ctx := context.WithValue(context.Background(), principalContextKey, "not-a-principal")

	_, ok := PrincipalFromContext(ctx)
	if ok {
		t.Fatalf("expected type mismatch to return ok=false")
	}
}
