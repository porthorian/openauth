package httptransport

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/porthorian/openauth"
)

type TokenValidator interface {
	Validate(ctx context.Context, token string) (openauth.Principal, error)
}

type ErrorWriter func(w http.ResponseWriter, r *http.Request, statusCode int, err error)

type MiddlewareConfig struct {
	TokenHeader        string
	CookieName         string
	FailureStatusCode  int
	InternalStatusCode int
	ErrorWriter        ErrorWriter
	Skipper            func(r *http.Request) bool
}

var (
	ErrNilValidator               = errors.New("http transport: token validator is nil")
	ErrMissingToken               = errors.New("http transport: token not found in request")
	ErrInvalidAuthorizationHeader = errors.New("http transport: invalid authorization header")
)

func DefaultConfig() MiddlewareConfig {
	return MiddlewareConfig{
		TokenHeader:        "Authorization",
		CookieName:         "",
		FailureStatusCode:  http.StatusUnauthorized,
		InternalStatusCode: http.StatusInternalServerError,
	}
}

func Middleware(validator TokenValidator, config MiddlewareConfig) func(http.Handler) http.Handler {
	cfg := DefaultConfig()
	if strings.TrimSpace(config.TokenHeader) != "" {
		cfg.TokenHeader = strings.TrimSpace(config.TokenHeader)
	}
	if strings.TrimSpace(config.CookieName) != "" {
		cfg.CookieName = strings.TrimSpace(config.CookieName)
	}
	if config.FailureStatusCode > 0 {
		cfg.FailureStatusCode = config.FailureStatusCode
	}
	if config.InternalStatusCode > 0 {
		cfg.InternalStatusCode = config.InternalStatusCode
	}
	if config.ErrorWriter != nil {
		cfg.ErrorWriter = config.ErrorWriter
	} else {
		cfg.ErrorWriter = defaultErrorWriter
	}
	cfg.Skipper = config.Skipper

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Skipper != nil && cfg.Skipper(r) {
				next.ServeHTTP(w, r)
				return
			}

			if validator == nil {
				cfg.ErrorWriter(w, r, cfg.InternalStatusCode, ErrNilValidator)
				return
			}

			token, err := extractToken(r, cfg)
			if err != nil {
				cfg.ErrorWriter(w, r, cfg.FailureStatusCode, err)
				return
			}

			principal, err := validator.Validate(r.Context(), token)
			if err != nil {
				cfg.ErrorWriter(w, r, cfg.FailureStatusCode, err)
				return
			}

			ctx := WithPrincipal(r.Context(), principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type principalContextKeyType string

const principalContextKey principalContextKeyType = "openauth.transport.http.principal"

func WithPrincipal(ctx context.Context, principal openauth.Principal) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, principalContextKey, principal)
}

func PrincipalFromContext(ctx context.Context) (openauth.Principal, bool) {
	var zero openauth.Principal

	if ctx == nil {
		return zero, false
	}

	principal := ctx.Value(principalContextKey)
	if principal == nil {
		return zero, false
	}

	typed, ok := principal.(openauth.Principal)
	if !ok {
		return zero, false
	}

	return typed, true
}

func extractToken(r *http.Request, config MiddlewareConfig) (string, error) {
	headerName := strings.TrimSpace(config.TokenHeader)
	if headerName == "" {
		headerName = DefaultConfig().TokenHeader
	}

	headerValue := strings.TrimSpace(r.Header.Get(headerName))
	if headerValue != "" {
		if strings.EqualFold(headerName, "Authorization") {
			token, ok := parseBearerToken(headerValue)
			if !ok {
				return "", ErrInvalidAuthorizationHeader
			}
			return token, nil
		}
		return headerValue, nil
	}

	if config.CookieName != "" {
		cookie, err := r.Cookie(config.CookieName)
		if err == nil {
			value := strings.TrimSpace(cookie.Value)
			if value != "" {
				return value, nil
			}
		}
	}

	return "", ErrMissingToken
}

func parseBearerToken(value string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(value))
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}

func defaultErrorWriter(w http.ResponseWriter, _ *http.Request, statusCode int, _ error) {
	if statusCode <= 0 {
		statusCode = http.StatusUnauthorized
	}
	if statusCode == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	http.Error(w, http.StatusText(statusCode), statusCode)
}
