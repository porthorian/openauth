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

type PermissionChecker interface {
	HasAllPermissions(principal openauth.Principal, permissionKeys ...string) (bool, error)
	HasAnyPermissions(principal openauth.Principal, permissionKeys ...string) (bool, error)
}

type RoleChecker interface {
	HasAllRoles(principal openauth.Principal, roleKeys ...string) (bool, error)
	HasAnyRoles(principal openauth.Principal, roleKeys ...string) (bool, error)
}

type AuthorizationChecker interface {
	PermissionChecker
	RoleChecker
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

func RequireAllPermissions(checker PermissionChecker, permissionKeys ...string) func(http.Handler) http.Handler {
	return requirePermissions(checker, true, permissionKeys...)
}

func RequireAnyPermissions(checker PermissionChecker, permissionKeys ...string) func(http.Handler) http.Handler {
	return requirePermissions(checker, false, permissionKeys...)
}

func RequireAllRoles(checker RoleChecker, roleKeys ...string) func(http.Handler) http.Handler {
	return requireRoles(checker, true, roleKeys...)
}

func RequireAnyRoles(checker RoleChecker, roleKeys ...string) func(http.Handler) http.Handler {
	return requireRoles(checker, false, roleKeys...)
}

func RequireAnyRoleOrPermission(checker AuthorizationChecker, roleKeys []string, permissionKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				defaultErrorWriter(w, r, http.StatusInternalServerError, errors.New("http transport: authorization checker is nil"))
				return
			}

			if len(roleKeys) == 0 && len(permissionKeys) == 0 {
				defaultErrorWriter(w, r, http.StatusInternalServerError, errors.New("http transport: role and permission keys are empty"))
				return
			}

			handleGuardEvaluation(
				w,
				r,
				errors.New("http transport: required roles or permissions are missing"),
				func(principal openauth.Principal) (bool, error) {
					if len(roleKeys) > 0 {
						roleAllowed, err := checker.HasAnyRoles(principal, roleKeys...)
						if err != nil {
							return false, err
						}
						if roleAllowed {
							return true, nil
						}
					}
					if len(permissionKeys) > 0 {
						return checker.HasAnyPermissions(principal, permissionKeys...)
					}
					return false, nil
				},
				next,
			)
		})
	}
}

func requirePermissions(checker PermissionChecker, requireAll bool, permissionKeys ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				defaultErrorWriter(w, r, http.StatusInternalServerError, errors.New("http transport: permission checker is nil"))
				return
			}

			handleGuardEvaluation(
				w,
				r,
				errors.New("http transport: required permissions are missing"),
				func(principal openauth.Principal) (bool, error) {
					if requireAll {
						return checker.HasAllPermissions(principal, permissionKeys...)
					}
					return checker.HasAnyPermissions(principal, permissionKeys...)
				},
				next,
			)
		})
	}
}

func requireRoles(checker RoleChecker, requireAll bool, roleKeys ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				defaultErrorWriter(w, r, http.StatusInternalServerError, errors.New("http transport: role checker is nil"))
				return
			}

			handleGuardEvaluation(
				w,
				r,
				errors.New("http transport: required roles are missing"),
				func(principal openauth.Principal) (bool, error) {
					if requireAll {
						return checker.HasAllRoles(principal, roleKeys...)
					}
					return checker.HasAnyRoles(principal, roleKeys...)
				},
				next,
			)
		})
	}
}

func handleGuardEvaluation(w http.ResponseWriter, r *http.Request, forbiddenErr error, evaluate func(principal openauth.Principal) (bool, error), next http.Handler) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok {
		defaultErrorWriter(w, r, http.StatusUnauthorized, errors.New("http transport: principal is missing from context"))
		return
	}

	allowed, err := evaluate(principal)
	if err != nil {
		defaultErrorWriter(w, r, http.StatusInternalServerError, err)
		return
	}
	if !allowed {
		defaultErrorWriter(w, r, http.StatusForbidden, forbiddenErr)
		return
	}

	next.ServeHTTP(w, r)
}
