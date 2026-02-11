package httptransport

import (
	"context"
	"net/http"
)

type TokenValidator interface {
	Validate(ctx context.Context, token string) (any, error)
}

type MiddlewareConfig struct {
	TokenHeader       string
	CookieName        string
	FailureStatusCode int
}

func DefaultConfig() MiddlewareConfig {
	return MiddlewareConfig{
		TokenHeader:       "Authorization",
		CookieName:        "",
		FailureStatusCode: http.StatusUnauthorized,
	}
}

func Middleware(_ TokenValidator, _ MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}
