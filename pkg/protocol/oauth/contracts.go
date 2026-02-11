package oauth

import (
	"context"
	"time"
)

type IntrospectionResponse struct {
	Active    bool
	Subject   string
	Audience  []string
	Scope     []string
	ExpiresAt time.Time
	Claims    map[string]any
}

type Introspector interface {
	Introspect(ctx context.Context, token string) (IntrospectionResponse, error)
}

type DiscoveryDocument struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
}

type DiscoveryProvider interface {
	Discover(ctx context.Context, issuer string) (DiscoveryDocument, error)
}

type JWKSResolver interface {
	ResolveJWKS(ctx context.Context, jwksURI string) (map[string]any, error)
}

type ClaimMapper interface {
	MapClaims(ctx context.Context, claims map[string]any) (map[string]any, error)
}
