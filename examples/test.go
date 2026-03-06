package main

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/porthorian/openauth"
	"github.com/porthorian/openauth/pkg/approach"
	"github.com/porthorian/openauth/pkg/session"
	sessionjwt "github.com/porthorian/openauth/pkg/session/jwt"
	httptransport "github.com/porthorian/openauth/pkg/transport/http"
)

func main() {
	ctx := context.Background()
	dsn := os.Getenv("OPENAUTH_POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("OPENAUTH_POSTGRES_DSN is required")
	}

	client, err := openauth.NewDefault(openauth.Config{
		Logger: logr.Discard(),
		Authorization: openauth.AuthorizationConfig{
			DefaultTenant: "example-tenant",
			Registry: openauth.AuthorizationRegistry{
				Permissions: []openauth.PermissionDefinition{
					{Key: "perm.read", Bit: 0},
					{Key: "perm.write", Bit: 1},
				},
				Roles: []openauth.RoleDefinition{
					{Key: "viewer", Bit: 0, Permissions: []string{"perm.read"}},
					{Key: "editor", Bit: 1, Permissions: []string{"perm.read", "perm.write"}},
				},
			},
		},
		Runtime: openauth.RuntimeConfig{
			Storage: openauth.StorageConfig{
				Backend: openauth.StorageBackendPostgres,
				Postgres: openauth.PostgresConfig{
					DriverName:      "pgx",
					DSN:             dsn,
					MaxOpenConns:    10,
					MaxIdleConns:    5,
					ConnMaxLifetime: 30 * time.Minute,
					ConnMaxIdleTime: 5 * time.Minute,
					PingTimeout:     5 * time.Second,
				},
			},
			Cache: openauth.CacheConfig{
				Backend: openauth.CacheBackendNone,
			},
			KeyStore: openauth.KeyStoreConfig{
				Backend: openauth.KeyStoreBackendNone,
			},
		},
	})
	if err != nil {
		log.Fatalf("client init error: %v", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Printf("client close error: %v", closeErr)
		}
	}()

	jwtManager, err := sessionjwt.NewManager(sessionjwt.Config{
		SigningKey: session.Key{
			ID:        "example-v1",
			Algorithm: "HS256",
			Material:  []byte("replace-this-example-secret"),
		},
		Issuer:    "openauth.example",
		Audience:  []string{"example-api"},
		ClockSkew: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("jwt manager init error: %v", err)
	}

	registeredUserID := uuid.NewString()
	registeredPassword := "correct-horse-battery-staple"
	err = client.CreateAuth(ctx, openauth.CreateAuthInput{
		UserID: registeredUserID,
		Value:  registeredPassword,
	})
	if err != nil {
		log.Fatalf("create auth error: %v", err)
	}

	err = client.SetSubjectRoles(ctx, openauth.SetSubjectRolesInput{
		Subject:  registeredUserID,
		Tenant:   "example-tenant",
		RoleKeys: []string{"viewer"},
	})
	if err != nil {
		log.Fatalf("set subject roles error: %v", err)
	}
	log.Printf("registered user=%s with password auth", registeredUserID)

	incomingUserID := registeredUserID
	incomingPassword := "correct-horse-battery-staple"
	principal, err := client.Authorize(ctx, openauth.AuthInput{
		UserID: incomingUserID,
		Type:   openauth.InputTypePassword,
		Value:  incomingPassword,
	})
	if err != nil {
		log.Printf("authorization failed for user=%s", incomingUserID)
		return
	}

	hasReadPermission, err := client.HasAllPermissions(principal, "perm.read")
	if err != nil {
		log.Fatalf("permission check failed: %v", err)
	}
	hasViewerRole, err := client.HasAnyRoles(principal, "viewer")
	if err != nil {
		log.Fatalf("role check failed: %v", err)
	}
	log.Printf("authorization checks: subject=%s has_read=%t has_viewer_role=%t", principal.Subject, hasReadPermission, hasViewerRole)

	token, err := jwtManager.IssueToken(ctx, principal.Subject, session.Claims{
		"tenant": principal.Tenant,
		"role":   "admin",
	}, 15*time.Minute)
	if err != nil {
		log.Fatalf("issue token error: %v", err)
	}
	log.Printf("authorization successful for user=%s; jwt issued (len=%d)", principal.Subject, len(token))

	directJWT, err := approach.NewDirectJWTHandler(approach.DirectJWTConfig{
		Validator: jwtManager,
	})
	if err != nil {
		log.Fatalf("direct jwt handler init error: %v", err)
	}

	registry, err := approach.NewRegistry(directJWT)
	if err != nil {
		log.Fatalf("approach registry init error: %v", err)
	}

	approachResult, err := registry.Validate(ctx, approach.NameDirectJWT, token)
	if err != nil {
		log.Fatalf("approach validation error: %v", err)
	}

	sessionID, err := jwtManager.IssueSession(ctx, approachResult.Subject, 24*time.Hour)
	if err != nil {
		log.Fatalf("issue session error: %v", err)
	}

	sessionValid, err := jwtManager.ValidateSession(ctx, sessionID)
	if err != nil {
		log.Fatalf("validate session error: %v", err)
	}
	if !sessionValid {
		log.Fatalf("session was issued but is not valid")
	}

	protected := httptransport.RequireAnyRoleOrPermission(client, []string{"admin"}, []string{"perm.read"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req = req.WithContext(httptransport.WithPrincipal(req.Context(), principal))
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		log.Fatalf("protected middleware check failed with status=%d", rr.Code)
	}
	log.Printf("http authz middleware allowed subject=%s status=%d", principal.Subject, rr.Code)

	log.Printf(
		"principal subject=%s tenant=%s authenticated_at=%s approach=%s approach_subject=%s approach_tenant=%s approach_expires_at=%s",
		principal.Subject,
		principal.Tenant,
		principal.AuthenticatedAt.Format(time.RFC3339),
		directJWT.Name(),
		approachResult.Subject,
		approachResult.Tenant,
		approachResult.ExpiresAt.Format(time.RFC3339),
	)
	log.Printf("issued session for subject=%s (len=%d)", approachResult.Subject, len(sessionID))
}
