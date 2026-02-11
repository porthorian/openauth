package storage

import (
	"context"
	"time"
)

type AuthMaterialType string

const (
	AuthMaterialTypePassword     AuthMaterialType = "password"
	AuthMaterialTypeAccessToken  AuthMaterialType = "access_token"
	AuthMaterialTypeRefreshToken AuthMaterialType = "refresh_token"
	AuthMaterialTypeAPIKey       AuthMaterialType = "api_key"
	AuthMaterialTypeClientSecret AuthMaterialType = "client_secret"
)

type TokenFormat string

const (
	TokenFormatOpaque TokenFormat = "opaque"
	TokenFormatJWT    TokenFormat = "jwt"
)

type TokenUse string

const (
	TokenUseAccess  TokenUse = "access"
	TokenUseRefresh TokenUse = "refresh"
	TokenUseID      TokenUse = "id"
)

type AuthRecord struct {
	ID           string
	DateAdded    time.Time
	DateModified *time.Time
	MaterialType AuthMaterialType
	MaterialHash string
	TokenFormat  *TokenFormat
	TokenUse     *TokenUse
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	Metadata     map[string]string
}

type SubjectAuthRecord struct {
	ID           string
	DateAdded    time.Time
	DateModified *time.Time
	Subject      string
	AuthID       string
}

type SessionRecord struct {
	ID        string
	AuthID    string
	Subject   string
	Tenant    string
	ExpiresAt time.Time
	Metadata  map[string]string
}

type RoleRecord struct {
	Subject  string
	Tenant   string
	RoleMask uint64
}

type PermissionRecord struct {
	Subject        string
	Tenant         string
	PermissionMask uint64
}

type AuthLogEvent string

const (
	AuthLogEventUsed      AuthLogEvent = "used"
	AuthLogEventValidated AuthLogEvent = "validated"
	AuthLogEventRevoked   AuthLogEvent = "revoked"
)

type AuthLogRecord struct {
	ID         string
	DateAdded  time.Time
	AuthID     string
	Subject    string
	Event      AuthLogEvent
	OccurredAt time.Time
	Metadata   map[string]string
}

type AuthStore interface {
	PutAuth(ctx context.Context, record AuthRecord) error
	GetAuth(ctx context.Context, id string) (AuthRecord, error)
	GetAuthByMaterialHash(ctx context.Context, materialType AuthMaterialType, materialHash string) (AuthRecord, error)
	DeleteAuth(ctx context.Context, id string) error
}

type SubjectAuthStore interface {
	PutSubjectAuth(ctx context.Context, record SubjectAuthRecord) error
	ListSubjectAuthBySubject(ctx context.Context, subject string) ([]SubjectAuthRecord, error)
	ListSubjectAuthByAuthID(ctx context.Context, authID string) ([]SubjectAuthRecord, error)
	DeleteSubjectAuth(ctx context.Context, id string) error
}

type SessionStore interface {
	PutSession(ctx context.Context, record SessionRecord) error
	GetSession(ctx context.Context, id string) (SessionRecord, error)
	DeleteSession(ctx context.Context, id string) error
}

type RoleStore interface {
	PutRole(ctx context.Context, record RoleRecord) error
	GetRole(ctx context.Context, subject string, tenant string) (RoleRecord, error)
	DeleteRole(ctx context.Context, subject string, tenant string) error
}

type PermissionStore interface {
	PutPermission(ctx context.Context, record PermissionRecord) error
	GetPermission(ctx context.Context, subject string, tenant string) (PermissionRecord, error)
	DeletePermission(ctx context.Context, subject string, tenant string) error
}

type AuthLogStore interface {
	PutAuthLog(ctx context.Context, record AuthLogRecord) error
	ListAuthLogsByAuthID(ctx context.Context, authID string) ([]AuthLogRecord, error)
	ListAuthLogsBySubject(ctx context.Context, subject string) ([]AuthLogRecord, error)
}

type Store interface {
	AuthStore
	SubjectAuthStore
	SessionStore
	RoleStore
	PermissionStore
	AuthLogStore
}
