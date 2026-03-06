package openauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/porthorian/openauth/pkg/approach"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type staticHasher struct{}

func (h staticHasher) Hash(password string) (string, error) {
	return password, nil
}

func (h staticHasher) Verify(password string, encodedHash string) (bool, error) {
	return password == encodedHash, nil
}

type memoryAuthStore struct {
	records map[string]storage.AuthRecord
}

func (s *memoryAuthStore) PutAuth(ctx context.Context, record storage.AuthRecord) error {
	_ = ctx
	if s.records == nil {
		s.records = map[string]storage.AuthRecord{}
	}
	s.records[record.ID] = record
	return nil
}

func (s *memoryAuthStore) GetAuth(ctx context.Context, id string) (storage.AuthRecord, error) {
	_ = ctx
	record, ok := s.records[id]
	if !ok {
		return storage.AuthRecord{}, errors.New("not found")
	}
	return record, nil
}

func (s *memoryAuthStore) GetAuths(ctx context.Context, ids []string) ([]storage.AuthRecord, error) {
	_ = ctx
	records := make([]storage.AuthRecord, 0, len(ids))
	for _, id := range ids {
		record, ok := s.records[id]
		if !ok {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

func (s *memoryAuthStore) DeleteAuth(ctx context.Context, id string) error {
	_ = ctx
	delete(s.records, id)
	return nil
}

type memorySubjectAuthStore struct {
	bySubject map[string][]storage.SubjectAuthRecord
	byAuthID  map[string][]storage.SubjectAuthRecord
}

func (s *memorySubjectAuthStore) PutSubjectAuth(ctx context.Context, record storage.SubjectAuthRecord) error {
	_ = ctx
	if s.bySubject == nil {
		s.bySubject = map[string][]storage.SubjectAuthRecord{}
	}
	if s.byAuthID == nil {
		s.byAuthID = map[string][]storage.SubjectAuthRecord{}
	}
	s.bySubject[record.Subject] = append(s.bySubject[record.Subject], record)
	s.byAuthID[record.AuthID] = append(s.byAuthID[record.AuthID], record)
	return nil
}

func (s *memorySubjectAuthStore) ListSubjectAuthBySubject(ctx context.Context, subject string) ([]storage.SubjectAuthRecord, error) {
	_ = ctx
	return append([]storage.SubjectAuthRecord(nil), s.bySubject[subject]...), nil
}

func (s *memorySubjectAuthStore) ListSubjectAuthByAuthID(ctx context.Context, authID string) ([]storage.SubjectAuthRecord, error) {
	_ = ctx
	return append([]storage.SubjectAuthRecord(nil), s.byAuthID[authID]...), nil
}

func (s *memorySubjectAuthStore) DeleteSubjectAuth(ctx context.Context, id string) error {
	_ = ctx
	_ = id
	return nil
}

type noopAuthLogStore struct{}

func (s noopAuthLogStore) PutAuthLog(ctx context.Context, record storage.AuthLogRecord) error {
	_ = ctx
	_ = record
	return nil
}

func (s noopAuthLogStore) ListAuthLogsByAuthID(ctx context.Context, authID string) ([]storage.AuthLogRecord, error) {
	_ = ctx
	_ = authID
	return nil, nil
}

func (s noopAuthLogStore) ListAuthLogsBySubject(ctx context.Context, subject string) ([]storage.AuthLogRecord, error) {
	_ = ctx
	_ = subject
	return nil, nil
}

type memoryRoleStore struct {
	data map[string][]string
}

func (s *memoryRoleStore) ReplaceSubjectRoles(ctx context.Context, subject string, tenant string, roleKeys []string) error {
	_ = ctx
	if s.data == nil {
		s.data = map[string][]string{}
	}
	key := subject + "|" + tenant
	s.data[key] = append([]string(nil), roleKeys...)
	return nil
}

func (s *memoryRoleStore) ListSubjectRoles(ctx context.Context, subject string, tenant string) ([]storage.SubjectRoleRecord, error) {
	_ = ctx
	key := subject + "|" + tenant
	roleKeys := s.data[key]
	records := make([]storage.SubjectRoleRecord, 0, len(roleKeys))
	for _, roleKey := range roleKeys {
		records = append(records, storage.SubjectRoleRecord{
			Subject: subject,
			Tenant:  tenant,
			RoleKey: roleKey,
		})
	}
	return records, nil
}

type memoryPermissionStore struct {
	data map[string][]storage.SubjectPermissionOverrideRecord
}

func (s *memoryPermissionStore) ReplaceSubjectPermissionOverrides(ctx context.Context, subject string, tenant string, overrides []storage.SubjectPermissionOverrideRecord) error {
	_ = ctx
	if s.data == nil {
		s.data = map[string][]storage.SubjectPermissionOverrideRecord{}
	}
	key := subject + "|" + tenant
	cloned := make([]storage.SubjectPermissionOverrideRecord, len(overrides))
	copy(cloned, overrides)
	s.data[key] = cloned
	return nil
}

func (s *memoryPermissionStore) ListSubjectPermissionOverrides(ctx context.Context, subject string, tenant string) ([]storage.SubjectPermissionOverrideRecord, error) {
	_ = ctx
	key := subject + "|" + tenant
	records := make([]storage.SubjectPermissionOverrideRecord, len(s.data[key]))
	copy(records, s.data[key])
	return records, nil
}

type staticApproachHandler struct {
	name   string
	result approach.Result
	err    error
}

func (h staticApproachHandler) Name() string {
	return h.name
}

func (h staticApproachHandler) Validate(ctx context.Context, token string) (approach.Result, error) {
	_ = ctx
	_ = token
	if h.err != nil {
		return approach.Result{}, h.err
	}
	return h.result, nil
}

func TestAuthorizeResolvesMasksWithDefaultTenant(t *testing.T) {
	authStore := &memoryAuthStore{
		records: map[string]storage.AuthRecord{
			"auth-1": {
				ID:           "auth-1",
				Status:       storage.StatusActive,
				MaterialType: storage.AuthMaterialTypePassword,
				MaterialHash: "pass-123",
				DateAdded:    time.Now().UTC(),
			},
		},
	}
	subjectStore := &memorySubjectAuthStore{
		bySubject: map[string][]storage.SubjectAuthRecord{
			"user-1": {
				{
					ID:      "link-1",
					Subject: "user-1",
					AuthID:  "auth-1",
				},
			},
		},
	}
	roleStore := &memoryRoleStore{
		data: map[string][]string{
			"user-1|tenant-default": {"viewer"},
		},
	}
	permissionStore := &memoryPermissionStore{
		data: map[string][]storage.SubjectPermissionOverrideRecord{
			"user-1|tenant-default": {
				{
					Subject:       "user-1",
					Tenant:        "tenant-default",
					PermissionKey: "write",
					Effect:        storage.PermissionEffectGrant,
				},
			},
		},
	}

	service, err := NewAuthService(Config{
		AuthStore: storage.AuthMaterial{
			Auth:        authStore,
			SubjectAuth: subjectStore,
			AuthLog:     noopAuthLogStore{},
		},
		AuthdStore: storage.AuthdMaterial{
			Role:       roleStore,
			Permission: permissionStore,
		},
		Hasher: staticHasher{},
		Authorization: AuthorizationConfig{
			DefaultTenant: "tenant-default",
			Registry: AuthorizationRegistry{
				Permissions: []PermissionDefinition{
					{Key: "read", Bit: 0},
					{Key: "write", Bit: 1},
				},
				Roles: []RoleDefinition{
					{Key: "viewer", Bit: 0, Permissions: []string{"read"}},
					{Key: "admin", Bit: 1, Permissions: []string{"read", "write"}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthService returned error: %v", err)
	}

	principal, err := service.Authorize(context.Background(), AuthInput{
		UserID: "user-1",
		Type:   InputTypePassword,
		Value:  "pass-123",
	})
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if principal.Tenant != "tenant-default" {
		t.Fatalf("expected tenant-default, got %q", principal.Tenant)
	}

	all, err := service.HasAllPermissions(principal, "read", "write")
	if err != nil {
		t.Fatalf("HasAllPermissions returned error: %v", err)
	}
	if !all {
		t.Fatalf("expected read/write permissions")
	}

	anyRole, err := service.HasAnyRoles(principal, "viewer")
	if err != nil {
		t.Fatalf("HasAnyRoles returned error: %v", err)
	}
	if !anyRole {
		t.Fatalf("expected viewer role to be present")
	}

	err = service.RequireAnyRoles(principal, "admin")
	if err == nil {
		t.Fatalf("expected missing role error")
	}
	if !oerrors.IsCode(err, oerrors.CodePermissionDenied) {
		t.Fatalf("expected permission denied code for missing role, got %v", err)
	}

	err = service.RequireAllRoles(principal, "viewer", "admin")
	if err == nil {
		t.Fatalf("expected missing role error")
	}
	if !oerrors.IsCode(err, oerrors.CodePermissionDenied) {
		t.Fatalf("expected permission denied code for missing role set, got %v", err)
	}

	_, err = service.HasAnyRoles(principal, "missing-role")
	if err == nil {
		t.Fatalf("expected invalid role key error")
	}
	if !oerrors.IsCode(err, oerrors.CodeRole) {
		t.Fatalf("expected role error code, got %v", err)
	}
}

func TestValidateTokenRequiresTenantClaim(t *testing.T) {
	handler := staticApproachHandler{
		name: "direct_jwt",
		result: approach.Result{
			Subject: "user-1",
			Tenant:  "",
			Claims:  map[string]any{"sub": "user-1"},
		},
	}
	registry, err := approach.NewRegistry(handler)
	if err != nil {
		t.Fatalf("approach.NewRegistry returned error: %v", err)
	}

	service, err := NewAuthService(Config{
		AuthdStore: storage.AuthdMaterial{
			Role:       &memoryRoleStore{},
			Permission: &memoryPermissionStore{},
		},
		Authorization: AuthorizationConfig{
			Registry: AuthorizationRegistry{
				Permissions: []PermissionDefinition{{Key: "read", Bit: 0}},
				Roles:       []RoleDefinition{{Key: "viewer", Bit: 0, Permissions: []string{"read"}}},
			},
		},
		ApproachRegistry:     registry,
		DefaultTokenApproach: "direct_jwt",
	})
	if err != nil {
		t.Fatalf("NewAuthService returned error: %v", err)
	}

	_, err = service.ValidateToken(context.Background(), "token-1")
	if err == nil {
		t.Fatalf("expected token validation error")
	}
	if !oerrors.IsCode(err, oerrors.CodeInvalidToken) {
		t.Fatalf("expected invalid token code, got %v", err)
	}
}

func TestSetSubjectRolesRejectsUnknownRole(t *testing.T) {
	service, err := NewAuthService(Config{
		AuthdStore: storage.AuthdMaterial{
			Role:       &memoryRoleStore{},
			Permission: &memoryPermissionStore{},
		},
		Authorization: AuthorizationConfig{
			Registry: AuthorizationRegistry{
				Permissions: []PermissionDefinition{{Key: "read", Bit: 0}},
				Roles:       []RoleDefinition{{Key: "viewer", Bit: 0, Permissions: []string{"read"}}},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthService returned error: %v", err)
	}

	err = service.SetSubjectRoles(context.Background(), SetSubjectRolesInput{
		Subject:  "user-1",
		Tenant:   "tenant-a",
		RoleKeys: []string{"missing-role"},
	})
	if err == nil {
		t.Fatalf("expected role validation error")
	}
	if !oerrors.IsCode(err, oerrors.CodeRole) {
		t.Fatalf("expected role error code, got %v", err)
	}
}
