package openauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/porthorian/openauth/pkg/approach"
	"github.com/porthorian/openauth/pkg/authz"
	ocache "github.com/porthorian/openauth/pkg/cache"
	ocrypto "github.com/porthorian/openauth/pkg/crypto"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type AuthService struct {
	authStore            storage.AuthMaterial
	authdStore           storage.AuthdMaterial
	cacheStore           ocache.Dependencies
	logger               logr.Logger
	hasher               ocrypto.Hasher
	policyMatrix         storage.PersistencePolicyMatrix
	defaultPolicy        storage.AuthProfile
	authzRegistry        *authz.Registry
	defaultTenant        string
	approachRegistry     *approach.Registry
	defaultTokenApproach string
}

type createAuthWrite struct {
	userID       string
	materialHash string
	expiresAt    *time.Time
	metadata     map[string]string
}

var _ Authenticator = (*AuthService)(nil)
var _ AuthorizationManager = (*AuthService)(nil)
var _ AuthorizationChecker = (*AuthService)(nil)

func NewAuthService(config Config) (*AuthService, error) {
	logger := resolveLogger(config.Logger)
	if config.Hasher == nil {
		config.Hasher = ocrypto.NewPBKDF2Hasher(ocrypto.DefaultPBKDF2Options())
	}

	compiledRegistry, err := compileAuthorizationRegistry(config.Authorization)
	if err != nil {
		return nil, oerrors.Wrap(oerrors.CodeUnknown, "failed to compile authorization registry", err)
	}

	defaultTenant := strings.TrimSpace(config.Authorization.DefaultTenant)
	if defaultTenant == "" {
		defaultTenant = "default"
	}

	return &AuthService{
		authStore:            config.AuthStore,
		authdStore:           config.AuthdStore,
		cacheStore:           config.CacheStore,
		logger:               logger,
		hasher:               config.Hasher,
		policyMatrix:         config.PolicyMatrix,
		defaultPolicy:        config.DefaultPolicy,
		authzRegistry:        compiledRegistry,
		defaultTenant:        defaultTenant,
		approachRegistry:     config.ApproachRegistry,
		defaultTokenApproach: strings.TrimSpace(config.DefaultTokenApproach),
	}, nil
}

func (s *AuthService) Authorize(ctx context.Context, input AuthInput) (Principal, error) {
	if s == nil || s.authStore.Auth == nil || s.authStore.SubjectAuth == nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "auth storage is not configured")
	}
	if s.hasher == nil {
		return Principal{}, oerrors.New(oerrors.CodeUnknown, "hasher is not configured")
	}
	if s.authdStore.Role == nil || s.authdStore.Permission == nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "authorization storage is not configured")
	}
	if s.authzRegistry == nil {
		return Principal{}, oerrors.New(oerrors.CodeUnknown, "authorization registry is not configured")
	}

	subjects, err := s.authStore.SubjectAuth.ListSubjectAuthBySubject(ctx, input.UserID)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to lookup subject auth records", err)
	}
	if len(subjects) < 1 {
		return Principal{}, oerrors.New(oerrors.CodeNotFound, "user_id not found")
	}

	authIDs := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		if subject.Subject != input.UserID {
			return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "multiple auth records found for different user_ids")
		}
		authIDs = append(authIDs, subject.AuthID)
	}

	records, err := s.authStore.Auth.GetAuths(ctx, authIDs)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to retrieve auth records", err)
	}

	materialType := input.GetMaterialType()
	if materialType == "" {
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "unsupported auth input type")
	}

	var selectedRecord *storage.AuthRecord
	for _, record := range records {
		if record.MaterialType != materialType {
			continue
		}
		if record.Status == storage.StatusActive {
			selectedRecord = &record
			break
		}
	}
	if selectedRecord == nil {
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "no valid input auth record found for user_id")
	}

	if selectedRecord.ExpiresAt != nil && selectedRecord.ExpiresAt.Before(time.Now().UTC()) {
		selectedRecord.Status = storage.StatusExpired
		if err := s.authStore.Auth.PutAuth(ctx, *selectedRecord); err != nil {
			s.logger.Error(err, "failed to persist expired auth status", "auth_id", selectedRecord.ID, "subject", input.UserID)
		}
		return Principal{}, oerrors.New(oerrors.CodeCredentialsExpired, "credentials have expired")
	}

	ok, verifyErr := s.verifyInputMaterial(materialType, input.Value, selectedRecord.MaterialHash)
	if verifyErr != nil {
		return Principal{}, verifyErr
	}

	if !ok {
		s.logAuthEvent(ctx, selectedRecord.ID, input.UserID, storage.AuthLogEventFailed)
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "authentication failed")
	}

	authenticatedAt := time.Now().UTC()
	s.logAuthEvent(ctx, selectedRecord.ID, input.UserID, storage.AuthLogEventUsed)

	tenant := s.resolveTenant(input.Tenant)
	roleMask, permissionMask, err := s.resolveAuthorization(ctx, input.UserID, tenant)
	if err != nil {
		return Principal{}, err
	}

	return Principal{
		Subject:         input.UserID,
		Tenant:          tenant,
		RoleMask:        roleMask,
		PermissionMask:  permissionMask,
		AuthenticatedAt: authenticatedAt,
	}, nil
}

func (s *AuthService) CreateAuth(ctx context.Context, input CreateAuthInput) error {
	if s == nil || s.authStore.Auth == nil || s.authStore.SubjectAuth == nil {
		return oerrors.New(oerrors.CodeStorageUnavailable, "auth storage is not configured")
	}
	if s.hasher == nil {
		return oerrors.New(oerrors.CodeUnknown, "hasher is not configured")
	}

	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return err
	}

	auths, err := s.authStore.SubjectAuth.ListSubjectAuthBySubject(ctx, input.UserID)
	if err != nil {
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to lookup existing auth records for subject", err)
	}

	authIDs := make([]string, 0, len(auths))
	for _, auth := range auths {
		if auth.Subject != input.UserID {
			return oerrors.New(oerrors.CodeInvalidCredentials, "multiple auth records found for different user_ids")
		}
		authIDs = append(authIDs, auth.AuthID)
	}

	if len(authIDs) > 0 {
		records, err := s.authStore.Auth.GetAuths(ctx, authIDs)
		if err != nil {
			return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to retrieve existing auth records for subject", err)
		}
		for _, record := range records {
			if record.Status != storage.StatusActive {
				continue
			}
			if record.MaterialType != InputTypePassword.GetMaterialType() {
				continue
			}

			match, verifyErr := s.hasher.Verify(input.Value, record.MaterialHash)
			if verifyErr != nil {
				return oerrors.Wrap(oerrors.CodeUnknown, "unable to verify credentials against existing auth record", verifyErr)
			}
			if match {
				return oerrors.New(oerrors.CodeInvalidCredentials, "auth with the same value already exists for user_id")
			}
		}
	}

	materialHash, err := s.hasher.Hash(input.Value)
	if err != nil {
		return oerrors.Wrap(oerrors.CodeUnknown, "failed to hash auth value", err)
	}

	write := createAuthWrite{
		userID:       input.UserID,
		materialHash: materialHash,
		expiresAt:    input.ExpiresAt,
		metadata:     input.Metadata,
	}

	writeAuth := func(stores storage.AuthMaterial, transactional bool) error {
		request := write
		return s.createAuthWithStores(ctx, stores, transactional, request)
	}

	if txRunner, ok := s.authStore.Auth.(storage.AuthMaterialTransactor); ok {
		if err := txRunner.WithAuthMaterialTx(ctx, func(stores storage.AuthMaterial) error {
			return writeAuth(stores, true)
		}); err != nil {
			if oerrors.IsCode(err, oerrors.CodeStorageUnavailable) || oerrors.IsCode(err, oerrors.CodeInvalidCredentials) || oerrors.IsCode(err, oerrors.CodeUnknown) {
				return err
			}
			return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to run create auth transaction", err)
		}
		return nil
	}

	return writeAuth(s.authStore, false)
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (Principal, error) {
	if s == nil || s.approachRegistry == nil {
		return Principal{}, oerrors.New(oerrors.CodeNotImplemented, "token validation approach registry is not configured")
	}
	if s.defaultTokenApproach == "" {
		return Principal{}, oerrors.New(oerrors.CodeNotImplemented, "default token validation approach is not configured")
	}
	if s.authdStore.Role == nil || s.authdStore.Permission == nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "authorization storage is not configured")
	}

	result, err := s.approachRegistry.Validate(ctx, s.defaultTokenApproach, token)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeInvalidToken, "token validation failed", err)
	}

	subject := strings.TrimSpace(result.Subject)
	if subject == "" {
		return Principal{}, oerrors.New(oerrors.CodeInvalidToken, "token subject is required")
	}

	tenant := strings.TrimSpace(result.Tenant)
	if tenant == "" {
		return Principal{}, oerrors.New(oerrors.CodeInvalidToken, "token tenant claim is required")
	}

	roleMask, permissionMask, err := s.resolveAuthorization(ctx, subject, tenant)
	if err != nil {
		return Principal{}, err
	}

	return Principal{
		Subject:         subject,
		Tenant:          tenant,
		RoleMask:        roleMask,
		PermissionMask:  permissionMask,
		Claims:          cloneClaims(result.Claims),
		AuthenticatedAt: time.Now().UTC(),
	}, nil
}

func (s *AuthService) SetSubjectRoles(ctx context.Context, input SetSubjectRolesInput) error {
	if s == nil || s.authdStore.Role == nil {
		return oerrors.New(oerrors.CodeStorageUnavailable, "role storage is not configured")
	}
	if s.authzRegistry == nil {
		return oerrors.New(oerrors.CodeUnknown, "authorization registry is not configured")
	}

	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return mapInputValidationError(err)
	}
	if err := s.authzRegistry.ValidateRoleKeys(input.RoleKeys); err != nil {
		return s.mapAuthzError(err)
	}

	tenant := s.resolveTenant(input.Tenant)
	if err := s.authdStore.Role.ReplaceSubjectRoles(ctx, input.Subject, tenant, input.RoleKeys); err != nil {
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to replace subject roles", err)
	}
	return nil
}

func (s *AuthService) SetSubjectPermissionOverrides(ctx context.Context, input SetSubjectPermissionOverridesInput) error {
	if s == nil || s.authdStore.Permission == nil {
		return oerrors.New(oerrors.CodeStorageUnavailable, "permission storage is not configured")
	}
	if s.authzRegistry == nil {
		return oerrors.New(oerrors.CodeUnknown, "authorization registry is not configured")
	}

	input = input.Normalize()
	if err := input.Validate(); err != nil {
		return mapInputValidationError(err)
	}
	if _, err := s.authzRegistry.PermissionMaskForKeys(input.GrantKeys); err != nil {
		return s.mapAuthzError(err)
	}
	if _, err := s.authzRegistry.PermissionMaskForKeys(input.DenyKeys); err != nil {
		return s.mapAuthzError(err)
	}

	denySet := make(map[string]struct{}, len(input.DenyKeys))
	for _, key := range input.DenyKeys {
		denySet[key] = struct{}{}
	}

	overrides := make([]storage.SubjectPermissionOverrideRecord, 0, len(input.GrantKeys)+len(input.DenyKeys))
	for _, key := range input.GrantKeys {
		if _, denied := denySet[key]; denied {
			continue
		}
		overrides = append(overrides, storage.SubjectPermissionOverrideRecord{
			Subject:       input.Subject,
			Tenant:        s.resolveTenant(input.Tenant),
			PermissionKey: key,
			Effect:        storage.PermissionEffectGrant,
		})
	}
	for _, key := range input.DenyKeys {
		overrides = append(overrides, storage.SubjectPermissionOverrideRecord{
			Subject:       input.Subject,
			Tenant:        s.resolveTenant(input.Tenant),
			PermissionKey: key,
			Effect:        storage.PermissionEffectDeny,
		})
	}

	if err := s.authdStore.Permission.ReplaceSubjectPermissionOverrides(ctx, input.Subject, s.resolveTenant(input.Tenant), overrides); err != nil {
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to replace subject permission overrides", err)
	}
	return nil
}

func (s *AuthService) HasAllRoles(principal Principal, roleKeys ...string) (bool, error) {
	required, err := s.requiredRoleMask(roleKeys)
	if err != nil {
		return false, err
	}
	return authz.HasAllRoles(principal.RoleMask, required), nil
}

func (s *AuthService) HasAnyRoles(principal Principal, roleKeys ...string) (bool, error) {
	required, err := s.requiredRoleMask(roleKeys)
	if err != nil {
		return false, err
	}
	return authz.HasAnyRoles(principal.RoleMask, required), nil
}

func (s *AuthService) RequireAllRoles(principal Principal, roleKeys ...string) error {
	ok, err := s.HasAllRoles(principal, roleKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required roles are missing")
	}
	return nil
}

func (s *AuthService) RequireAnyRoles(principal Principal, roleKeys ...string) error {
	ok, err := s.HasAnyRoles(principal, roleKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required roles are missing")
	}
	return nil
}

func (s *AuthService) HasAllPermissions(principal Principal, permissionKeys ...string) (bool, error) {
	required, err := s.requiredPermissionMask(permissionKeys)
	if err != nil {
		return false, err
	}
	return authz.HasAllPermissions(principal.PermissionMask, required), nil
}

func (s *AuthService) HasAnyPermissions(principal Principal, permissionKeys ...string) (bool, error) {
	required, err := s.requiredPermissionMask(permissionKeys)
	if err != nil {
		return false, err
	}
	return authz.HasAnyPermissions(principal.PermissionMask, required), nil
}

func (s *AuthService) RequireAllPermissions(principal Principal, permissionKeys ...string) error {
	ok, err := s.HasAllPermissions(principal, permissionKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required permissions are missing")
	}
	return nil
}

func (s *AuthService) RequireAnyPermissions(principal Principal, permissionKeys ...string) error {
	ok, err := s.HasAnyPermissions(principal, permissionKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required permissions are missing")
	}
	return nil
}

func (s *AuthService) verifyInputMaterial(materialType storage.AuthMaterialType, inputValue string, materialHash string) (bool, error) {
	switch materialType {
	case storage.AuthMaterialTypePassword:
		ok, verifyErr := s.hasher.Verify(inputValue, materialHash)
		if verifyErr != nil {
			return false, oerrors.Wrap(oerrors.CodeInvalidCredentials, "unable to verify credentials", verifyErr)
		}
		return ok, nil
	default:
		return false, oerrors.New(oerrors.CodeNotImplemented, "auth input type is not implemented")
	}
}

func (s *AuthService) resolveAuthorization(ctx context.Context, subject string, tenant string) (RoleMask, PermissionMask, error) {
	if s.authzRegistry == nil {
		return RoleMask{}, PermissionMask{}, oerrors.New(oerrors.CodeUnknown, "authorization registry is not configured")
	}
	if s.authdStore.Role == nil || s.authdStore.Permission == nil {
		return RoleMask{}, PermissionMask{}, oerrors.New(oerrors.CodeStorageUnavailable, "authorization storage is not configured")
	}

	roleRecords, err := s.authdStore.Role.ListSubjectRoles(ctx, subject, tenant)
	if err != nil {
		return RoleMask{}, PermissionMask{}, oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to list subject roles", err)
	}
	overrideRecords, err := s.authdStore.Permission.ListSubjectPermissionOverrides(ctx, subject, tenant)
	if err != nil {
		return RoleMask{}, PermissionMask{}, oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to list permission overrides", err)
	}

	roleKeys := make([]string, 0, len(roleRecords))
	for _, role := range roleRecords {
		roleKeys = append(roleKeys, role.RoleKey)
	}

	grantKeys := make([]string, 0, len(overrideRecords))
	denyKeys := make([]string, 0, len(overrideRecords))
	for _, override := range overrideRecords {
		switch override.Effect {
		case storage.PermissionEffectGrant:
			grantKeys = append(grantKeys, override.PermissionKey)
		case storage.PermissionEffectDeny:
			denyKeys = append(denyKeys, override.PermissionKey)
		default:
			return RoleMask{}, PermissionMask{}, oerrors.New(oerrors.CodePermission, "unknown permission effect")
		}
	}

	roleMask, permissionMask, err := s.authzRegistry.Resolve(roleKeys, grantKeys, denyKeys)
	if err != nil {
		return RoleMask{}, PermissionMask{}, s.mapAuthzError(err)
	}
	return roleMask, permissionMask, nil
}

func (s *AuthService) requiredRoleMask(roleKeys []string) (RoleMask, error) {
	if s == nil || s.authzRegistry == nil {
		return RoleMask{}, oerrors.New(oerrors.CodeUnknown, "authorization registry is not configured")
	}
	required, err := s.authzRegistry.RoleMaskForKeys(roleKeys)
	if err != nil {
		return RoleMask{}, s.mapAuthzError(err)
	}
	return required, nil
}

func (s *AuthService) requiredPermissionMask(permissionKeys []string) (PermissionMask, error) {
	if s == nil || s.authzRegistry == nil {
		return PermissionMask{}, oerrors.New(oerrors.CodeUnknown, "authorization registry is not configured")
	}
	required, err := s.authzRegistry.PermissionMaskForKeys(permissionKeys)
	if err != nil {
		return PermissionMask{}, s.mapAuthzError(err)
	}
	return required, nil
}

func (s *AuthService) mapAuthzError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, authz.ErrUnknownRoleKey) {
		return oerrors.Wrap(oerrors.CodeRole, "invalid role assignment", err)
	}
	if errors.Is(err, authz.ErrUnknownPermissionKey) {
		return oerrors.Wrap(oerrors.CodePermission, "invalid permission assignment", err)
	}
	if errors.Is(err, authz.ErrRoleInheritanceCycle) {
		return oerrors.Wrap(oerrors.CodeRole, "invalid role inheritance configuration", err)
	}
	return oerrors.Wrap(oerrors.CodeUnknown, "authorization evaluation failed", err)
}

func (s *AuthService) resolveTenant(rawTenant string) string {
	tenant := strings.TrimSpace(rawTenant)
	if tenant != "" {
		return tenant
	}
	if strings.TrimSpace(s.defaultTenant) != "" {
		return s.defaultTenant
	}
	return "default"
}

func (s *AuthService) logAuthEvent(ctx context.Context, authID string, subject string, event storage.AuthLogEvent) {
	if s.authStore.AuthLog == nil {
		return
	}
	now := time.Now().UTC()
	if err := s.authStore.AuthLog.PutAuthLog(ctx, storage.AuthLogRecord{
		ID:         uuid.NewString(),
		DateAdded:  now,
		AuthID:     authID,
		Subject:    subject,
		Event:      event,
		OccurredAt: now,
	}); err != nil {
		s.logger.Error(err, "failed to write auth log record", "auth_id", authID, "subject", subject, "event", event)
	}
}

func (s *AuthService) createAuthWithStores(ctx context.Context, stores storage.AuthMaterial, transactional bool, request createAuthWrite) error {
	if stores.Auth == nil || stores.SubjectAuth == nil {
		return oerrors.New(oerrors.CodeStorageUnavailable, "auth storage is not configured")
	}

	now := time.Now().UTC()
	authID := uuid.NewString()

	if err := stores.Auth.PutAuth(ctx, storage.AuthRecord{
		ID:           authID,
		Status:       storage.StatusActive,
		DateAdded:    now,
		MaterialType: storage.AuthMaterialTypePassword,
		MaterialHash: request.materialHash,
		ExpiresAt:    request.expiresAt,
		Metadata:     request.metadata,
	}); err != nil {
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to create auth record", err)
	}

	if err := stores.SubjectAuth.PutSubjectAuth(ctx, storage.SubjectAuthRecord{
		ID:        uuid.NewString(),
		DateAdded: now,
		Subject:   request.userID,
		AuthID:    authID,
	}); err != nil {
		if !transactional {
			if deleteErr := stores.Auth.DeleteAuth(ctx, authID); deleteErr != nil {
				s.logger.Error(deleteErr, "failed to cleanup auth record after subject link failure", "auth_id", authID, "subject", request.userID)
			}
		}
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to link auth record to subject", err)
	}

	if stores.AuthLog != nil {
		if err := stores.AuthLog.PutAuthLog(ctx, storage.AuthLogRecord{
			ID:         uuid.NewString(),
			DateAdded:  now,
			AuthID:     authID,
			Subject:    request.userID,
			Event:      storage.AuthLogEventCreated,
			OccurredAt: now,
		}); err != nil {
			s.logger.Error(err, "failed to write create auth log record", "auth_id", authID, "subject", request.userID)
		}
	}

	return nil
}

func cloneClaims(input map[string]any) Claims {
	if len(input) == 0 {
		return Claims{}
	}
	cloned := make(Claims, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
