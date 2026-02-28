package openauth

import (
	"context"
	"errors"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	ocache "github.com/porthorian/openauth/pkg/cache"
	ocrypto "github.com/porthorian/openauth/pkg/crypto"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type AuthService struct {
	authStore     storage.AuthMaterial
	authdStore    storage.AuthdMaterial
	cacheStore    ocache.Dependencies
	logger        logr.Logger
	hasher        ocrypto.Hasher
	policyMatrix  storage.PersistencePolicyMatrix
	defaultPolicy storage.AuthProfile
}

var _ Authenticator = (*AuthService)(nil)

func NewAuthService(config Config) *AuthService {
	logger := resolveLogger(config.Logger)

	if config.Hasher == nil {
		config.Hasher = ocrypto.NewPBKDF2Hasher(ocrypto.DefaultPBKDF2Options())
	}

	return &AuthService{
		authStore:     config.AuthStore,
		authdStore:    config.AuthdStore,
		cacheStore:    config.CacheStore,
		logger:        logger,
		hasher:        config.Hasher,
		policyMatrix:  config.PolicyMatrix,
		defaultPolicy: config.DefaultPolicy,
	}
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

	subjects, err := s.authStore.SubjectAuth.ListSubjectAuthBySubject(ctx, input.UserID)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to lookup subject auth records", err)
	}

	if len(subjects) < 1 {
		return Principal{}, oerrors.New(oerrors.CodeNotFound, "user_id not found")
	}

	authIds := []string{}
	for _, subject := range subjects {
		if subject.Subject != input.UserID {
			return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "multiple auth records found for different user_ids")
		}
		authIds = append(authIds, subject.AuthID)
	}

	records, err := s.authStore.Auth.GetAuths(ctx, authIds)
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
			s.logger.Error(
				err,
				"failed to persist expired auth status",
				"auth_id", selectedRecord.ID,
				"subject", input.UserID,
			)
		}
		return Principal{}, oerrors.New(oerrors.CodeCredentialsExpired, "credentials have expired")
	}

	ok := false
	var verifyErr error
	switch materialType {
	case storage.AuthMaterialTypePassword:
		ok, verifyErr = s.hasher.Verify(input.Value, selectedRecord.MaterialHash)
	default:
		return Principal{}, oerrors.New(oerrors.CodeNotImplemented, "auth input type is not implemented")
	}

	if verifyErr != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeInvalidCredentials, "unable to verify credentials", verifyErr)
	}

	if !ok {
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "authentication failed")
	}

	authenticatedAt := time.Now().UTC()
	if s.authStore.AuthLog != nil {
		if err := s.authStore.AuthLog.PutAuthLog(ctx, storage.AuthLogRecord{
			ID:         uuid.NewString(),
			DateAdded:  time.Now().UTC(),
			AuthID:     selectedRecord.ID,
			Subject:    input.UserID,
			Event:      storage.AuthLogEventUsed,
			OccurredAt: authenticatedAt,
		}); err != nil {
			s.logger.Error(
				err,
				"failed to write auth log record",
				"auth_id", selectedRecord.ID,
				"subject", input.UserID,
				"event", storage.AuthLogEventUsed,
			)
		}
	}

	// TODO Configure tenants
	// role, err := s.authdStore.Role.GetRole(ctx, input.UserID, "default")
	// if err != nil {
	// 	return Principal{}, oerrors.Wrap(oerrors.CodeRole, "failed to get role", err)
	// }

	// perm, err := s.authdStore.Permission.GetPermission(ctx, input.UserID, "default")
	// if err != nil {
	// 	return Principal{}, oerrors.Wrap(oerrors.CodePermission, "failed to get permission", err)
	// }

	return Principal{
		Subject: input.UserID,
		Tenant:  "default",
		//RoleMask:        role.RoleMask,
		//PermissionMask:  perm.PermissionMask,
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

	materialHash, err := s.hasher.Hash(input.Value)
	if err != nil {
		return oerrors.Wrap(oerrors.CodeUnknown, "failed to hash auth value", err)
	}

	writeAuth := func(stores storage.AuthMaterial, transactional bool) error {
		return s.createAuthWithStores(ctx, stores, input.UserID, materialHash, input.ExpiresAt, input.Metadata, transactional)
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
	return Principal{}, errors.New("not implemented")
}

func (s *AuthService) createAuthWithStores(ctx context.Context, stores storage.AuthMaterial, userID string, materialHash string, expiresAt *time.Time, metadata map[string]string, transactional bool) error {
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
		MaterialHash: materialHash,
		ExpiresAt:    expiresAt,
		Metadata:     metadata,
	}); err != nil {
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to create auth record", err)
	}

	if err := stores.SubjectAuth.PutSubjectAuth(ctx, storage.SubjectAuthRecord{
		ID:        uuid.NewString(),
		DateAdded: now,
		Subject:   userID,
		AuthID:    authID,
	}); err != nil {
		if !transactional {
			if deleteErr := stores.Auth.DeleteAuth(ctx, authID); deleteErr != nil {
				s.logger.Error(deleteErr, "failed to cleanup auth record after subject link failure", "auth_id", authID, "subject", userID)
			}
		}
		return oerrors.Wrap(oerrors.CodeStorageUnavailable, "failed to link auth record to subject", err)
	}

	if stores.AuthLog != nil {
		if err := stores.AuthLog.PutAuthLog(ctx, storage.AuthLogRecord{
			ID:         uuid.NewString(),
			DateAdded:  now,
			AuthID:     authID,
			Subject:    userID,
			Event:      storage.AuthLogEventValidated,
			OccurredAt: now,
		}); err != nil {
			s.logger.Error(err, "failed to write create auth log record", "auth_id", authID, "subject", userID)
		}
	}

	return nil
}
