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

func (s *AuthService) AuthPassword(ctx context.Context, input PasswordInput) (Principal, error) {
	if s == nil || s.authStore.Auth == nil || s.authStore.SubjectAuth == nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "auth storage is not configured")
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

	var selectedRecord *storage.AuthRecord
	for _, record := range records {
		if record.MaterialType != storage.AuthMaterialTypePassword {
			continue
		}

		if record.Status == storage.StatusActive {
			selectedRecord = &record
			break
		}
	}

	if selectedRecord == nil {
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "no valid password auth record found for user_id")
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

	ok, err := s.hasher.Verify(input.Password, selectedRecord.MaterialHash)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeInvalidCredentials, "unable to verify password authentication", err)
	}

	if !ok {
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "password authentication failed")
	}

	authenticatedAt := time.Now().UTC()
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

	// TODO Configure tenants
	role, err := s.authdStore.Role.GetRole(ctx, input.UserID, "default")
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeRole, "failed to get role", err)
	}

	perm, err := s.authdStore.Permission.GetPermission(ctx, input.UserID, "default")
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodePermission, "failed to get permission", err)
	}

	return Principal{
		Subject:         input.UserID,
		Tenant:          "default",
		RoleMask:        role.RoleMask,
		PermissionMask:  perm.PermissionMask,
		AuthenticatedAt: authenticatedAt,
	}, nil
}

func (s *AuthService) AuthToken(ctx context.Context, input TokenInput) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}
