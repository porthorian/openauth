package openauth

import (
	"context"
	"errors"
	"time"

	ocrypto "github.com/porthorian/openauth/pkg/crypto"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type AuthService struct {
	authStore     storage.AuthMaterial
	authdStore    storage.AuthdMaterial
	hasher        ocrypto.Hasher
	policyMatrix  storage.PersistencePolicyMatrix
	defaultPolicy storage.AuthProfile
}

func NewAuthService(config Config) *AuthService {
	if config.Hasher == nil {
		config.Hasher = ocrypto.NewPBKDF2Hasher(ocrypto.DefaultPBKDF2Options())
	}

	return &AuthService{
		authStore:     config.AuthStore,
		authdStore:    config.AuthdStore,
		hasher:        config.Hasher,
		policyMatrix:  config.PolicyMatrix,
		defaultPolicy: config.DefaultPolicy,
	}
}

func (s *AuthService) AuthPassword(ctx context.Context, input PasswordInput) (Principal, error) {
	if s == nil || s.authStore.Auth == nil || s.authStore.SubjectAuth == nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "auth storage is not configured", nil)
	}

	subjects, err := s.authStore.SubjectAuth.ListSubjectAuthBySubject(ctx, input.UserID)
	if err != nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "failed to lookup subject auth records", &err)
	}

	if len(subjects) < 1 {
		return Principal{}, oerrors.New(oerrors.CodeNotFound, "user_id not found", nil)
	}

	authIds := []string{}
	for _, subject := range subjects {
		if subject.Subject != input.UserID {
			return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "multiple auth records found for different user_ids", nil)
		}
		authIds = append(authIds, subject.AuthID)
	}

	records, err := s.authStore.Auth.GetAuths(ctx, authIds)
	if err != nil {
		return Principal{}, oerrors.New(oerrors.CodeStorageUnavailable, "failed to retrieve auth records", &err)
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
		return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "no valid password auth record found for user_id", nil)
	}

	if selectedRecord.ExpiresAt != nil && selectedRecord.ExpiresAt.Before(time.Now().UTC()) {
		selectedRecord.Status = storage.StatusExpired
		if err := s.authStore.Auth.PutAuth(ctx, *selectedRecord); err != nil {
			// TODO: log error and alert monitoring system
		}
		return Principal{}, oerrors.New(oerrors.CodeCredentialsExpired, "credentials have expired", nil)
	}

	return Principal{}, oerrors.New(oerrors.CodeInvalidCredentials, "password authentication failed", nil)
}

func (s *AuthService) AuthToken(ctx context.Context, input TokenInput) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}
