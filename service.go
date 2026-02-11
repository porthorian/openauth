package openauth

import (
	"context"
	"errors"
)

type AuthService struct {
}

func (s *AuthService) AuthPassword(ctx context.Context, input PasswordInput) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}

func (s *AuthService) AuthToken(ctx context.Context, input TokenInput) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (Principal, error) {
	return Principal{}, errors.New("not implemented")
}
