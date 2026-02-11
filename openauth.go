package openauth

import (
	"context"

	"github.com/porthorian/openauth/pkg/errors"
)

type Config struct {
}

type Client struct {
	auth Authenticator
}

func New(auth Authenticator, config Config) (*Client, error) {
	if auth == nil {
		return nil, errors.ErrMissingAuthenticator
	}

	return &Client{
		auth: auth,
	}, nil
}

func (c *Client) AuthPassword(ctx context.Context, input PasswordInput) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, errors.ErrMissingAuthenticator
	}

	p, err := c.auth.AuthPassword(ctx, input)
	if err != nil {
		return Principal{}, errors.Wrap(errors.CodeUnauthenticated, "failed to authenticate", err)
	}
	return p, nil
}

func (c *Client) AuthToken(ctx context.Context, input TokenInput) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, errors.ErrMissingAuthenticator
	}

	p, err := c.auth.AuthToken(ctx, input)
	if err != nil {
		return Principal{}, errors.Wrap(errors.CodeUnauthenticated, "failed to authenticate access token", err)
	}
	return p, nil
}

func (c *Client) Validate(ctx context.Context, token string) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, errors.ErrMissingAuthenticator
	}

	p, err := c.auth.ValidateToken(ctx, token)
	if err != nil {
		return Principal{}, errors.Wrap(errors.CodeInvalidToken, "failed to validate token", err)
	}
	return p, nil
}
