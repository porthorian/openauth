package openauth

import (
	"context"

	"github.com/go-logr/logr"
	ocache "github.com/porthorian/openauth/pkg/cache"
	ocrypto "github.com/porthorian/openauth/pkg/crypto"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type Config struct {
	AuthStore     storage.AuthMaterial
	AuthdStore    storage.AuthdMaterial
	CacheStore    ocache.Dependencies
	Logger        logr.Logger
	Hasher        ocrypto.Hasher
	PolicyMatrix  storage.PersistencePolicyMatrix
	DefaultPolicy storage.AuthProfile
	Runtime       RuntimeConfig
}

type Client struct {
	auth          Authenticator
	logger        logr.Logger
	closeResource func() error
}

func New(auth Authenticator, config Config) (*Client, error) {
	closeResource, resolvedConfig, err := config.initialize(context.Background())
	if err != nil {
		return nil, err
	}

	if auth == nil {
		_ = closeResource()
		return nil, oerrors.ErrMissingAuthenticator
	}

	return &Client{
		auth:          auth,
		logger:        resolvedConfig.Logger,
		closeResource: closeResource,
	}, nil
}

func NewDefault(config Config) (*Client, error) {
	closeResource, resolvedConfig, err := config.initialize(context.Background())
	if err != nil {
		return nil, err
	}

	return &Client{
		auth:          NewAuthService(resolvedConfig),
		logger:        resolvedConfig.Logger,
		closeResource: closeResource,
	}, nil
}

func (c *Client) AuthPassword(ctx context.Context, input PasswordInput) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, oerrors.ErrMissingAuthenticator
	}

	p, err := c.auth.AuthPassword(ctx, input)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeUnauthenticated, "failed to authenticate", err)
	}
	return p, nil
}

func (c *Client) AuthToken(ctx context.Context, input TokenInput) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, oerrors.ErrMissingAuthenticator
	}

	p, err := c.auth.AuthToken(ctx, input)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeUnauthenticated, "failed to authenticate access token", err)
	}
	return p, nil
}

func (c *Client) Validate(ctx context.Context, token string) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, oerrors.ErrMissingAuthenticator
	}

	p, err := c.auth.ValidateToken(ctx, token)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeInvalidToken, "failed to validate token", err)
	}
	return p, nil
}

func (c *Client) Close() error {
	if c == nil || c.closeResource == nil {
		return nil
	}

	err := c.closeResource()
	if err != nil {
		return oerrors.Wrap(oerrors.CodeUnknown, "failed to close client resources", err)
	}
	c.closeResource = nil
	c.auth = nil
	return nil
}
