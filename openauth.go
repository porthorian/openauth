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

var _ Authenticator = (*Client)(nil)

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

func (c *Client) Authorize(ctx context.Context, input AuthInput) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, oerrors.ErrMissingAuthenticator
	}

	p, err := c.auth.Authorize(ctx, input)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeUnauthenticated, "failed to authorize", err)
	}
	return p, nil
}

func (c *Client) ValidateToken(ctx context.Context, token string) (Principal, error) {
	if c == nil || c.auth == nil {
		return Principal{}, oerrors.ErrMissingAuthenticator
	}

	p, err := c.auth.ValidateToken(ctx, token)
	if err != nil {
		return Principal{}, oerrors.Wrap(oerrors.CodeInvalidToken, "failed to validate token", err)
	}
	return p, nil
}

func (c *Client) CreateAuth(ctx context.Context, input CreateAuthInput) error {
	if c == nil || c.auth == nil {
		return oerrors.ErrMissingAuthenticator
	}

	err := c.auth.CreateAuth(ctx, input)
	if err != nil {
		return oerrors.Wrap(oerrors.CodeUnknown, "failed to create auth", err)
	}
	return nil
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
