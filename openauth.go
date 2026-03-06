package openauth

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/porthorian/openauth/pkg/approach"
	"github.com/porthorian/openauth/pkg/authz"
	ocache "github.com/porthorian/openauth/pkg/cache"
	ocrypto "github.com/porthorian/openauth/pkg/crypto"
	oerrors "github.com/porthorian/openauth/pkg/errors"
	"github.com/porthorian/openauth/pkg/storage"
)

type Config struct {
	AuthStore            storage.AuthMaterial
	AuthdStore           storage.AuthdMaterial
	CacheStore           ocache.Dependencies
	Logger               logr.Logger
	Hasher               ocrypto.Hasher
	PolicyMatrix         storage.PersistencePolicyMatrix
	DefaultPolicy        storage.AuthProfile
	Authorization        AuthorizationConfig
	ApproachRegistry     *approach.Registry
	DefaultTokenApproach string
	Runtime              RuntimeConfig
}

type ClientDependencies struct {
	Authenticator        Authenticator
	AuthorizationManager AuthorizationManager
	AuthorizationChecker AuthorizationChecker
}

type ClientBuilder func(resolved Config) (ClientDependencies, error)

type Client struct {
	authzManager  AuthorizationManager
	authzChecker  AuthorizationChecker
	auth          Authenticator
	logger        logr.Logger
	closeResource func() error
}

var _ Authenticator = (*Client)(nil)

func New(config Config, build ClientBuilder) (*Client, error) {
	closeResource, resolvedConfig, err := config.initialize(context.Background())
	if err != nil {
		return nil, err
	}

	return newClientWithBuilder(resolvedConfig, closeResource, build)
}

func NewDefault(config Config) (*Client, error) {
	return New(config, func(resolved Config) (ClientDependencies, error) {
		authService, err := NewAuthService(resolved)
		if err != nil {
			return ClientDependencies{}, err
		}
		return ClientDependencies{
			Authenticator:        authService,
			AuthorizationManager: authService,
			AuthorizationChecker: authService,
		}, nil
	})
}

func newClientWithBuilder(resolvedConfig Config, closeResource func() error, build ClientBuilder) (*Client, error) {
	if build == nil {
		_ = closeResource()
		return nil, oerrors.ErrMissingAuthenticator
	}

	dependencies, err := build(resolvedConfig)
	if err != nil {
		_ = closeResource()
		return nil, err
	}
	if dependencies.Authenticator == nil {
		_ = closeResource()
		return nil, oerrors.ErrMissingAuthenticator
	}

	return newClient(dependencies, resolvedConfig.Logger, closeResource), nil
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
	c.authzManager = nil
	c.authzChecker = nil
	c.auth = nil
	return nil
}

func (c *Client) SetSubjectRoles(ctx context.Context, input SetSubjectRolesInput) error {
	if c == nil {
		return oerrors.ErrMissingAuthenticator
	}
	if c.authzManager == nil {
		if c.auth == nil {
			return oerrors.ErrMissingAuthenticator
		}
		return oerrors.New(oerrors.CodeNotImplemented, "authorization manager is not configured")
	}
	if err := c.authzManager.SetSubjectRoles(ctx, input); err != nil {
		return oerrors.Wrap(oerrors.CodeUnknown, "failed to set subject roles", err)
	}
	return nil
}

func (c *Client) SetSubjectPermissionOverrides(ctx context.Context, input SetSubjectPermissionOverridesInput) error {
	if c == nil {
		return oerrors.ErrMissingAuthenticator
	}
	if c.authzManager == nil {
		if c.auth == nil {
			return oerrors.ErrMissingAuthenticator
		}
		return oerrors.New(oerrors.CodeNotImplemented, "authorization manager is not configured")
	}
	if err := c.authzManager.SetSubjectPermissionOverrides(ctx, input); err != nil {
		return oerrors.Wrap(oerrors.CodeUnknown, "failed to set subject permission overrides", err)
	}
	return nil
}

func (c *Client) HasAllRoles(principal Principal, roleKeys ...string) (bool, error) {
	if c == nil {
		return false, oerrors.ErrMissingAuthenticator
	}
	if c.authzChecker == nil {
		if c.auth == nil {
			return false, oerrors.ErrMissingAuthenticator
		}
		return false, oerrors.New(oerrors.CodeNotImplemented, "authorization checker is not configured")
	}
	return c.authzChecker.HasAllRoles(principal, roleKeys...)
}

func (c *Client) HasAnyRoles(principal Principal, roleKeys ...string) (bool, error) {
	if c == nil {
		return false, oerrors.ErrMissingAuthenticator
	}
	if c.authzChecker == nil {
		if c.auth == nil {
			return false, oerrors.ErrMissingAuthenticator
		}
		return false, oerrors.New(oerrors.CodeNotImplemented, "authorization checker is not configured")
	}
	return c.authzChecker.HasAnyRoles(principal, roleKeys...)
}

func (c *Client) RequireAllRoles(principal Principal, roleKeys ...string) error {
	ok, err := c.HasAllRoles(principal, roleKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required roles are missing")
	}
	return nil
}

func (c *Client) RequireAnyRoles(principal Principal, roleKeys ...string) error {
	ok, err := c.HasAnyRoles(principal, roleKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required roles are missing")
	}
	return nil
}

func (c *Client) HasAllPermissions(principal Principal, permissionKeys ...string) (bool, error) {
	if c == nil {
		return false, oerrors.ErrMissingAuthenticator
	}
	if c.authzChecker == nil {
		if c.auth == nil {
			return false, oerrors.ErrMissingAuthenticator
		}
		return false, oerrors.New(oerrors.CodeNotImplemented, "authorization checker is not configured")
	}
	return c.authzChecker.HasAllPermissions(principal, permissionKeys...)
}

func (c *Client) HasAnyPermissions(principal Principal, permissionKeys ...string) (bool, error) {
	if c == nil {
		return false, oerrors.ErrMissingAuthenticator
	}
	if c.authzChecker == nil {
		if c.auth == nil {
			return false, oerrors.ErrMissingAuthenticator
		}
		return false, oerrors.New(oerrors.CodeNotImplemented, "authorization checker is not configured")
	}
	return c.authzChecker.HasAnyPermissions(principal, permissionKeys...)
}

func (c *Client) RequireAllPermissions(principal Principal, permissionKeys ...string) error {
	ok, err := c.HasAllPermissions(principal, permissionKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required permissions are missing")
	}
	return nil
}

func (c *Client) RequireAnyPermissions(principal Principal, permissionKeys ...string) error {
	ok, err := c.HasAnyPermissions(principal, permissionKeys...)
	if err != nil {
		return err
	}
	if !ok {
		return oerrors.New(oerrors.CodePermissionDenied, "required permissions are missing")
	}
	return nil
}

func compileAuthorizationRegistry(config AuthorizationConfig) (*authz.Registry, error) {
	return authz.CompileRegistry(config.Registry.Permissions, config.Registry.Roles)
}

func newClient(dependencies ClientDependencies, logger logr.Logger, closeResource func() error) *Client {
	return &Client{
		authzManager:  dependencies.AuthorizationManager,
		authzChecker:  dependencies.AuthorizationChecker,
		auth:          dependencies.Authenticator,
		logger:        logger,
		closeResource: closeResource,
	}
}
