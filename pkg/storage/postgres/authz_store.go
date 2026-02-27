package postgres

import (
	"context"

	"github.com/porthorian/openauth/pkg/storage"
)

func (a *Adapter) PutRole(ctx context.Context, record storage.RoleRecord) error {
	return ErrNotImplemented
}

func (a *Adapter) GetRole(ctx context.Context, subject string, tenant string) (storage.RoleRecord, error) {
	return storage.RoleRecord{}, ErrNotImplemented
}

func (a *Adapter) DeleteRole(ctx context.Context, subject string, tenant string) error {
	return ErrNotImplemented
}

func (a *Adapter) PutPermission(ctx context.Context, record storage.PermissionRecord) error {
	return ErrNotImplemented
}

func (a *Adapter) GetPermission(ctx context.Context, subject string, tenant string) (storage.PermissionRecord, error) {
	return storage.PermissionRecord{}, ErrNotImplemented
}

func (a *Adapter) DeletePermission(ctx context.Context, subject string, tenant string) error {
	return ErrNotImplemented
}
