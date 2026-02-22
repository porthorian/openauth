package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/porthorian/openauth/pkg/cache"
)

var (
	ErrInvalidTTL = errors.New("memory cache: ttl must be greater than zero")
)

type principalEntry struct {
	snapshot cache.PrincipalSnapshot
	expires  time.Time
}

type permissionEntry struct {
	mask    uint64
	expires time.Time
}

type Adapter struct {
	mu                sync.RWMutex
	tokenEntries      map[string]principalEntry
	principalEntries  map[string]principalEntry
	permissionEntries map[string]permissionEntry
}

var _ cache.TokenCache = (*Adapter)(nil)
var _ cache.PrincipalCache = (*Adapter)(nil)
var _ cache.PermissionCache = (*Adapter)(nil)

func NewAdapter() *Adapter {
	return &Adapter{
		tokenEntries:      map[string]principalEntry{},
		principalEntries:  map[string]principalEntry{},
		permissionEntries: map[string]permissionEntry{},
	}
}

func (a *Adapter) SetToken(ctx context.Context, key string, snapshot cache.PrincipalSnapshot, ttl time.Duration) error {
	if err := validateSetInput(key, ttl); err != nil {
		return err
	}

	a.mu.Lock()
	a.tokenEntries[key] = principalEntry{
		snapshot: cloneSnapshot(snapshot),
		expires:  time.Now().UTC().Add(ttl),
	}
	a.mu.Unlock()
	return nil
}

func (a *Adapter) GetToken(ctx context.Context, key string) (cache.PrincipalSnapshot, bool, error) {
	entry, ok := a.getPrincipalEntry(&a.tokenEntries, key)
	if !ok {
		return cache.PrincipalSnapshot{}, false, nil
	}

	return cloneSnapshot(entry.snapshot), true, nil
}

func (a *Adapter) DeleteToken(ctx context.Context, key string) error {
	a.mu.Lock()
	delete(a.tokenEntries, key)
	a.mu.Unlock()
	return nil
}

func (a *Adapter) SetPrincipal(ctx context.Context, key string, snapshot cache.PrincipalSnapshot, ttl time.Duration) error {
	if err := validateSetInput(key, ttl); err != nil {
		return err
	}

	a.mu.Lock()
	a.principalEntries[key] = principalEntry{
		snapshot: cloneSnapshot(snapshot),
		expires:  time.Now().UTC().Add(ttl),
	}
	a.mu.Unlock()
	return nil
}

func (a *Adapter) GetPrincipal(ctx context.Context, key string) (cache.PrincipalSnapshot, bool, error) {
	entry, ok := a.getPrincipalEntry(&a.principalEntries, key)
	if !ok {
		return cache.PrincipalSnapshot{}, false, nil
	}

	return cloneSnapshot(entry.snapshot), true, nil
}

func (a *Adapter) DeletePrincipal(ctx context.Context, key string) error {
	a.mu.Lock()
	delete(a.principalEntries, key)
	a.mu.Unlock()
	return nil
}

func (a *Adapter) SetPermissionMask(ctx context.Context, key string, permissionMask uint64, ttl time.Duration) error {
	if err := validateSetInput(key, ttl); err != nil {
		return err
	}

	a.mu.Lock()
	a.permissionEntries[key] = permissionEntry{
		mask:    permissionMask,
		expires: time.Now().UTC().Add(ttl),
	}
	a.mu.Unlock()
	return nil
}

func (a *Adapter) GetPermissionMask(ctx context.Context, key string) (uint64, bool, error) {
	now := time.Now().UTC()

	a.mu.RLock()
	entry, ok := a.permissionEntries[key]
	a.mu.RUnlock()
	if !ok {
		return 0, false, nil
	}

	if now.After(entry.expires) {
		a.mu.Lock()
		delete(a.permissionEntries, key)
		a.mu.Unlock()
		return 0, false, nil
	}

	return entry.mask, true, nil
}

func (a *Adapter) DeletePermissionMask(ctx context.Context, key string) error {
	a.mu.Lock()
	delete(a.permissionEntries, key)
	a.mu.Unlock()
	return nil
}

func (a *Adapter) getPrincipalEntry(entries *map[string]principalEntry, key string) (principalEntry, bool) {
	now := time.Now().UTC()

	a.mu.RLock()
	entry, ok := (*entries)[key]
	a.mu.RUnlock()
	if !ok {
		return principalEntry{}, false
	}

	if now.After(entry.expires) {
		a.mu.Lock()
		delete(*entries, key)
		a.mu.Unlock()
		return principalEntry{}, false
	}

	return entry, true
}

func validateSetInput(key string, ttl time.Duration) error {
	if key == "" {
		return errors.New("memory cache: key is required")
	}
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	return nil
}

func cloneSnapshot(snapshot cache.PrincipalSnapshot) cache.PrincipalSnapshot {
	clonedClaims := map[string]any{}
	for key, value := range snapshot.Claims {
		clonedClaims[key] = value
	}

	snapshot.Claims = clonedClaims
	return snapshot
}
