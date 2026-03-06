package authz

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	MaskWordCount = 8
	MaxBitIndex   = 511
)

type RoleMask [MaskWordCount]uint64
type PermissionMask [MaskWordCount]uint64

type PermissionDefinition struct {
	Key string
	Bit uint16
}

type RoleDefinition struct {
	Key         string
	Bit         uint16
	Permissions []string
	Inherits    []string
}

type Registry struct {
	permissions map[string]permissionEntry
	roles       map[string]roleEntry
}

type permissionEntry struct {
	bit  uint16
	mask PermissionMask
}

type roleEntry struct {
	bit                uint16
	mask               RoleMask
	effectivePermsMask PermissionMask
}

type rawRole struct {
	bit         uint16
	permissions []string
	inherits    []string
}

type visitState uint8

const (
	visitUnvisited visitState = iota
	visitVisiting
	visitVisited
)

var (
	ErrNilRegistry            = errors.New("authz: registry is nil")
	ErrEmptyPermissionKey     = errors.New("authz: permission key is required")
	ErrEmptyRoleKey           = errors.New("authz: role key is required")
	ErrDuplicatePermissionKey = errors.New("authz: duplicate permission key")
	ErrDuplicateRoleKey       = errors.New("authz: duplicate role key")
	ErrDuplicatePermissionBit = errors.New("authz: duplicate permission bit")
	ErrDuplicateRoleBit       = errors.New("authz: duplicate role bit")
	ErrInvalidPermissionBit   = errors.New("authz: permission bit is out of range")
	ErrInvalidRoleBit         = errors.New("authz: role bit is out of range")
	ErrUnknownPermissionKey   = errors.New("authz: unknown permission key")
	ErrUnknownRoleKey         = errors.New("authz: unknown role key")
	ErrRoleInheritanceCycle   = errors.New("authz: role inheritance cycle detected")
)

func CompileRegistry(permissions []PermissionDefinition, roles []RoleDefinition) (*Registry, error) {
	registry := &Registry{
		permissions: make(map[string]permissionEntry, len(permissions)),
		roles:       make(map[string]roleEntry, len(roles)),
	}

	permissionBits := make(map[uint16]string, len(permissions))
	for _, definition := range permissions {
		key := strings.TrimSpace(definition.Key)
		if key == "" {
			return nil, ErrEmptyPermissionKey
		}
		if definition.Bit > MaxBitIndex {
			return nil, fmt.Errorf("%w: %d", ErrInvalidPermissionBit, definition.Bit)
		}
		if _, exists := registry.permissions[key]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicatePermissionKey, key)
		}
		if existingKey, exists := permissionBits[definition.Bit]; exists {
			return nil, fmt.Errorf("%w: bit=%d keys=%s,%s", ErrDuplicatePermissionBit, definition.Bit, existingKey, key)
		}

		var bitMask PermissionMask
		setPermissionBit(&bitMask, definition.Bit)
		registry.permissions[key] = permissionEntry{
			bit:  definition.Bit,
			mask: bitMask,
		}
		permissionBits[definition.Bit] = key
	}

	roleBits := make(map[uint16]string, len(roles))
	rawRoles := make(map[string]rawRole, len(roles))
	for _, definition := range roles {
		key := strings.TrimSpace(definition.Key)
		if key == "" {
			return nil, ErrEmptyRoleKey
		}
		if definition.Bit > MaxBitIndex {
			return nil, fmt.Errorf("%w: %d", ErrInvalidRoleBit, definition.Bit)
		}
		if _, exists := rawRoles[key]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateRoleKey, key)
		}
		if existingKey, exists := roleBits[definition.Bit]; exists {
			return nil, fmt.Errorf("%w: bit=%d keys=%s,%s", ErrDuplicateRoleBit, definition.Bit, existingKey, key)
		}

		rawRoles[key] = rawRole{
			bit:         definition.Bit,
			permissions: normalizeKeys(definition.Permissions),
			inherits:    normalizeKeys(definition.Inherits),
		}
		roleBits[definition.Bit] = key
	}

	for roleKey, role := range rawRoles {
		for _, permissionKey := range role.permissions {
			if _, exists := registry.permissions[permissionKey]; !exists {
				return nil, fmt.Errorf("%w: role=%s permission=%s", ErrUnknownPermissionKey, roleKey, permissionKey)
			}
		}
		for _, inheritedRoleKey := range role.inherits {
			if _, exists := rawRoles[inheritedRoleKey]; !exists {
				return nil, fmt.Errorf("%w: role=%s inherited_role=%s", ErrUnknownRoleKey, roleKey, inheritedRoleKey)
			}
		}
	}

	visited := make(map[string]visitState, len(rawRoles))
	effectiveMasks := make(map[string]PermissionMask, len(rawRoles))
	var resolveRolePermissions func(roleKey string) (PermissionMask, error)

	resolveRolePermissions = func(roleKey string) (PermissionMask, error) {
		switch visited[roleKey] {
		case visitVisited:
			return effectiveMasks[roleKey], nil
		case visitVisiting:
			return PermissionMask{}, fmt.Errorf("%w: role=%s", ErrRoleInheritanceCycle, roleKey)
		}

		visited[roleKey] = visitVisiting
		role := rawRoles[roleKey]

		var mask PermissionMask
		for _, permissionKey := range role.permissions {
			entry := registry.permissions[permissionKey]
			orPermissionMask(&mask, entry.mask)
		}
		for _, inheritedRoleKey := range role.inherits {
			inheritedMask, err := resolveRolePermissions(inheritedRoleKey)
			if err != nil {
				return PermissionMask{}, err
			}
			orPermissionMask(&mask, inheritedMask)
		}

		visited[roleKey] = visitVisited
		effectiveMasks[roleKey] = mask
		return mask, nil
	}

	for roleKey, role := range rawRoles {
		effectiveMask, err := resolveRolePermissions(roleKey)
		if err != nil {
			return nil, err
		}

		var roleMask RoleMask
		setRoleBit(&roleMask, role.bit)
		registry.roles[roleKey] = roleEntry{
			bit:                role.bit,
			mask:               roleMask,
			effectivePermsMask: effectiveMask,
		}
	}

	return registry, nil
}

func (r *Registry) ValidateRoleKeys(roleKeys []string) error {
	if r == nil {
		return ErrNilRegistry
	}
	for _, key := range normalizeKeys(roleKeys) {
		if _, exists := r.roles[key]; !exists {
			return fmt.Errorf("%w: %s", ErrUnknownRoleKey, key)
		}
	}
	return nil
}

func (r *Registry) PermissionMaskForKeys(keys []string) (PermissionMask, error) {
	if r == nil {
		return PermissionMask{}, ErrNilRegistry
	}

	var mask PermissionMask
	for _, key := range normalizeKeys(keys) {
		entry, exists := r.permissions[key]
		if !exists {
			return PermissionMask{}, fmt.Errorf("%w: %s", ErrUnknownPermissionKey, key)
		}
		orPermissionMask(&mask, entry.mask)
	}
	return mask, nil
}

func (r *Registry) RoleMaskForKeys(keys []string) (RoleMask, error) {
	if r == nil {
		return RoleMask{}, ErrNilRegistry
	}

	var mask RoleMask
	for _, key := range normalizeKeys(keys) {
		entry, exists := r.roles[key]
		if !exists {
			return RoleMask{}, fmt.Errorf("%w: %s", ErrUnknownRoleKey, key)
		}
		orRoleMask(&mask, entry.mask)
	}
	return mask, nil
}

func (r *Registry) Resolve(roleKeys []string, grantKeys []string, denyKeys []string) (RoleMask, PermissionMask, error) {
	if r == nil {
		return RoleMask{}, PermissionMask{}, ErrNilRegistry
	}

	var roleMask RoleMask
	var permissionMask PermissionMask
	for _, roleKey := range normalizeKeys(roleKeys) {
		entry, exists := r.roles[roleKey]
		if !exists {
			return RoleMask{}, PermissionMask{}, fmt.Errorf("%w: %s", ErrUnknownRoleKey, roleKey)
		}
		orRoleMask(&roleMask, entry.mask)
		orPermissionMask(&permissionMask, entry.effectivePermsMask)
	}

	grantMask, err := r.PermissionMaskForKeys(grantKeys)
	if err != nil {
		return RoleMask{}, PermissionMask{}, err
	}
	denyMask, err := r.PermissionMaskForKeys(denyKeys)
	if err != nil {
		return RoleMask{}, PermissionMask{}, err
	}

	orPermissionMask(&permissionMask, grantMask)
	andNotPermissionMask(&permissionMask, denyMask)
	return roleMask, permissionMask, nil
}

func HasAnyRoles(current RoleMask, required RoleMask) bool {
	for i := 0; i < MaskWordCount; i++ {
		if current[i]&required[i] != 0 {
			return true
		}
	}
	return false
}

func HasAllRoles(current RoleMask, required RoleMask) bool {
	for i := 0; i < MaskWordCount; i++ {
		if current[i]&required[i] != required[i] {
			return false
		}
	}
	return true
}

func HasAnyPermissions(current PermissionMask, required PermissionMask) bool {
	for i := 0; i < MaskWordCount; i++ {
		if current[i]&required[i] != 0 {
			return true
		}
	}
	return false
}

func HasAllPermissions(current PermissionMask, required PermissionMask) bool {
	for i := 0; i < MaskWordCount; i++ {
		if current[i]&required[i] != required[i] {
			return false
		}
	}
	return true
}

func setPermissionBit(mask *PermissionMask, bit uint16) {
	word := int(bit) / 64
	offset := bit % 64
	mask[word] |= uint64(1) << offset
}

func setRoleBit(mask *RoleMask, bit uint16) {
	word := int(bit) / 64
	offset := bit % 64
	mask[word] |= uint64(1) << offset
}

func orPermissionMask(dst *PermissionMask, src PermissionMask) {
	for i := 0; i < MaskWordCount; i++ {
		dst[i] |= src[i]
	}
}

func andNotPermissionMask(dst *PermissionMask, src PermissionMask) {
	for i := 0; i < MaskWordCount; i++ {
		dst[i] &^= src[i]
	}
}

func orRoleMask(dst *RoleMask, src RoleMask) {
	for i := 0; i < MaskWordCount; i++ {
		dst[i] |= src[i]
	}
}

func normalizeKeys(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}

	dedup := make(map[string]struct{}, len(keys))
	normalized := make([]string, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		if _, exists := dedup[trimmed]; exists {
			continue
		}
		dedup[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	slices.Sort(normalized)
	return normalized
}
