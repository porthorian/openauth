package authz

import (
	"errors"
	"testing"
)

func TestCompileRegistryRejectsDuplicatePermissionBit(t *testing.T) {
	_, err := CompileRegistry(
		[]PermissionDefinition{
			{Key: "read", Bit: 1},
			{Key: "write", Bit: 1},
		},
		nil,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrDuplicatePermissionBit) {
		t.Fatalf("expected duplicate permission bit error, got %v", err)
	}
}

func TestCompileRegistryRejectsRoleCycle(t *testing.T) {
	_, err := CompileRegistry(
		[]PermissionDefinition{{Key: "read", Bit: 0}},
		[]RoleDefinition{
			{Key: "role_a", Bit: 0, Inherits: []string{"role_b"}},
			{Key: "role_b", Bit: 1, Inherits: []string{"role_a"}},
		},
	)
	if err == nil {
		t.Fatalf("expected cycle error")
	}
	if !errors.Is(err, ErrRoleInheritanceCycle) {
		t.Fatalf("expected cycle error, got %v", err)
	}
}

func TestResolveRoleInheritanceAndOverrides(t *testing.T) {
	registry, err := CompileRegistry(
		[]PermissionDefinition{
			{Key: "read", Bit: 0},
			{Key: "write", Bit: 1},
			{Key: "delete", Bit: 2},
			{Key: "audit", Bit: 129},
		},
		[]RoleDefinition{
			{Key: "viewer", Bit: 0, Permissions: []string{"read"}},
			{Key: "editor", Bit: 1, Permissions: []string{"write"}, Inherits: []string{"viewer"}},
		},
	)
	if err != nil {
		t.Fatalf("CompileRegistry returned error: %v", err)
	}

	roleMask, permissionMask, err := registry.Resolve(
		[]string{"editor"},
		[]string{"audit"},
		[]string{"write"},
	)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}

	requiredAll, err := registry.PermissionMaskForKeys([]string{"read", "audit"})
	if err != nil {
		t.Fatalf("PermissionMaskForKeys returned error: %v", err)
	}
	if !HasAllPermissions(permissionMask, requiredAll) {
		t.Fatalf("expected required permissions to be present")
	}

	denied, err := registry.PermissionMaskForKeys([]string{"write"})
	if err != nil {
		t.Fatalf("PermissionMaskForKeys returned error: %v", err)
	}
	if HasAnyPermissions(permissionMask, denied) {
		t.Fatalf("expected write to be denied")
	}

	if roleMask[0] == 0 {
		t.Fatalf("expected non-empty role mask")
	}
}

func TestResolveUnknownRoleFails(t *testing.T) {
	registry, err := CompileRegistry(
		[]PermissionDefinition{{Key: "read", Bit: 0}},
		[]RoleDefinition{{Key: "viewer", Bit: 0, Permissions: []string{"read"}}},
	)
	if err != nil {
		t.Fatalf("CompileRegistry returned error: %v", err)
	}

	_, _, err = registry.Resolve([]string{"missing"}, nil, nil)
	if err == nil {
		t.Fatalf("expected unknown role error")
	}
	if !errors.Is(err, ErrUnknownRoleKey) {
		t.Fatalf("expected unknown role error, got %v", err)
	}
}

func TestRoleMaskForKeys(t *testing.T) {
	registry, err := CompileRegistry(
		[]PermissionDefinition{{Key: "read", Bit: 0}},
		[]RoleDefinition{
			{Key: "viewer", Bit: 0, Permissions: []string{"read"}},
			{Key: "auditor", Bit: 130, Permissions: []string{"read"}},
		},
	)
	if err != nil {
		t.Fatalf("CompileRegistry returned error: %v", err)
	}

	required, err := registry.RoleMaskForKeys([]string{"viewer", "auditor"})
	if err != nil {
		t.Fatalf("RoleMaskForKeys returned error: %v", err)
	}

	if !HasAllRoles(required, required) {
		t.Fatalf("expected required role mask to satisfy HasAllRoles")
	}

	viewerOnly, err := registry.RoleMaskForKeys([]string{"viewer"})
	if err != nil {
		t.Fatalf("RoleMaskForKeys returned error: %v", err)
	}
	if !HasAnyRoles(required, viewerOnly) {
		t.Fatalf("expected HasAnyRoles to match viewer role")
	}
}

func TestRoleMaskForKeysUnknownRole(t *testing.T) {
	registry, err := CompileRegistry(
		[]PermissionDefinition{{Key: "read", Bit: 0}},
		[]RoleDefinition{{Key: "viewer", Bit: 0, Permissions: []string{"read"}}},
	)
	if err != nil {
		t.Fatalf("CompileRegistry returned error: %v", err)
	}

	_, err = registry.RoleMaskForKeys([]string{"missing-role"})
	if err == nil {
		t.Fatalf("expected unknown role error")
	}
	if !errors.Is(err, ErrUnknownRoleKey) {
		t.Fatalf("expected unknown role error, got %v", err)
	}
}
