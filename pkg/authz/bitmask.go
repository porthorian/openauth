package authz

type PermissionMask uint64

type RoleMask uint64

const (
	PermissionRead PermissionMask = 1 << iota
	PermissionWrite
	PermissionDelete
	PermissionAdmin
)

const (
	RoleViewer RoleMask = 1 << iota
	RoleEditor
	RoleOwner
	RoleAdmin
)

var RolePermissionMatrix = map[RoleMask]PermissionMask{
	RoleViewer: PermissionRead,
	RoleEditor: PermissionRead | PermissionWrite,
	RoleOwner:  PermissionRead | PermissionWrite | PermissionDelete,
	RoleAdmin:  PermissionRead | PermissionWrite | PermissionDelete | PermissionAdmin,
}

func EffectivePermissions(roleMask RoleMask, direct PermissionMask) PermissionMask {
	effective := direct

	for role, perms := range RolePermissionMatrix {
		if roleMask&role != 0 {
			effective |= perms
		}
	}

	return effective
}

func HasAnyPermissions(current PermissionMask, required PermissionMask) bool {
	return current&required != 0
}

func HasAllPermissions(current PermissionMask, required PermissionMask) bool {
	return current&required == required
}
