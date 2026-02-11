package storage

import "time"

type Authority string

const (
	AuthoritySourceOfTruth Authority = "source_of_truth"
	AuthorityExternal      Authority = "external_authority"
	AuthoritySelfContained Authority = "self_contained"
)

type CacheRole string

const (
	CacheRoleNone          CacheRole = "none"
	CacheRoleReadThrough   CacheRole = "read_through"
	CacheRoleIntrospection CacheRole = "introspection"
)

type FailureMode string

const (
	FailureModeClosed FailureMode = "fail_closed"
	FailureModeOpen   FailureMode = "fail_open"
)

type AuthProfile string

const (
	AuthProfilePasswordBasic      AuthProfile = "password_basic"
	AuthProfileRefreshRotating    AuthProfile = "refresh_rotating"
	AuthProfileAccessOpaqueLocal  AuthProfile = "access_opaque_local"
	AuthProfileAccessOpaqueRemote AuthProfile = "access_opaque_remote"
	AuthProfileAccessJWT          AuthProfile = "access_jwt"
	AuthProfileAPIKey             AuthProfile = "api_key"
	AuthProfileClientSecret       AuthProfile = "client_secret"
)

type PersistencePolicy struct {
	MaterialType           AuthMaterialType
	TokenFormat            TokenFormat
	TokenUse               TokenUse
	Authority              Authority
	CacheRole              CacheRole
	PersistInSourceOfTruth bool
	AllowNonExpiring       bool
	MaxCacheTTL            time.Duration
	FailureMode            FailureMode
}

type PersistencePolicyMatrix interface {
	Policy(profile AuthProfile) (PersistencePolicy, bool)
}

type StaticPolicyMatrix struct {
	policies map[AuthProfile]PersistencePolicy
}

func NewStaticPolicyMatrix(policies map[AuthProfile]PersistencePolicy) *StaticPolicyMatrix {
	cloned := make(map[AuthProfile]PersistencePolicy, len(policies))
	for profile, policy := range policies {
		cloned[profile] = policy
	}
	return &StaticPolicyMatrix{policies: cloned}
}

func DefaultPersistencePolicyMatrix() *StaticPolicyMatrix {
	return NewStaticPolicyMatrix(DefaultPersistencePolicies())
}

func DefaultPersistencePolicies() map[AuthProfile]PersistencePolicy {
	return map[AuthProfile]PersistencePolicy{
		AuthProfilePasswordBasic: {
			MaterialType:           AuthMaterialTypePassword,
			Authority:              AuthoritySourceOfTruth,
			CacheRole:              CacheRoleNone,
			PersistInSourceOfTruth: true,
			AllowNonExpiring:       false,
			FailureMode:            FailureModeClosed,
		},
		AuthProfileRefreshRotating: {
			MaterialType:           AuthMaterialTypeRefreshToken,
			TokenFormat:            TokenFormatOpaque,
			TokenUse:               TokenUseRefresh,
			Authority:              AuthoritySourceOfTruth,
			CacheRole:              CacheRoleReadThrough,
			PersistInSourceOfTruth: true,
			AllowNonExpiring:       false,
			MaxCacheTTL:            2 * time.Minute,
			FailureMode:            FailureModeClosed,
		},
		AuthProfileAccessOpaqueLocal: {
			MaterialType:           AuthMaterialTypeAccessToken,
			TokenFormat:            TokenFormatOpaque,
			TokenUse:               TokenUseAccess,
			Authority:              AuthoritySourceOfTruth,
			CacheRole:              CacheRoleReadThrough,
			PersistInSourceOfTruth: true,
			AllowNonExpiring:       false,
			MaxCacheTTL:            5 * time.Minute,
			FailureMode:            FailureModeClosed,
		},
		AuthProfileAccessOpaqueRemote: {
			MaterialType:           AuthMaterialTypeAccessToken,
			TokenFormat:            TokenFormatOpaque,
			TokenUse:               TokenUseAccess,
			Authority:              AuthorityExternal,
			CacheRole:              CacheRoleIntrospection,
			PersistInSourceOfTruth: false,
			AllowNonExpiring:       false,
			MaxCacheTTL:            time.Minute,
			FailureMode:            FailureModeClosed,
		},
		AuthProfileAccessJWT: {
			MaterialType:           AuthMaterialTypeAccessToken,
			TokenFormat:            TokenFormatJWT,
			TokenUse:               TokenUseAccess,
			Authority:              AuthoritySelfContained,
			CacheRole:              CacheRoleNone,
			PersistInSourceOfTruth: false,
			AllowNonExpiring:       false,
			FailureMode:            FailureModeClosed,
		},
		AuthProfileAPIKey: {
			MaterialType:           AuthMaterialTypeAPIKey,
			Authority:              AuthoritySourceOfTruth,
			CacheRole:              CacheRoleReadThrough,
			PersistInSourceOfTruth: true,
			AllowNonExpiring:       true,
			MaxCacheTTL:            15 * time.Minute,
			FailureMode:            FailureModeClosed,
		},
		AuthProfileClientSecret: {
			MaterialType:           AuthMaterialTypeClientSecret,
			Authority:              AuthoritySourceOfTruth,
			CacheRole:              CacheRoleNone,
			PersistInSourceOfTruth: true,
			AllowNonExpiring:       false,
			FailureMode:            FailureModeClosed,
		},
	}
}

func (m *StaticPolicyMatrix) Policy(profile AuthProfile) (PersistencePolicy, bool) {
	if m == nil {
		return PersistencePolicy{}, false
	}

	policy, ok := m.policies[profile]
	return policy, ok
}
