package postgres

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	deleteSubjectRolesQuery = `
DELETE FROM openauth.subject_role
WHERE subject = $1 AND tenant = $2
`

	putSubjectRoleQuery = `
INSERT INTO openauth.subject_role (
  subject, tenant, role_key, date_added
) VALUES ($1, $2, $3, $4)
ON CONFLICT (subject, tenant, role_key) DO NOTHING
`

	listSubjectRolesQuery = `
SELECT
  subject, tenant, role_key
FROM openauth.subject_role
WHERE subject = $1 AND tenant = $2
ORDER BY role_key ASC
`

	deleteSubjectPermissionOverridesQuery = `
DELETE FROM openauth.subject_permission_override
WHERE subject = $1 AND tenant = $2
`

	putSubjectPermissionOverrideQuery = `
INSERT INTO openauth.subject_permission_override (
  subject, tenant, permission_key, effect, date_added
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (subject, tenant, permission_key) DO UPDATE
SET
  effect = EXCLUDED.effect,
  date_added = EXCLUDED.date_added
`

	listSubjectPermissionOverridesQuery = `
SELECT
  subject, tenant, permission_key, effect
FROM openauth.subject_permission_override
WHERE subject = $1 AND tenant = $2
ORDER BY permission_key ASC
`
)

func (a *Adapter) ReplaceSubjectRoles(ctx context.Context, subject string, tenant string, roleKeys []string) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	normalizedSubject := strings.TrimSpace(subject)
	normalizedTenant := strings.TrimSpace(tenant)
	normalizedKeys := normalizeRoleKeys(roleKeys)

	if a.tx != nil {
		return a.replaceSubjectRolesInTx(ctx, a.tx, normalizedSubject, normalizedTenant, normalizedKeys)
	}

	db, err := a.requireDB()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := a.replaceSubjectRolesInTx(ctx, tx, normalizedSubject, normalizedTenant, normalizedKeys); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) ListSubjectRoles(ctx context.Context, subject string, tenant string) ([]storage.SubjectRoleRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listSubjectRoles.QueryContext(ctx, strings.TrimSpace(subject), strings.TrimSpace(tenant))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.SubjectRoleRecord{}
	for rows.Next() {
		var record storage.SubjectRoleRecord
		if err := rows.Scan(&record.Subject, &record.Tenant, &record.RoleKey); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (a *Adapter) ReplaceSubjectPermissionOverrides(ctx context.Context, subject string, tenant string, overrides []storage.SubjectPermissionOverrideRecord) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	normalizedSubject := strings.TrimSpace(subject)
	normalizedTenant := strings.TrimSpace(tenant)
	normalizedOverrides := normalizePermissionOverrides(overrides, normalizedSubject, normalizedTenant)

	if a.tx != nil {
		return a.replaceSubjectPermissionOverridesInTx(ctx, a.tx, normalizedSubject, normalizedTenant, normalizedOverrides)
	}

	db, err := a.requireDB()
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if err := a.replaceSubjectPermissionOverridesInTx(ctx, tx, normalizedSubject, normalizedTenant, normalizedOverrides); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) ListSubjectPermissionOverrides(ctx context.Context, subject string, tenant string) ([]storage.SubjectPermissionOverrideRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listSubjectPermissionOverrides.QueryContext(ctx, strings.TrimSpace(subject), strings.TrimSpace(tenant))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.SubjectPermissionOverrideRecord{}
	for rows.Next() {
		var (
			record storage.SubjectPermissionOverrideRecord
			effect string
		)
		if err := rows.Scan(&record.Subject, &record.Tenant, &record.PermissionKey, &effect); err != nil {
			return nil, err
		}
		record.Effect = storage.PermissionEffect(effect)
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (a *Adapter) replaceSubjectRolesInTx(ctx context.Context, tx *sql.Tx, subject string, tenant string, roleKeys []string) error {
	deleteStmt := tx.StmtContext(ctx, a.stmts.deleteSubjectRoles)
	if _, err := deleteStmt.ExecContext(ctx, subject, tenant); err != nil {
		_ = deleteStmt.Close()
		return err
	}
	_ = deleteStmt.Close()

	if len(roleKeys) == 0 {
		return nil
	}

	insertStmt := tx.StmtContext(ctx, a.stmts.putSubjectRole)
	defer insertStmt.Close()

	now := time.Now().UTC()
	for _, roleKey := range roleKeys {
		if _, err := insertStmt.ExecContext(ctx, subject, tenant, roleKey, now); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) replaceSubjectPermissionOverridesInTx(ctx context.Context, tx *sql.Tx, subject string, tenant string, overrides []storage.SubjectPermissionOverrideRecord) error {
	deleteStmt := tx.StmtContext(ctx, a.stmts.deleteSubjectPermissionOverrides)
	if _, err := deleteStmt.ExecContext(ctx, subject, tenant); err != nil {
		_ = deleteStmt.Close()
		return err
	}
	_ = deleteStmt.Close()

	if len(overrides) == 0 {
		return nil
	}

	insertStmt := tx.StmtContext(ctx, a.stmts.putSubjectPermissionOverride)
	defer insertStmt.Close()

	now := time.Now().UTC()
	for _, override := range overrides {
		if _, err := insertStmt.ExecContext(ctx, subject, tenant, override.PermissionKey, string(override.Effect), now); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRoleKeys(roleKeys []string) []string {
	if len(roleKeys) == 0 {
		return nil
	}

	dedup := make(map[string]struct{}, len(roleKeys))
	normalized := make([]string, 0, len(roleKeys))
	for _, roleKey := range roleKeys {
		trimmed := strings.TrimSpace(roleKey)
		if trimmed == "" {
			continue
		}
		if _, exists := dedup[trimmed]; exists {
			continue
		}
		dedup[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func normalizePermissionOverrides(overrides []storage.SubjectPermissionOverrideRecord, subject string, tenant string) []storage.SubjectPermissionOverrideRecord {
	if len(overrides) == 0 {
		return nil
	}

	normalized := make([]storage.SubjectPermissionOverrideRecord, 0, len(overrides))
	seen := make(map[string]int, len(overrides))
	for _, override := range overrides {
		permissionKey := strings.TrimSpace(override.PermissionKey)
		if permissionKey == "" {
			continue
		}
		record := storage.SubjectPermissionOverrideRecord{
			Subject:       subject,
			Tenant:        tenant,
			PermissionKey: permissionKey,
			Effect:        override.Effect,
		}
		if record.Effect != storage.PermissionEffectGrant && record.Effect != storage.PermissionEffectDeny {
			continue
		}

		if index, exists := seen[permissionKey]; exists {
			normalized[index] = record
			continue
		}
		seen[permissionKey] = len(normalized)
		normalized = append(normalized, record)
	}
	return normalized
}
