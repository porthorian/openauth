package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putAuthQuery = `
INSERT INTO openauth.auth (
  id, status, date_added, date_modified, material_type, material_hash, expires_at, revoked_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE
SET
  status = EXCLUDED.status,
  date_modified = EXCLUDED.date_modified,
  material_type = EXCLUDED.material_type,
  material_hash = EXCLUDED.material_hash,
  expires_at = EXCLUDED.expires_at,
  revoked_at = EXCLUDED.revoked_at
`

	getAuthQuery = `
SELECT
  id::text, status, date_added, date_modified, material_type, material_hash, expires_at, revoked_at
FROM openauth.auth
WHERE id = $1
`

	deleteAuthQuery = `DELETE FROM openauth.auth WHERE id = $1`

	deleteAuthMetadataQuery = `
DELETE FROM openauth.auth_metadata
WHERE auth_id = $1
`

	putAuthMetadataQuery = `
INSERT INTO openauth.auth_metadata (
  auth_id, date_added, key, value
) VALUES ($1, $2, $3, $4)
`

	getAuthMetadataQuery = `
SELECT
  key, value
FROM openauth.auth_metadata
WHERE auth_id = $1
`
)

func (a *Adapter) PutAuth(ctx context.Context, record storage.AuthRecord) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	if a.tx != nil {
		return a.putAuthInTx(ctx, a.tx, record)
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

	if err := a.putAuthInTx(ctx, tx, record); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (a *Adapter) putAuthInTx(ctx context.Context, tx *sql.Tx, record storage.AuthRecord) error {
	dateAdded := record.DateAdded
	if dateAdded.IsZero() {
		dateAdded = time.Now().UTC()
	}

	dateModified := time.Now().UTC()
	if record.DateModified != nil {
		dateModified = record.DateModified.UTC()
	}

	putAuthStmt := tx.StmtContext(ctx, a.stmts.putAuth)
	_, err := putAuthStmt.ExecContext(
		ctx,
		record.ID,
		string(record.Status),
		dateAdded,
		dateModified,
		string(record.MaterialType),
		record.MaterialHash,
		record.ExpiresAt,
		record.RevokedAt,
	)
	_ = putAuthStmt.Close()
	if err != nil {
		return err
	}

	deleteMetadataStmt := tx.StmtContext(ctx, a.stmts.deleteAuthMetadata)
	if _, err := deleteMetadataStmt.ExecContext(ctx, record.ID); err != nil {
		_ = deleteMetadataStmt.Close()
		return err
	}
	_ = deleteMetadataStmt.Close()

	keys := sortedMetadataKeys(record.Metadata)
	if len(keys) > 0 {
		putMetadataStmt := tx.StmtContext(ctx, a.stmts.putAuthMetadata)
		for _, key := range keys {
			if _, err := putMetadataStmt.ExecContext(ctx, record.ID, time.Now().UTC(), key, record.Metadata[key]); err != nil {
				_ = putMetadataStmt.Close()
				return err
			}
		}
		_ = putMetadataStmt.Close()
	}

	return nil
}

func (a *Adapter) GetAuth(ctx context.Context, id string) (storage.AuthRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return storage.AuthRecord{}, err
	}

	row := a.stmts.getAuth.QueryRowContext(ctx, id)
	record, err := scanAuth(row)
	if err != nil {
		return storage.AuthRecord{}, err
	}

	metadata, err := a.getMetadataByAuthID(ctx, id)
	if err != nil {
		return storage.AuthRecord{}, err
	}
	record.Metadata = metadata

	return record, nil
}

func (a *Adapter) GetAuths(ctx context.Context, ids []string) ([]storage.AuthRecord, error) {
	if len(ids) == 0 {
		return []storage.AuthRecord{}, nil
	}

	stmt, err := a.getAuthsPrepared(len(ids))
	if err != nil {
		return nil, err
	}

	args := make([]any, len(ids))
	for i := range ids {
		args[i] = ids[i]
	}

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]storage.AuthRecord, 0, len(ids))
	authIDs := make([]string, 0, len(ids))
	for rows.Next() {
		record, scanErr := scanAuth(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
		authIDs = append(authIDs, record.ID)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	metadataByAuthID, err := a.getMetadataByAuthIDs(ctx, authIDs)
	if err != nil {
		return nil, err
	}

	for i := range records {
		metadata, ok := metadataByAuthID[records[i].ID]
		if !ok {
			records[i].Metadata = map[string]string{}
			continue
		}
		records[i].Metadata = metadata
	}

	return records, nil
}

func (a *Adapter) DeleteAuth(ctx context.Context, id string) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	if a.tx != nil {
		stmt := a.tx.StmtContext(ctx, a.stmts.deleteAuth)
		defer stmt.Close()
		_, err := stmt.ExecContext(ctx, id)
		return err
	}

	_, err := a.stmts.deleteAuth.ExecContext(ctx, id)
	return err
}

func (a *Adapter) getAuthsPrepared(size int) (*sql.Stmt, error) {
	if size <= 0 {
		return nil, nil
	}

	db, err := a.requireDB()
	if err != nil {
		return nil, err
	}

	a.stmts.getAuthsMu.Lock()
	defer a.stmts.getAuthsMu.Unlock()

	if stmt, ok := a.stmts.getAuthsBySize[size]; ok {
		return stmt, nil
	}

	placeholders := make([]string, size)
	for i := 0; i < size; i++ {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(`
SELECT
  id::text, status, date_added, date_modified, material_type, material_hash, expires_at, revoked_at
FROM openauth.auth
WHERE id IN (%s)
`, strings.Join(placeholders, ", "))

	stmt, err := db.Prepare(query)
	if err != nil {
		return nil, err
	}

	a.stmts.getAuthsBySize[size] = stmt
	return stmt, nil
}

func scanAuth(s scanner) (storage.AuthRecord, error) {
	var (
		record       storage.AuthRecord
		status       string
		materialType string
		dateModified sql.NullTime
		expiresAt    sql.NullTime
		revokedAt    sql.NullTime
	)

	if err := s.Scan(
		&record.ID,
		&status,
		&record.DateAdded,
		&dateModified,
		&materialType,
		&record.MaterialHash,
		&expiresAt,
		&revokedAt,
	); err != nil {
		return storage.AuthRecord{}, err
	}

	record.Status = storage.AuthStatus(status)
	record.MaterialType = storage.AuthMaterialType(materialType)
	if dateModified.Valid {
		t := dateModified.Time.UTC()
		record.DateModified = &t
	}
	if expiresAt.Valid {
		t := expiresAt.Time.UTC()
		record.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		record.RevokedAt = &t
	}
	record.Metadata = map[string]string{}

	return record, nil
}

func sortedMetadataKeys(metadata map[string]string) []string {
	if len(metadata) == 0 {
		return nil
	}

	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (a *Adapter) getMetadataByAuthID(ctx context.Context, authID string) (map[string]string, error) {
	rows, err := a.stmts.getAuthMetadata.QueryContext(ctx, authID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	metadata := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		metadata[key] = value
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return metadata, nil
}

func (a *Adapter) getMetadataByAuthIDs(ctx context.Context, authIDs []string) (map[string]map[string]string, error) {
	if len(authIDs) == 0 {
		return map[string]map[string]string{}, nil
	}

	db, err := a.requireDB()
	if err != nil {
		return nil, err
	}

	placeholders := make([]string, len(authIDs))
	args := make([]any, len(authIDs))
	for i := range authIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = authIDs[i]
	}

	query := fmt.Sprintf(`
SELECT
  auth_id::text, key, value
FROM openauth.auth_metadata
WHERE auth_id IN (%s)
`, strings.Join(placeholders, ", "))

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	metadataByAuthID := map[string]map[string]string{}
	for rows.Next() {
		var authID, key, value string
		if err := rows.Scan(&authID, &key, &value); err != nil {
			return nil, err
		}

		metadata, ok := metadataByAuthID[authID]
		if !ok {
			metadata = map[string]string{}
			metadataByAuthID[authID] = metadata
		}
		metadata[key] = value
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return metadataByAuthID, nil
}
