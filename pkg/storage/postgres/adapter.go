package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putAuthQuery = `
INSERT INTO auth (
  id, status, date_added, date_modified, material_type, material_hash, expires_at, revoked_at, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE
SET
  status = EXCLUDED.status,
  date_modified = EXCLUDED.date_modified,
  material_type = EXCLUDED.material_type,
  material_hash = EXCLUDED.material_hash,
  expires_at = EXCLUDED.expires_at,
  revoked_at = EXCLUDED.revoked_at,
  metadata = EXCLUDED.metadata
`

	getAuthQuery = `
SELECT
  id, status, date_added, date_modified, material_type, material_hash, expires_at, revoked_at, metadata
FROM auth
WHERE id = $1
`

	deleteAuthQuery = `DELETE FROM auth WHERE id = $1`
)

type Adapter struct {
	db *sql.DB

	prepareOnce sync.Once
	prepareErr  error

	putAuthStmt    *sql.Stmt
	getAuthStmt    *sql.Stmt
	deleteAuthStmt *sql.Stmt

	getAuthsMu    sync.Mutex
	getAuthsStmts map[int]*sql.Stmt
}

var (
	ErrNilDB = errors.New("postgres adapter: db is nil")
)

var _ storage.AuthStore = (*Adapter)(nil)

func NewAdapter(db *sql.DB) *Adapter {
	return &Adapter{
		db:            db,
		getAuthsStmts: map[int]*sql.Stmt{},
	}
}

func (a *Adapter) PutAuth(ctx context.Context, record storage.AuthRecord) error {
	if err := a.ensurePrepared(); err != nil {
		return err
	}

	dateAdded := record.DateAdded
	if dateAdded.IsZero() {
		dateAdded = time.Now().UTC()
	}

	dateModified := time.Now().UTC()
	if record.DateModified != nil {
		dateModified = record.DateModified.UTC()
	}

	metadata, err := marshalMetadata(record.Metadata)
	if err != nil {
		return err
	}

	_, err = a.putAuthStmt.ExecContext(
		ctx,
		record.ID,
		string(record.Status),
		dateAdded,
		dateModified,
		string(record.MaterialType),
		record.MaterialHash,
		record.ExpiresAt,
		record.RevokedAt,
		metadata,
	)
	return err
}

func (a *Adapter) GetAuth(ctx context.Context, id string) (storage.AuthRecord, error) {
	if err := a.ensurePrepared(); err != nil {
		return storage.AuthRecord{}, err
	}

	row := a.getAuthStmt.QueryRowContext(ctx, id)
	return scanAuth(row)
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
	for rows.Next() {
		record, scanErr := scanAuth(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (a *Adapter) DeleteAuth(ctx context.Context, id string) error {
	if err := a.ensurePrepared(); err != nil {
		return err
	}

	_, err := a.deleteAuthStmt.ExecContext(ctx, id)
	return err
}

func (a *Adapter) Close() error {
	if a == nil {
		return nil
	}

	var errs []error

	if a.putAuthStmt != nil {
		if err := a.putAuthStmt.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.getAuthStmt != nil {
		if err := a.getAuthStmt.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.deleteAuthStmt != nil {
		if err := a.deleteAuthStmt.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	a.getAuthsMu.Lock()
	for _, stmt := range a.getAuthsStmts {
		if stmt == nil {
			continue
		}
		if err := stmt.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	a.getAuthsMu.Unlock()

	return errors.Join(errs...)
}

func (a *Adapter) getAuthsPrepared(size int) (*sql.Stmt, error) {
	if size <= 0 {
		return nil, nil
	}

	a.getAuthsMu.Lock()
	defer a.getAuthsMu.Unlock()

	if stmt, ok := a.getAuthsStmts[size]; ok {
		return stmt, nil
	}

	placeholders := make([]string, size)
	for i := 0; i < size; i++ {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	query := fmt.Sprintf(`
SELECT
  id, status, date_added, date_modified, material_type, material_hash, expires_at, revoked_at, metadata
FROM auth
WHERE id IN (%s)
`, strings.Join(placeholders, ", "))

	stmt, err := a.db.Prepare(query)
	if err != nil {
		return nil, err
	}

	a.getAuthsStmts[size] = stmt
	return stmt, nil
}

func (a *Adapter) ensurePrepared() error {
	a.prepareOnce.Do(func() {
		db, err := a.requireDB()
		if err != nil {
			a.prepareErr = err
			return
		}

		a.putAuthStmt, err = db.Prepare(putAuthQuery)
		if err != nil {
			a.prepareErr = err
			return
		}

		a.getAuthStmt, err = db.Prepare(getAuthQuery)
		if err != nil {
			a.prepareErr = err
			return
		}

		a.deleteAuthStmt, err = db.Prepare(deleteAuthQuery)
		if err != nil {
			a.prepareErr = err
			return
		}
	})

	return a.prepareErr
}

func (a *Adapter) requireDB() (*sql.DB, error) {
	if a == nil || a.db == nil {
		return nil, ErrNilDB
	}
	return a.db, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanAuth(s scanner) (storage.AuthRecord, error) {
	var (
		record       storage.AuthRecord
		status       string
		materialType string
		dateModified sql.NullTime
		expiresAt    sql.NullTime
		revokedAt    sql.NullTime
		metadataJSON []byte
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
		&metadataJSON,
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

	metadata, err := unmarshalMetadata(metadataJSON)
	if err != nil {
		return storage.AuthRecord{}, err
	}
	record.Metadata = metadata

	return record, nil
}

func marshalMetadata(metadata map[string]string) ([]byte, error) {
	if metadata == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(metadata)
}

func unmarshalMetadata(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}

	metadata := map[string]string{}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil, err
	}

	if metadata == nil {
		return map[string]string{}, nil
	}
	return metadata, nil
}
