package postgres

import (
	"context"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putSubjectAuthQuery = `
INSERT INTO openauth.subject_auth (
  id, auth_id, subject, date_added, date_modified
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (auth_id) DO UPDATE
SET
  subject = EXCLUDED.subject,
  date_modified = EXCLUDED.date_modified
`

	listSubjectAuthBySubjectQuery = `
SELECT
  id::text, date_added, auth_id::text, subject
FROM openauth.subject_auth
WHERE subject = $1
`

	listSubjectAuthByAuthIDQuery = `
SELECT
  id::text, date_added, auth_id::text, subject
FROM openauth.subject_auth
WHERE auth_id = $1
`

	deleteSubjectAuthQuery = `DELETE FROM openauth.subject_auth WHERE id = $1`
)

func (a *Adapter) PutSubjectAuth(ctx context.Context, record storage.SubjectAuthRecord) error {
	if err := a.requirePreparedStatements(); err != nil {
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

	if a.tx != nil {
		stmt := a.tx.StmtContext(ctx, a.stmts.putSubjectAuth)
		defer stmt.Close()
		_, err := stmt.ExecContext(
			ctx,
			record.ID,
			record.AuthID,
			record.Subject,
			dateAdded,
			dateModified,
		)
		return err
	}

	_, err := a.stmts.putSubjectAuth.ExecContext(
		ctx,
		record.ID,
		record.AuthID,
		record.Subject,
		dateAdded,
		dateModified,
	)
	return err
}

func (a *Adapter) ListSubjectAuthBySubject(ctx context.Context, subject string) ([]storage.SubjectAuthRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listSubjectAuthBySubject.QueryContext(ctx, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.SubjectAuthRecord{}
	for rows.Next() {
		record, scanErr := scanSubjectAuth(rows)
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

func (a *Adapter) ListSubjectAuthByAuthID(ctx context.Context, authID string) ([]storage.SubjectAuthRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listSubjectAuthByAuthID.QueryContext(ctx, authID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.SubjectAuthRecord{}
	for rows.Next() {
		record, scanErr := scanSubjectAuth(rows)
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

func (a *Adapter) DeleteSubjectAuth(ctx context.Context, id string) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	if a.tx != nil {
		stmt := a.tx.StmtContext(ctx, a.stmts.deleteSubjectAuthByID)
		defer stmt.Close()
		_, err := stmt.ExecContext(ctx, id)
		return err
	}

	_, err := a.stmts.deleteSubjectAuthByID.ExecContext(ctx, id)
	return err
}

func scanSubjectAuth(s scanner) (storage.SubjectAuthRecord, error) {
	var (
		record    storage.SubjectAuthRecord
		dateAdded time.Time
		authID    string
		subject   string
	)

	if err := s.Scan(&record.ID, &dateAdded, &authID, &subject); err != nil {
		return storage.SubjectAuthRecord{}, err
	}

	record.DateAdded = dateAdded.UTC()
	record.DateModified = nil
	record.AuthID = authID
	record.Subject = subject
	return record, nil
}
