package postgres

import (
	"context"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putAuthUserQuery = `
INSERT INTO openauth.auth_user (
  id, auth_id, user_id, date_added
) VALUES ($1, $2, $3, $4)
ON CONFLICT (auth_id) DO UPDATE
SET
  user_id = EXCLUDED.user_id
`

	listAuthUserByUserIDQuery = `
SELECT
  id::text, date_added, auth_id::text, user_id::text
FROM openauth.auth_user
WHERE user_id = $1
`

	listAuthUserByAuthIDQuery = `
SELECT
  id::text, date_added, auth_id::text, user_id::text
FROM openauth.auth_user
WHERE auth_id = $1
`

	deleteAuthUserQuery = `DELETE FROM openauth.auth_user WHERE id = $1`
)

func (a *Adapter) PutSubjectAuth(ctx context.Context, record storage.SubjectAuthRecord) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	dateAdded := record.DateAdded
	if dateAdded.IsZero() {
		dateAdded = time.Now().UTC()
	}

	_, err := a.stmts.putAuthUser.ExecContext(
		ctx,
		record.ID,
		record.AuthID,
		record.Subject,
		dateAdded,
	)
	return err
}

func (a *Adapter) ListSubjectAuthBySubject(ctx context.Context, subject string) ([]storage.SubjectAuthRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listAuthUserByUserID.QueryContext(ctx, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.SubjectAuthRecord{}
	for rows.Next() {
		record, err := scanSubjectAuth(rows)
		if err != nil {
			return nil, err
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

	rows, err := a.stmts.listAuthUserByAuthID.QueryContext(ctx, authID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.SubjectAuthRecord{}
	for rows.Next() {
		record, err := scanSubjectAuth(rows)
		if err != nil {
			return nil, err
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

	_, err := a.stmts.deleteAuthUserByID.ExecContext(ctx, id)
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
