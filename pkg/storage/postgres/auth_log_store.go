package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putAuthLogQuery = `
INSERT INTO openauth.auth_log (
  id, auth_id, subject, event, occurred_at, date_added, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7)
`

	listAuthLogByAuthIDQuery = `
SELECT
  id::text, date_added, auth_id::text, subject, event, occurred_at, metadata
FROM openauth.auth_log
WHERE auth_id = $1
ORDER BY date_added ASC
`

	listAuthLogBySubjectQuery = `
SELECT
  id::text, date_added, auth_id::text, subject, event, occurred_at, metadata
FROM openauth.auth_log
WHERE subject = $1
ORDER BY date_added ASC
`
)

func (a *Adapter) PutAuthLog(ctx context.Context, record storage.AuthLogRecord) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	dateAdded := record.DateAdded
	if dateAdded.IsZero() {
		dateAdded = time.Now().UTC()
	}

	occurredAt := record.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = dateAdded
	}

	event := string(record.Event)
	if event == "" {
		event = string(storage.AuthLogEventUsed)
	}

	metadata := cloneStringMap(record.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	if a.tx != nil {
		stmt := a.tx.StmtContext(ctx, a.stmts.putAuthLog)
		defer stmt.Close()
		_, err := stmt.ExecContext(ctx, record.ID, record.AuthID, record.Subject, event, occurredAt, dateAdded, metadataRaw)
		return err
	}

	_, err = a.stmts.putAuthLog.ExecContext(ctx, record.ID, record.AuthID, record.Subject, event, occurredAt, dateAdded, metadataRaw)
	return err
}

func (a *Adapter) ListAuthLogsByAuthID(ctx context.Context, authID string) ([]storage.AuthLogRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listAuthLogByAuthID.QueryContext(ctx, authID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.AuthLogRecord{}
	for rows.Next() {
		record, scanErr := scanAuthLog(rows)
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

func (a *Adapter) ListAuthLogsBySubject(ctx context.Context, subject string) ([]storage.AuthLogRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listAuthLogBySubject.QueryContext(ctx, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.AuthLogRecord{}
	for rows.Next() {
		record, scanErr := scanAuthLog(rows)
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

func scanAuthLog(s scanner) (storage.AuthLogRecord, error) {
	var (
		record      storage.AuthLogRecord
		dateAdded   time.Time
		event       string
		occurredAt  time.Time
		metadataRaw []byte
	)

	if err := s.Scan(
		&record.ID,
		&dateAdded,
		&record.AuthID,
		&record.Subject,
		&event,
		&occurredAt,
		&metadataRaw,
	); err != nil {
		return storage.AuthLogRecord{}, err
	}

	record.DateAdded = dateAdded.UTC()
	record.Event = storage.AuthLogEvent(event)
	record.OccurredAt = occurredAt.UTC()
	record.Metadata = map[string]string{}
	if len(metadataRaw) == 0 {
		return record, nil
	}

	decoded := map[string]string{}
	if err := json.Unmarshal(metadataRaw, &decoded); err != nil {
		return storage.AuthLogRecord{}, err
	}
	record.Metadata = decoded
	return record, nil
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
