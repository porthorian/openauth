package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putAuthEventQuery = `
INSERT INTO openauth.auth_event (
  auth_id, date_added, user_agent, ip_address, event, metadata, error_message
) VALUES ($1, $2, $3, $4, $5, $6, $7)
`

	listAuthEventByAuthIDQuery = `
SELECT
  id::text, date_added, auth_id::text, event, metadata
FROM openauth.auth_event
WHERE auth_id = $1
ORDER BY date_added ASC
`

	listAuthEventBySubjectQuery = `
SELECT
  id::text, date_added, auth_id::text, event, metadata
FROM openauth.auth_event
WHERE metadata ->> 'subject' = $1
ORDER BY date_added ASC
`
)

func (a *Adapter) PutAuthLog(ctx context.Context, record storage.AuthLogRecord) error {
	if err := a.requirePreparedStatements(); err != nil {
		return err
	}

	dateAdded := record.DateAdded
	if dateAdded.IsZero() {
		if !record.OccurredAt.IsZero() {
			dateAdded = record.OccurredAt.UTC()
		} else {
			dateAdded = time.Now().UTC()
		}
	}

	metadata := cloneStringMap(record.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}

	userAgent := "openauth"
	if value := strings.TrimSpace(metadata["user_agent"]); value != "" {
		userAgent = value
	}

	ipAddress := "0.0.0.0"
	if value := strings.TrimSpace(metadata["ip_address"]); value != "" {
		ipAddress = value
	}

	event := strings.TrimSpace(string(record.Event))
	if event == "" {
		event = strings.TrimSpace(metadata["event"])
	}
	if event == "" {
		event = string(storage.AuthLogEventUsed)
	}

	occurredAt := record.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = dateAdded
	}

	metadata["occurred_at"] = occurredAt.UTC().Format(time.RFC3339Nano)
	if subject := strings.TrimSpace(record.Subject); subject != "" {
		metadata["subject"] = subject
	}

	var errorMessage any
	if msg := strings.TrimSpace(metadata["error_message"]); msg != "" {
		errorMessage = msg
	}
	delete(metadata, "user_agent")
	delete(metadata, "ip_address")
	delete(metadata, "event")
	delete(metadata, "error_message")

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	if a.tx != nil {
		stmt := a.tx.StmtContext(ctx, a.stmts.putAuthEvent)
		defer stmt.Close()
		_, err := stmt.ExecContext(
			ctx,
			record.AuthID,
			dateAdded,
			userAgent,
			ipAddress,
			event,
			metadataJSON,
			errorMessage,
		)
		return err
	}

	_, err = a.stmts.putAuthEvent.ExecContext(
		ctx,
		record.AuthID,
		dateAdded,
		userAgent,
		ipAddress,
		event,
		metadataJSON,
		errorMessage,
	)
	return err
}

func (a *Adapter) ListAuthLogsByAuthID(ctx context.Context, authID string) ([]storage.AuthLogRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listAuthEventByAuthID.QueryContext(ctx, authID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.AuthLogRecord{}
	for rows.Next() {
		record, err := scanAuthEvent(rows)
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

func (a *Adapter) ListAuthLogsBySubject(ctx context.Context, subject string) ([]storage.AuthLogRecord, error) {
	if err := a.requirePreparedStatements(); err != nil {
		return nil, err
	}

	rows, err := a.stmts.listAuthEventBySubject.QueryContext(ctx, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []storage.AuthLogRecord{}
	for rows.Next() {
		record, err := scanAuthEvent(rows)
		if err != nil {
			return nil, err
		}
		if record.Subject != subject {
			continue
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func scanAuthEvent(s scanner) (storage.AuthLogRecord, error) {
	var (
		record      storage.AuthLogRecord
		dateAdded   time.Time
		event       string
		metadataRaw []byte
	)

	if err := s.Scan(
		&record.ID,
		&dateAdded,
		&record.AuthID,
		&event,
		&metadataRaw,
	); err != nil {
		return storage.AuthLogRecord{}, err
	}

	record.DateAdded = dateAdded.UTC()
	record.OccurredAt = record.DateAdded
	record.Metadata = map[string]string{}

	if len(metadataRaw) > 0 {
		decodedMetadata, err := decodeAuthEventMetadata(metadataRaw)
		if err != nil {
			return storage.AuthLogRecord{}, err
		}
		for key, value := range decodedMetadata {
			record.Metadata[key] = value
		}
	}

	if subject := strings.TrimSpace(record.Metadata["subject"]); subject != "" {
		record.Subject = subject
	}

	record.Event = storage.AuthLogEvent(strings.TrimSpace(event))
	if record.Event == "" {
		if metadataEvent := strings.TrimSpace(record.Metadata["event"]); metadataEvent != "" {
			record.Event = storage.AuthLogEvent(metadataEvent)
		}
	}

	if occurredAtRaw := strings.TrimSpace(record.Metadata["occurred_at"]); occurredAtRaw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, occurredAtRaw)
		if err == nil {
			record.OccurredAt = parsed.UTC()
		}
	}

	return record, nil
}

func decodeAuthEventMetadata(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	typed := map[string]string{}
	if err := json.Unmarshal(raw, &typed); err == nil {
		return typed, nil
	}

	anyTyped := map[string]any{}
	if err := json.Unmarshal(raw, &anyTyped); err != nil {
		return nil, err
	}

	decoded := make(map[string]string, len(anyTyped))
	for key, value := range anyTyped {
		switch typedValue := value.(type) {
		case nil:
			continue
		case string:
			decoded[key] = typedValue
		default:
			decoded[key] = fmt.Sprint(typedValue)
		}
	}

	return decoded, nil
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
