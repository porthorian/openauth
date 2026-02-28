package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/porthorian/openauth/pkg/storage"
)

const (
	putAuthEventQuery = `
INSERT INTO openauth.auth_event (
  auth_id, date_added, user_agent, ip_address, login_status, error_message
) VALUES ($1, $2, $3, $4, $5, $6)
`

	listAuthEventByAuthIDQuery = `
SELECT
  id::text, date_added, auth_id::text, user_agent, ip_address::text, login_status, error_message
FROM openauth.auth_event
WHERE auth_id = $1
ORDER BY date_added ASC
`

	listAuthEventBySubjectQuery = `
SELECT
  id::text, date_added, auth_id::text, user_agent, ip_address::text, login_status, error_message
FROM openauth.auth_event
WHERE error_message LIKE $1
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

	userAgent := "openauth"
	if record.Metadata != nil {
		if value := strings.TrimSpace(record.Metadata["user_agent"]); value != "" {
			userAgent = value
		}
	}

	ipAddress := "0.0.0.0"
	if record.Metadata != nil {
		if value := strings.TrimSpace(record.Metadata["ip_address"]); value != "" {
			ipAddress = value
		}
	}

	loginStatus := record.Event != storage.AuthLogEventRevoked
	if record.Metadata != nil {
		if raw := strings.TrimSpace(record.Metadata["login_status"]); raw != "" {
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return err
			}
			loginStatus = parsed
		}
	}

	errorMessage := encodeAuthEventErrorMessage(record)

	if a.tx != nil {
		stmt := a.tx.StmtContext(ctx, a.stmts.putAuthEvent)
		defer stmt.Close()
		_, err := stmt.ExecContext(
			ctx,
			record.AuthID,
			dateAdded,
			userAgent,
			ipAddress,
			loginStatus,
			errorMessage,
		)
		return err
	}

	_, err := a.stmts.putAuthEvent.ExecContext(
		ctx,
		record.AuthID,
		dateAdded,
		userAgent,
		ipAddress,
		loginStatus,
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

	pattern := "subject=" + url.QueryEscape(subject) + ";%"
	rows, err := a.stmts.listAuthEventBySubject.QueryContext(ctx, pattern)
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
		record       storage.AuthLogRecord
		dateAdded    time.Time
		userAgent    string
		ipAddress    string
		loginStatus  bool
		errorMessage sql.NullString
	)

	if err := s.Scan(
		&record.ID,
		&dateAdded,
		&record.AuthID,
		&userAgent,
		&ipAddress,
		&loginStatus,
		&errorMessage,
	); err != nil {
		return storage.AuthLogRecord{}, err
	}

	record.DateAdded = dateAdded.UTC()
	record.OccurredAt = record.DateAdded
	record.Metadata = map[string]string{
		"user_agent":   userAgent,
		"ip_address":   ipAddress,
		"login_status": strconv.FormatBool(loginStatus),
	}

	if loginStatus {
		record.Event = storage.AuthLogEventUsed
	} else {
		record.Event = storage.AuthLogEventRevoked
	}

	if errorMessage.Valid && strings.TrimSpace(errorMessage.String) != "" {
		subject, event, occurredAt, message := decodeAuthEventErrorMessage(errorMessage.String)
		if subject != "" {
			record.Subject = subject
		}
		if event != "" {
			record.Event = storage.AuthLogEvent(event)
		}
		if !occurredAt.IsZero() {
			record.OccurredAt = occurredAt
		}
		if message != "" {
			record.Metadata["error_message"] = message
		}
	}

	return record, nil
}

func encodeAuthEventErrorMessage(record storage.AuthLogRecord) string {
	occurredAt := record.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}

	parts := []string{
		"subject=" + url.QueryEscape(record.Subject),
		"event=" + url.QueryEscape(string(record.Event)),
		"occurred_at=" + url.QueryEscape(occurredAt.UTC().Format(time.RFC3339Nano)),
	}
	if record.Metadata != nil {
		if message := strings.TrimSpace(record.Metadata["error_message"]); message != "" {
			parts = append(parts, "error="+url.QueryEscape(message))
		}
	}

	return strings.Join(parts, ";")
}

func decodeAuthEventErrorMessage(raw string) (subject string, event string, occurredAt time.Time, message string) {
	parts := strings.Split(raw, ";")
	values := map[string]string{}
	for _, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			continue
		}
		values[key] = decoded
	}

	subject = values["subject"]
	event = values["event"]
	if values["occurred_at"] != "" {
		parsed, err := time.Parse(time.RFC3339Nano, values["occurred_at"])
		if err == nil {
			occurredAt = parsed.UTC()
		}
	}
	message = values["error"]
	return subject, event, occurredAt, message
}
