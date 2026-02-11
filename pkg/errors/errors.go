package errors

import (
	"errors"
)

type Code string

const (
	CodeUnknown            Code = "unknown"
	CodeInvalidCredentials Code = "invalid_credentials"
	CodeInvalidToken       Code = "invalid_token"
	CodePermissionDenied   Code = "permission_denied"
	CodeUnauthenticated    Code = "unauthenticated"
	CodeStorageUnavailable Code = "storage_unavailable"
	CodeNotFound           Code = "not_found"
	CodeNotImplemented     Code = "not_implemented"
)

var ErrMissingAuthenticator = errors.New("openauth: authenticator is required")

type Error struct {
	Code    Code
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}

	if e.Message != "" {
		return e.Message
	}

	if e.Err != nil {
		return e.Err.Error()
	}

	return string(e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func New(code Code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

func Wrap(code Code, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

func IsCode(err error, code Code) bool {
	var typed *Error
	if !errors.As(err, &typed) {
		return false
	}
	return typed.Code == code
}
