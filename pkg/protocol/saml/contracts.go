package saml

import (
	"context"
	"time"
)

type Assertion struct {
	Subject      string
	Audience     string
	Issuer       string
	NotBefore    time.Time
	NotOnOrAfter time.Time
	Attributes   map[string][]string
}

type Validator interface {
	ValidateResponse(ctx context.Context, encodedResponse string) (Assertion, error)
}

type ClaimMapper interface {
	MapAssertion(ctx context.Context, assertion Assertion) (map[string]any, error)
}
