package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/porthorian/openauth/pkg/session"
)

const (
	algorithmHS256 = "HS256"
	algorithmHS384 = "HS384"
	algorithmHS512 = "HS512"

	defaultSigningKeyID = "default"
	defaultSessionClaim = "openauth_session"
	defaultClockSkew    = 30 * time.Second
)

var (
	ErrInvalidConfig        = errors.New("session/jwt: invalid config")
	ErrMissingSigningKey    = errors.New("session/jwt: signing key is required for token issuance")
	ErrMissingValidationKey = errors.New("session/jwt: key is required for token validation")
	ErrUnknownKeyID         = errors.New("session/jwt: key ID not found")
	ErrUnsupportedAlgorithm = errors.New("session/jwt: unsupported JWT algorithm")

	ErrInvalidToken         = errors.New("session/jwt: invalid token")
	ErrInvalidSubject       = errors.New("session/jwt: invalid subject")
	ErrInvalidTTL           = errors.New("session/jwt: ttl must be greater than zero")
	ErrReservedClaim        = errors.New("session/jwt: reserved claim cannot be overridden")
	ErrMissingRequiredClaim = errors.New("session/jwt: missing required registered claim")
	ErrTokenExpired         = errors.New("session/jwt: token has expired")
	ErrTokenNotYetValid     = errors.New("session/jwt: token is not valid yet")
	ErrTokenIssuedInFuture  = errors.New("session/jwt: token issued-at claim is in the future")
	ErrInvalidIssuer        = errors.New("session/jwt: issuer claim does not match configuration")
	ErrInvalidAudience      = errors.New("session/jwt: audience claim does not match configuration")

	ErrInvalidSessionToken = errors.New("session/jwt: token is not a session token")
)

type Config struct {
	SigningKey   session.Key
	KeyResolver  session.KeyResolver
	Issuer       string
	Audience     []string
	ClockSkew    time.Duration
	Now          func() time.Time
	SessionClaim string
}

type Manager struct {
	signingKey   session.Key
	keyResolver  session.KeyResolver
	issuer       string
	audience     []string
	clockSkew    time.Duration
	now          func() time.Time
	sessionClaim string

	revokedMu sync.RWMutex
	revoked   map[string]time.Time
}

var _ session.TokenIssuer = (*Manager)(nil)
var _ session.TokenValidator = (*Manager)(nil)
var _ session.SessionManager = (*Manager)(nil)

func NewManager(config Config) (*Manager, error) {
	signingKey := normalizeKey(config.SigningKey)
	if len(signingKey.Material) > 0 {
		if signingKey.ID == "" {
			signingKey.ID = defaultSigningKeyID
		}
		if signingKey.Algorithm == "" {
			signingKey.Algorithm = algorithmHS256
		}
		if !isSupportedAlgorithm(signingKey.Algorithm) {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, signingKey.Algorithm)
		}
	}

	if len(signingKey.Material) == 0 && config.KeyResolver == nil {
		return nil, fmt.Errorf("%w: either signing key or key resolver must be configured", ErrInvalidConfig)
	}

	clockSkew := config.ClockSkew
	if clockSkew == 0 {
		clockSkew = defaultClockSkew
	}
	if clockSkew < 0 {
		return nil, fmt.Errorf("%w: clock skew cannot be negative", ErrInvalidConfig)
	}

	nowFn := config.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	sessionClaim := strings.TrimSpace(config.SessionClaim)
	if sessionClaim == "" {
		sessionClaim = defaultSessionClaim
	}

	return &Manager{
		signingKey:   signingKey,
		keyResolver:  config.KeyResolver,
		issuer:       strings.TrimSpace(config.Issuer),
		audience:     normalizeAudience(config.Audience),
		clockSkew:    clockSkew,
		now:          nowFn,
		sessionClaim: sessionClaim,
		revoked:      map[string]time.Time{},
	}, nil
}

func (m *Manager) IssueToken(ctx context.Context, subject string, claims session.Claims, ttl time.Duration) (string, error) {
	_ = ctx

	if m == nil {
		return "", fmt.Errorf("%w: manager is nil", ErrInvalidConfig)
	}
	if len(m.signingKey.Material) == 0 {
		return "", ErrMissingSigningKey
	}
	if ttl <= 0 {
		return "", ErrInvalidTTL
	}

	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", ErrInvalidSubject
	}

	payload := cloneClaims(claims)
	if err := validateCustomClaims(payload); err != nil {
		return "", err
	}

	now := m.now().UTC()
	payload["sub"] = subject
	payload["iat"] = now.Unix()
	payload["nbf"] = now.Unix()
	payload["exp"] = now.Add(ttl).Unix()

	if m.issuer != "" {
		payload["iss"] = m.issuer
	}
	if len(m.audience) == 1 {
		payload["aud"] = m.audience[0]
	} else if len(m.audience) > 1 {
		payload["aud"] = append([]string(nil), m.audience...)
	}

	header := map[string]any{
		"typ": "JWT",
		"alg": m.signingKey.Algorithm,
	}
	if m.signingKey.ID != "" {
		header["kid"] = m.signingKey.ID
	}

	return encodeAndSignToken(header, payload, m.signingKey)
}

func (m *Manager) ValidateToken(ctx context.Context, token string) (session.Claims, error) {
	if m == nil {
		return nil, fmt.Errorf("%w: manager is nil", ErrInvalidConfig)
	}

	parsed, err := parseToken(token)
	if err != nil {
		return nil, err
	}

	alg, err := readStringValue(parsed.header["alg"])
	if err != nil || strings.TrimSpace(alg) == "" {
		return nil, fmt.Errorf("%w: missing alg header", ErrInvalidToken)
	}
	alg = strings.ToUpper(strings.TrimSpace(alg))
	if !isSupportedAlgorithm(alg) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	kid := ""
	if value, ok := parsed.header["kid"]; ok {
		parsedKID, parseErr := readStringValue(value)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: invalid kid header: %v", ErrInvalidToken, parseErr)
		}
		kid = strings.TrimSpace(parsedKID)
	}

	key, err := m.resolveValidationKey(ctx, kid, alg)
	if err != nil {
		return nil, err
	}

	if err := verifySignature(parsed.signingInput, parsed.signature, key); err != nil {
		return nil, err
	}

	if err := m.validateRegisteredClaims(parsed.claims); err != nil {
		return nil, err
	}

	return parsed.claims, nil
}

func (m *Manager) IssueSession(ctx context.Context, subject string, ttl time.Duration) (string, error) {
	claims := session.Claims{
		m.sessionClaim: true,
		"jti":          uuid.NewString(),
	}
	return m.IssueToken(ctx, subject, claims, ttl)
}

func (m *Manager) ValidateSession(ctx context.Context, sessionID string) (bool, error) {
	claims, err := m.ValidateToken(ctx, sessionID)
	if err != nil {
		return false, err
	}

	isSession, ok := claimBool(claims, m.sessionClaim)
	if !ok || !isSession {
		return false, ErrInvalidSessionToken
	}

	jti, ok := claimString(claims, "jti")
	if !ok || strings.TrimSpace(jti) == "" {
		return false, ErrInvalidSessionToken
	}

	if m.isRevoked(jti) {
		return false, nil
	}

	return true, nil
}

func (m *Manager) RevokeSession(ctx context.Context, sessionID string) error {
	claims, err := m.ValidateToken(ctx, sessionID)
	if err != nil {
		return err
	}

	isSession, ok := claimBool(claims, m.sessionClaim)
	if !ok || !isSession {
		return ErrInvalidSessionToken
	}

	jti, ok := claimString(claims, "jti")
	if !ok || strings.TrimSpace(jti) == "" {
		return ErrInvalidSessionToken
	}

	expiresAt, err := readTimeClaim(claims, "exp", true)
	if err != nil {
		return err
	}

	m.markRevoked(jti, expiresAt)
	return nil
}

func (m *Manager) resolveValidationKey(ctx context.Context, keyID string, algorithm string) (session.Key, error) {
	if m.keyResolver != nil {
		key, err := m.keyResolver.ResolveKey(ctx, keyID)
		if err != nil {
			return session.Key{}, fmt.Errorf("%w: %v", ErrMissingValidationKey, err)
		}

		key = normalizeKey(key)
		if len(key.Material) == 0 {
			return session.Key{}, ErrMissingValidationKey
		}

		if key.Algorithm != "" && key.Algorithm != algorithm {
			return session.Key{}, fmt.Errorf("%w: header=%s resolver=%s", ErrUnsupportedAlgorithm, algorithm, key.Algorithm)
		}
		if key.Algorithm == "" {
			key.Algorithm = algorithm
		}

		return key, nil
	}

	key := normalizeKey(m.signingKey)
	if len(key.Material) == 0 {
		return session.Key{}, ErrMissingValidationKey
	}

	if keyID != "" && key.ID != "" && keyID != key.ID {
		return session.Key{}, fmt.Errorf("%w: %s", ErrUnknownKeyID, keyID)
	}

	if key.Algorithm != "" && key.Algorithm != algorithm {
		return session.Key{}, fmt.Errorf("%w: header=%s key=%s", ErrUnsupportedAlgorithm, algorithm, key.Algorithm)
	}
	if key.Algorithm == "" {
		key.Algorithm = algorithm
	}

	return key, nil
}

func (m *Manager) validateRegisteredClaims(claims session.Claims) error {
	now := m.now().UTC()

	subject, ok := claimString(claims, "sub")
	if !ok || strings.TrimSpace(subject) == "" {
		return fmt.Errorf("%w: sub", ErrMissingRequiredClaim)
	}

	expiresAt, err := readTimeClaim(claims, "exp", true)
	if err != nil {
		return err
	}
	if now.After(expiresAt.Add(m.clockSkew)) {
		return ErrTokenExpired
	}

	notBefore, err := readTimeClaim(claims, "nbf", false)
	if err != nil {
		return err
	}
	if !notBefore.IsZero() && now.Add(m.clockSkew).Before(notBefore) {
		return ErrTokenNotYetValid
	}

	issuedAt, err := readTimeClaim(claims, "iat", false)
	if err != nil {
		return err
	}
	if !issuedAt.IsZero() && now.Add(m.clockSkew).Before(issuedAt) {
		return ErrTokenIssuedInFuture
	}

	if m.issuer != "" {
		issuer, hasIssuer := claimString(claims, "iss")
		if !hasIssuer || strings.TrimSpace(issuer) != m.issuer {
			return ErrInvalidIssuer
		}
	}

	if len(m.audience) > 0 {
		audience, parseErr := readAudienceClaim(claims["aud"])
		if parseErr != nil || len(audience) == 0 || !hasAudienceMatch(audience, m.audience) {
			return ErrInvalidAudience
		}
	}

	return nil
}

func (m *Manager) markRevoked(jti string, expiresAt time.Time) {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return
	}

	now := m.now().UTC()
	if !expiresAt.IsZero() && now.After(expiresAt) {
		return
	}

	m.revokedMu.Lock()
	defer m.revokedMu.Unlock()

	m.cleanupRevokedLocked(now)
	m.revoked[jti] = expiresAt
}

func (m *Manager) isRevoked(jti string) bool {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return false
	}

	now := m.now().UTC()

	m.revokedMu.Lock()
	defer m.revokedMu.Unlock()

	expiresAt, found := m.revoked[jti]
	if !found {
		m.cleanupRevokedLocked(now)
		return false
	}

	if !expiresAt.IsZero() && now.After(expiresAt) {
		delete(m.revoked, jti)
		return false
	}

	return true
}

func (m *Manager) cleanupRevokedLocked(now time.Time) {
	for jti, expiresAt := range m.revoked {
		if !expiresAt.IsZero() && now.After(expiresAt) {
			delete(m.revoked, jti)
		}
	}
}

type parsedToken struct {
	header       map[string]any
	claims       session.Claims
	signingInput string
	signature    []byte
}

func parseToken(token string) (parsedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return parsedToken{}, fmt.Errorf("%w: expected three JWT segments", ErrInvalidToken)
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return parsedToken{}, fmt.Errorf("%w: invalid header segment", ErrInvalidToken)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return parsedToken{}, fmt.Errorf("%w: invalid payload segment", ErrInvalidToken)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return parsedToken{}, fmt.Errorf("%w: invalid signature segment", ErrInvalidToken)
	}

	header := map[string]any{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return parsedToken{}, fmt.Errorf("%w: invalid header JSON", ErrInvalidToken)
	}

	claims := session.Claims{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return parsedToken{}, fmt.Errorf("%w: invalid payload JSON", ErrInvalidToken)
	}

	return parsedToken{
		header:       header,
		claims:       claims,
		signingInput: parts[0] + "." + parts[1],
		signature:    signature,
	}, nil
}

func encodeAndSignToken(header map[string]any, claims session.Claims, key session.Key) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims

	signature, err := signSignature(signingInput, key)
	if err != nil {
		return "", err
	}

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + encodedSignature, nil
}

func signSignature(signingInput string, key session.Key) ([]byte, error) {
	if len(key.Material) == 0 {
		return nil, ErrMissingSigningKey
	}

	switch key.Algorithm {
	case algorithmHS256:
		mac := hmac.New(sha256.New, key.Material)
		_, _ = mac.Write([]byte(signingInput))
		return mac.Sum(nil), nil
	case algorithmHS384:
		mac := hmac.New(sha512.New384, key.Material)
		_, _ = mac.Write([]byte(signingInput))
		return mac.Sum(nil), nil
	case algorithmHS512:
		mac := hmac.New(sha512.New, key.Material)
		_, _ = mac.Write([]byte(signingInput))
		return mac.Sum(nil), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, key.Algorithm)
	}
}

func verifySignature(signingInput string, signature []byte, key session.Key) error {
	if len(key.Material) == 0 {
		return ErrMissingValidationKey
	}

	expected, err := signSignature(signingInput, key)
	if err != nil {
		return err
	}

	if !hmac.Equal(expected, signature) {
		return fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}

	return nil
}

func validateCustomClaims(claims session.Claims) error {
	for key := range claims {
		switch key {
		case "sub", "iss", "aud", "exp", "nbf", "iat":
			return fmt.Errorf("%w: %s", ErrReservedClaim, key)
		}
	}

	return nil
}

func readTimeClaim(claims session.Claims, claim string, required bool) (time.Time, error) {
	value, found := claims[claim]
	if !found {
		if required {
			return time.Time{}, fmt.Errorf("%w: %s", ErrMissingRequiredClaim, claim)
		}
		return time.Time{}, nil
	}

	seconds, err := readInt64Value(value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid %s claim", ErrInvalidToken, claim)
	}

	return time.Unix(seconds, 0).UTC(), nil
}

func readAudienceClaim(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		aud := strings.TrimSpace(typed)
		if aud == "" {
			return nil, nil
		}
		return []string{aud}, nil
	case []string:
		return normalizeAudience(typed), nil
	case []any:
		audience := make([]string, 0, len(typed))
		for _, raw := range typed {
			text, err := readStringValue(raw)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(text) == "" {
				continue
			}
			audience = append(audience, strings.TrimSpace(text))
		}
		return audience, nil
	default:
		return nil, fmt.Errorf("%w: invalid aud claim", ErrInvalidToken)
	}
}

func hasAudienceMatch(actual []string, expected []string) bool {
	if len(actual) == 0 || len(expected) == 0 {
		return false
	}

	expectedSet := map[string]struct{}{}
	for _, value := range expected {
		expectedSet[value] = struct{}{}
	}

	for _, aud := range actual {
		if _, found := expectedSet[aud]; found {
			return true
		}
	}

	return false
}

func claimString(claims session.Claims, key string) (string, bool) {
	value, ok := claims[key]
	if !ok {
		return "", false
	}

	text, err := readStringValue(value)
	if err != nil {
		return "", false
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return "", false
	}

	return text, true
}

func claimBool(claims session.Claims, key string) (bool, bool) {
	value, ok := claims[key]
	if !ok {
		return false, false
	}

	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err != nil {
			return false, false
		}
		return parsed, true
	default:
		return false, false
	}
}

func readStringValue(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case fmt.Stringer:
		return typed.String(), nil
	default:
		return "", fmt.Errorf("value is not a string")
	}
}

func readInt64Value(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case int:
		return int64(typed), nil
	case float64:
		return int64(typed), nil
	case float32:
		return int64(typed), nil
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return parsed, nil
		}
		parsedFloat, err := typed.Float64()
		if err != nil {
			return 0, err
		}
		return int64(parsedFloat), nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, errors.New("empty string")
		}
		if parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); err == nil {
			return parsed, nil
		}
		parsedFloat, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return 0, err
		}
		return int64(parsedFloat), nil
	default:
		return 0, fmt.Errorf("value is not numeric")
	}
}

func normalizeAudience(audience []string) []string {
	if len(audience) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(audience))
	seen := map[string]struct{}{}

	for _, value := range audience {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	return normalized
}

func normalizeKey(key session.Key) session.Key {
	normalized := key
	normalized.ID = strings.TrimSpace(normalized.ID)
	normalized.Algorithm = strings.ToUpper(strings.TrimSpace(normalized.Algorithm))
	return normalized
}

func isSupportedAlgorithm(algorithm string) bool {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case algorithmHS256, algorithmHS384, algorithmHS512:
		return true
	default:
		return false
	}
}

func cloneClaims(claims session.Claims) session.Claims {
	if len(claims) == 0 {
		return session.Claims{}
	}

	cloned := make(session.Claims, len(claims))
	for key, value := range claims {
		cloned[key] = value
	}

	return cloned
}
