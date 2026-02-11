package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/porthorian/openauth"
	"github.com/porthorian/openauth/pkg/session"
)

type authRequest struct {
	UserID string `json:"user_id"`
	Token  string `json:"token"`
}

type authResponse struct {
	Subject     string `json:"subject"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type hmacTokenIssuer struct {
	secret []byte
}

func (h *hmacTokenIssuer) IssueToken(ctx context.Context, subject string, claims session.Claims, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	headerJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}

	payload := map[string]any{
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}

	for key, value := range claims {
		payload[key] = value
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := fmt.Sprintf("%s.%s", headerPart, payloadPart)

	mac := hmac.New(sha256.New, h.secret)
	if _, err := mac.Write([]byte(signingInput)); err != nil {
		return "", err
	}

	signaturePart := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", signingInput, signaturePart), nil
}

type restAuthenticator struct {
}

func (r *restAuthenticator) AuthPassword(ctx context.Context, input openauth.PasswordInput) (openauth.Principal, error) {
	return openauth.Principal{}, errors.New("not implemented")
}

func (r *restAuthenticator) AuthToken(ctx context.Context, input openauth.TokenInput) (openauth.Principal, error) {
	if input.UserID == "" || input.Token == "" {
		return openauth.Principal{}, errors.New("missing user_id or token")
	}

	if input.Token != "user-supplied-proof" {
		return openauth.Principal{}, errors.New("invalid token")
	}

	return openauth.Principal{
		Subject:         input.UserID,                         // Subject identifies who was authenticated, so every downstream check uses the same stable identity key.
		Tenant:          "default",                            // Tenant scopes access decisions, which prevents accidental cross-tenant authorization.
		RoleMask:        1,                                    // RoleMask encodes coarse role membership for fast bitwise role checks.
		PermissionMask:  1,                                    // PermissionMask carries direct grants so handlers can enforce least-privilege rules quickly.
		Claims:          openauth.Claims{"tenant": "default"}, // Claims carries contextual identity attributes that can be forwarded into issued tokens and audit logs.
		AuthenticatedAt: time.Now().UTC(),                     // AuthenticatedAt records auth time so freshness/TTL and audit policies can be enforced.
	}, nil
}

func (r *restAuthenticator) ValidateToken(ctx context.Context, token string) (openauth.Principal, error) {
	return openauth.Principal{}, errors.New("not implemented")
}

func main() {
	issuer := &hmacTokenIssuer{secret: []byte("example-secret")}

	client, err := openauth.New(&restAuthenticator{}, openauth.Config{})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/auth", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var body authRequest
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		principal, err := client.AuthToken(req.Context(), openauth.TokenInput{
			UserID: body.UserID,
			Token:  body.Token,
		})
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		accessToken, err := issuer.IssueToken(req.Context(), principal.Subject, session.Claims{
			"tenant": principal.Tenant,
		}, 15*time.Minute)
		if err != nil {
			http.Error(w, "token issuance failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authResponse{
			Subject:     principal.Subject,
			AccessToken: accessToken,
			TokenType:   "Bearer",
		})
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
