package service

import (
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
)

const openAITokenRefreshRequestedAtKey = "openai_token_refresh_requested_at"

// JWT exp is only an expiry hint for stored upstream credentials, never an
// authentication decision. Prefer the earlier deadline when imported metadata
// and the access token disagree; opaque tokens still use expires_at.
func openAIAccessTokenExpiry(token string) *time.Time {
	claims, err := openai.DecodeIDToken(strings.TrimSpace(token))
	if err != nil || claims.Exp <= 0 {
		return nil
	}
	expiresAt := time.Unix(claims.Exp, 0)
	return &expiresAt
}

func openAIResponseTokenExpiry(token string, expiresIn int64) int64 {
	var deadline int64
	if expiresIn > 0 {
		deadline = time.Now().Unix() + expiresIn
	}
	if jwtExpiry := openAIAccessTokenExpiry(token); jwtExpiry != nil && (deadline == 0 || jwtExpiry.Unix() < deadline) {
		deadline = jwtExpiry.Unix()
	}
	return deadline
}

func openAITokenExpiry(account *Account) *time.Time {
	expiresAt := account.GetCredentialAsTime("expires_at")
	if jwtExpiry := openAIAccessTokenExpiry(account.GetOpenAIAccessToken()); jwtExpiry != nil && (expiresAt == nil || jwtExpiry.Before(*expiresAt)) {
		return jwtExpiry
	}
	return expiresAt
}

// A recoverable upstream rejection requests one durable refresh even if the
// local expiry is missing or wrong. The locked refresh API writes _token_version
// after rotation, satisfying older requests without rewriting credentials in
// the 401 handler or continually refreshing a successfully rotated token.
func openAITokenRefreshRequested(account *Account) bool {
	if account == nil || account.Extra == nil {
		return false
	}
	value, _ := account.Extra[openAITokenRefreshRequestedAtKey].(string)
	requestedAt, _ := strconv.ParseInt(value, 10, 64)
	return requestedAt > 0 && requestedAt > account.GetCredentialAsInt64("_token_version")
}

func openAITokenCanBeUsed(account *Account, token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	if account.IsOpenAIPersonalAccessToken() {
		return true
	}
	if openAITokenRefreshRequested(account) {
		return false
	}
	expiresAt := openAIAccessTokenExpiry(token)
	if token == account.GetOpenAIAccessToken() {
		expiresAt = openAITokenExpiry(account)
	}
	return expiresAt == nil || time.Now().Before(*expiresAt)
}
