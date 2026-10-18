//go:build unit

package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/stretchr/testify/require"
)

func openAIRecoveryJWT(exp time.Time) string {
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix()))) + ".test"
}

func openAIRecoveryAccount() *Account {
	return &Account{ID: 818, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive,
		Credentials: map[string]any{"access_token": "old-access", "refresh_token": "old-refresh", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}}
}

type openAIRecoveryClient struct {
	OpenAIOAuthClient
	calls    int
	err      error
	response *openai.TokenResponse
}

func (s *openAIRecoveryClient) RefreshTokenWithClientID(_ context.Context, refreshToken, _, _ string) (*openai.TokenResponse, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.response != nil {
		return s.response, nil
	}
	return &openai.TokenResponse{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 3600}, nil
}

func TestOpenAITokenRecovery_ResponseWithoutExpiresInUsesJWT(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	client := &openAIRecoveryClient{response: &openai.TokenResponse{AccessToken: openAIRecoveryJWT(expiresAt), RefreshToken: "new-refresh"}}
	oauth := NewOpenAIOAuthService(nil, client)
	defer oauth.Stop()
	info, err := oauth.RefreshAccountToken(context.Background(), openAIRecoveryAccount())
	require.NoError(t, err)
	require.Equal(t, expiresAt.Unix(), info.ExpiresAt)
}

func TestOpenAITokenRecovery_MissingOrIncorrectExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		expiry any
		token  string
		want   bool
	}{
		{"missing opaque expiry", nil, "opaque", true},
		{"malformed expiry", "invalid", "opaque", true},
		{"expired JWT without metadata", nil, openAIRecoveryJWT(time.Now().Add(-time.Hour)), true},
		{"expired JWT with future metadata", time.Now().Add(time.Hour).Format(time.RFC3339), openAIRecoveryJWT(time.Now().Add(-time.Hour)), true},
		{"valid JWT without metadata", nil, openAIRecoveryJWT(time.Now().Add(time.Hour)), false},
		{"metadata earlier than JWT", time.Now().Add(-time.Hour).Format(time.RFC3339), openAIRecoveryJWT(time.Now().Add(time.Hour)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := openAIRecoveryAccount()
			a.Credentials["access_token"] = tc.token
			a.Credentials["expires_at"] = tc.expiry
			require.Equal(t, tc.want, NewOpenAITokenRefresher(nil, nil).NeedsRefresh(a, 3*time.Minute))
		})
	}
}

func TestOpenAITokenRecovery_Expired401TriggersLockedRefresh(t *testing.T) {
	for _, body := range []string{
		`{"detail":{"code":"token_expired","message":"Your authentication token has expired. Please try refreshing it."},"error":{"code":"token_expired","type":"invalid_request_error"},"status":401}`,
		`{"detail":{"code":"token_expired","message":"Please try refreshing it."}}`,
	} {
		t.Run(body, func(t *testing.T) {
			ctx := context.Background()
			a := openAIRecoveryAccount()
			rateRepo := &rateLimitAccountRepoStub{}
			rateSvc := NewRateLimitService(rateRepo, nil, &config.Config{}, nil, nil)
			require.True(t, rateSvc.HandleUpstreamError(ctx, a, http.StatusUnauthorized, nil, []byte(body)))
			require.Zero(t, rateRepo.setErrorCalls)
			require.Zero(t, rateRepo.updateCredentialsCalls, "401 must not overwrite rotated credentials")
			require.Equal(t, 1, rateRepo.updateExtraCalls)
			a.Extra = rateRepo.lastExtraUpdates
			require.True(t, NewOpenAITokenRefresher(nil, nil).NeedsRefresh(a, 3*time.Minute), "upstream expiry overrides local future expires_at")

			repo := &refreshAPIAccountRepo{account: a}
			cache := newOpenAITokenCacheStub()
			cache.tokens[OpenAITokenCacheKey(a)] = "old-access"
			client := &openAIRecoveryClient{}
			oauth := NewOpenAIOAuthService(nil, client)
			defer oauth.Stop()
			executor := NewOpenAITokenRefresher(oauth, repo)
			provider := NewOpenAITokenProvider(repo, cache, oauth)
			provider.SetRefreshAPI(NewOAuthRefreshAPI(repo, cache), executor)
			token, err := provider.GetAccessToken(ctx, a)
			require.NoError(t, err)
			require.Equal(t, "new-access", token)
			require.Equal(t, "new-refresh", repo.account.GetOpenAIRefreshToken())
			require.Equal(t, 1, client.calls)
			require.False(t, executor.NeedsRefresh(repo.account, 3*time.Minute), "successful rotation satisfies the durable refresh request")
			_, err = provider.GetAccessToken(ctx, repo.account)
			require.NoError(t, err)
			require.Equal(t, 1, client.calls, "do not refresh repeatedly after recovery")
		})
	}
}

func TestOpenAITokenRecovery_MissingExpiryRefreshesThroughRealExecutor(t *testing.T) {
	a := openAIRecoveryAccount()
	delete(a.Credentials, "expires_at")
	repo := &refreshAPIAccountRepo{account: a}
	client := &openAIRecoveryClient{}
	oauth := NewOpenAIOAuthService(nil, client)
	defer oauth.Stop()
	provider := NewOpenAITokenProvider(repo, nil, oauth)
	provider.SetRefreshAPI(NewOAuthRefreshAPI(repo, nil), NewOpenAITokenRefresher(oauth, repo))
	token, err := provider.GetAccessToken(context.Background(), a)
	require.NoError(t, err)
	require.Equal(t, "new-access", token)
	require.Equal(t, 1, client.calls)
}

func TestOpenAITokenRecovery_ExpiredTokensNeverReturnedOrCached(t *testing.T) {
	for _, lockHeld := range []bool{false, true} {
		t.Run(fmt.Sprint(lockHeld), func(t *testing.T) {
			a := openAIRecoveryAccount()
			a.Credentials["access_token"] = openAIRecoveryJWT(time.Now().Add(-time.Hour))
			repo := &refreshAPIAccountRepo{account: a}
			cache := newOpenAITokenCacheStub()
			cache.lockAcquired = !lockHeld
			cache.tokens[OpenAITokenCacheKey(a)] = a.GetOpenAIAccessToken()
			client := &openAIRecoveryClient{err: errors.New("temporary refresh outage")}
			oauth := NewOpenAIOAuthService(nil, client)
			defer oauth.Stop()
			provider := NewOpenAITokenProvider(repo, cache, oauth)
			provider.SetRefreshAPI(NewOAuthRefreshAPI(repo, cache), NewOpenAITokenRefresher(oauth, repo))
			token, err := provider.GetAccessToken(context.Background(), a)
			require.Error(t, err)
			require.Empty(t, token)
			require.Zero(t, cache.setCalled, "never extend an expired token's TTL")
		})
	}
}

func TestOpenAITokenRecovery_RefreshMarkerDoesNotInvalidateNewerRotation(t *testing.T) {
	a := openAIRecoveryAccount()
	requestedAt := time.Now().Add(-time.Minute).UnixMilli()
	a.Extra = map[string]any{openAITokenRefreshRequestedAtKey: strconv.FormatInt(requestedAt, 10)}
	a.Credentials["_token_version"] = requestedAt + 1
	require.False(t, NewOpenAITokenRefresher(nil, nil).NeedsRefresh(a, 3*time.Minute))
}

func TestOpenAITokenRecovery_BackgroundClearsSchedulerCooldown(t *testing.T) {
	a := openAIRecoveryAccount()
	until := time.Now().Add(10 * time.Minute)
	a.TempUnschedulableUntil = &until
	a.TempUnschedulableReason = "OAuth 401: token_expired"
	a.Extra = map[string]any{openAITokenRefreshRequestedAtKey: strconv.FormatInt(time.Now().UnixMilli(), 10)}
	repo := &tokenRefreshAccountRepo{}
	repo.accountsByID = map[int64]*Account{a.ID: a}
	client := &openAIRecoveryClient{}
	oauth := NewOpenAIOAuthService(nil, client)
	defer oauth.Stop()
	cache := &tokenRefreshSchedulerCache{}
	svc := NewTokenRefreshService(repo, nil, oauth, nil, nil, nil, nil, &config.Config{}, nil)
	svc.schedulerCache = cache
	svc.SetRefreshAPI(NewOAuthRefreshAPI(repo, nil))
	refresher := NewOpenAITokenRefresher(oauth, repo)
	require.NoError(t, svc.refreshWithRetry(context.Background(), a, refresher, refresher, 3*time.Minute))
	require.Equal(t, 1, client.calls)
	require.Equal(t, 1, repo.clearTempCalls)
	require.Equal(t, 1, cache.setAccountCalls)
	require.Nil(t, cache.lastAccount.TempUnschedulableUntil)
	require.Empty(t, cache.lastAccount.TempUnschedulableReason)
	require.Equal(t, "new-access", cache.lastAccount.GetOpenAIAccessToken())
}
