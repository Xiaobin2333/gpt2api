package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestSanitizeCodexOAuthJSONBodyStripsLocalIdentityMetadata(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.4",
		"base_url":"https://relay.example",
		"client_metadata":{
			"session_id":"session-keep",
			"nested":{"thread_id":"thread-keep","api_key":"sk-leak"},
			"authorization":"Bearer leak",
			"timezone":"Asia/Shanghai",
			"x-codex-turn-metadata":"{\"session_id\":\"session-keep\",\"request_kind\":\"turn\",\"base_url\":\"https://relay.example\",\"region\":\"CN\"}"
		}
	}`)

	got, changed := sanitizeCodexOAuthJSONBody(body)
	require.True(t, changed)
	require.Equal(t, "gpt-5.4", gjson.GetBytes(got, "model").String())
	require.Equal(t, "session-keep", gjson.GetBytes(got, "client_metadata.session_id").String())
	require.Equal(t, "thread-keep", gjson.GetBytes(got, "client_metadata.nested.thread_id").String())
	for _, path := range []string{
		"base_url",
		"client_metadata.nested.api_key",
		"client_metadata.authorization",
		"client_metadata.timezone",
	} {
		require.False(t, gjson.GetBytes(got, path).Exists(), path)
	}
	turnMetadata := gjson.GetBytes(got, "client_metadata.x-codex-turn-metadata").String()
	require.Equal(t, "session-keep", gjson.Get(turnMetadata, "session_id").String())
	require.Equal(t, "turn", gjson.Get(turnMetadata, "request_kind").String())
	require.False(t, gjson.Get(turnMetadata, "base_url").Exists())
	require.False(t, gjson.Get(turnMetadata, "region").Exists())
}

func TestSanitizeCodexOAuthJSONBodyPreservesInvalidOrUnchangedBody(t *testing.T) {
	invalid := []byte(`{"model":`)
	got, changed := sanitizeCodexOAuthJSONBody(invalid)
	require.False(t, changed)
	require.Equal(t, invalid, got)

	clean := []byte(`{"model":"gpt-5.4","client_metadata":{"session_id":"session-keep"}}`)
	got, changed = sanitizeCodexOAuthJSONBody(clean)
	require.False(t, changed)
	require.Equal(t, clean, got)
}

func TestBuildOpenAIWSCreatePayloadSanitizesOnlyOAuth(t *testing.T) {
	svc := &OpenAIGatewayService{}
	request := map[string]any{
		"model": "gpt-5.4",
		"client_metadata": map[string]any{
			"session_id": "session-keep",
			"base_url":   "https://relay.example",
		},
	}

	oauthPayload := svc.buildOpenAIWSCreatePayload(request, &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth})
	oauthMetadata := oauthPayload["client_metadata"].(map[string]any)
	require.Equal(t, "session-keep", oauthMetadata["session_id"])
	require.NotContains(t, oauthMetadata, "base_url")

	apiKeyPayload := svc.buildOpenAIWSCreatePayload(request, &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey})
	apiKeyMetadata := apiKeyPayload["client_metadata"].(map[string]any)
	require.Equal(t, "https://relay.example", apiKeyMetadata["base_url"])
}

func TestSanitizeCodexOAuthTurnMetadataDropsOpaqueSensitiveValue(t *testing.T) {
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`opaque timezone=Asia/Shanghai`))
	require.Equal(t, "opaque sandbox=workspace-write", sanitizeCodexOAuthTurnMetadataString(`opaque sandbox=workspace-write`))
}

func TestSanitizeCodexOAuthTurnMetadataHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set(openAIWSTurnMetadataHeader, `{"session_id":"session-keep","timezone":"Asia/Shanghai","base_url":"https://relay.example"}`)

	require.True(t, sanitizeCodexOAuthTurnMetadataHeader(headers))
	metadata := headers.Get(openAIWSTurnMetadataHeader)
	require.Equal(t, "session-keep", gjson.Get(metadata, "session_id").String())
	require.False(t, gjson.Get(metadata, "timezone").Exists())
	require.False(t, gjson.Get(metadata, "base_url").Exists())
}
