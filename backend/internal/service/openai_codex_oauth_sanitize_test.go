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
			"nested":{"thread_id":"thread-keep","api_key":"sk-leak","device_id":"device-leak","client_id":"client-leak"},
			"authorization":"Bearer leak",
			"timezone":"Asia/Shanghai",
			"runtime":"node",
			"runtime_version":"24.0.0",
			"app.version":"9.9.9",
			"os":"local-os",
			"architecture":"local-arch",
			"cwd":"/home/user/project",
			"workspace":{"root":"/home/user/project"},
			"git":{"branch":"feature/local","remote_url":"ssh://private/repo"},
			"terminal":"private-terminal",
			"plugins":["private-plugin"],
			"skills":["private-skill"],
			"mcp_servers":{"private":{"url":"http://127.0.0.1:9000"}},
			"trace_id":"local-trace",
			"telemetry":{"app_version":"9.9.9"},
			"x-codex-turn-metadata":"{\"session_id\":\"session-keep\",\"request_kind\":\"turn\",\"sandbox_mode\":\"workspace-write\",\"agent_name\":\"/home/user/project\",\"tool_namespaces_info\":{\"private\":{}},\"base_url\":\"https://relay.example\",\"region\":\"CN\",\"device_id\":\"device-leak\",\"app.version\":\"9.9.9\"}"
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
		"client_metadata.nested.device_id",
		"client_metadata.nested.client_id",
		"client_metadata.authorization",
		"client_metadata.timezone",
		"client_metadata.runtime",
		"client_metadata.runtime_version",
		"client_metadata.app\\.version",
		"client_metadata.os",
		"client_metadata.architecture",
		"client_metadata.cwd",
		"client_metadata.workspace",
		"client_metadata.git",
		"client_metadata.terminal",
		"client_metadata.plugins",
		"client_metadata.skills",
		"client_metadata.mcp_servers",
		"client_metadata.trace_id",
		"client_metadata.telemetry",
	} {
		require.False(t, gjson.GetBytes(got, path).Exists(), path)
	}
	turnMetadata := gjson.GetBytes(got, "client_metadata.x-codex-turn-metadata").String()
	require.Equal(t, "session-keep", gjson.Get(turnMetadata, "session_id").String())
	require.Equal(t, "turn", gjson.Get(turnMetadata, "request_kind").String())
	require.Equal(t, "workspace-write", gjson.Get(turnMetadata, "sandbox_mode").String())
	require.False(t, gjson.Get(turnMetadata, "agent_name").Exists())
	require.False(t, gjson.Get(turnMetadata, "tool_namespaces_info").Exists())
	require.False(t, gjson.Get(turnMetadata, "base_url").Exists())
	require.False(t, gjson.Get(turnMetadata, "region").Exists())
	require.False(t, gjson.Get(turnMetadata, "device_id").Exists())
	require.False(t, gjson.Get(turnMetadata, "app\\.version").Exists())
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
			"session_id":  "session-keep",
			"base_url":    "https://relay.example",
			"device_id":   "device-leak",
			"app.version": "9.9.9",
		},
	}

	oauthPayload := svc.buildOpenAIWSCreatePayload(request, &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth})
	oauthMetadata := oauthPayload["client_metadata"].(map[string]any)
	require.Equal(t, "session-keep", oauthMetadata["session_id"])
	require.NotContains(t, oauthMetadata, "base_url")
	require.NotContains(t, oauthMetadata, "device_id")
	require.NotContains(t, oauthMetadata, "app.version")

	apiKeyPayload := svc.buildOpenAIWSCreatePayload(request, &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey})
	apiKeyMetadata := apiKeyPayload["client_metadata"].(map[string]any)
	require.Equal(t, "https://relay.example", apiKeyMetadata["base_url"])
	require.Equal(t, "device-leak", apiKeyMetadata["device_id"])
	require.Equal(t, "9.9.9", apiKeyMetadata["app.version"])
}

func TestSanitizeCodexOAuthTurnMetadataDropsOpaqueSensitiveValue(t *testing.T) {
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`opaque timezone=Asia/Shanghai`))
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`opaque workspace=/home/user/project`))
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

func TestSanitizeCodexOAuthOutboundHeaders(t *testing.T) {
	headers := http.Header{
		"Accept-Language":       []string{"zh-CN"},
		"Cookie":                []string{"session=private"},
		"Traceparent":           []string{"00-private"},
		"Tracestate":            []string{"vendor=private"},
		"Baggage":               []string{"workspace=private"},
		"X-Stainless-Timeout":   []string{"120000"},
		"X-Codex-Attestation":   []string{"private"},
		"X-Oai-Attestation":     []string{"live-required"},
		"X-Codex-Turn-State":    []string{"opaque-state"},
		"X-Codex-Beta-Features": []string{"client-feature"},
	}

	require.True(t, sanitizeCodexOAuthOutboundHeaders(headers))
	for _, name := range []string{
		"Accept-Language", "Cookie", "Traceparent", "Tracestate", "Baggage",
		"X-Stainless-Timeout", "X-Codex-Attestation",
	} {
		require.Empty(t, headers.Get(name), name)
	}
	require.Equal(t, "live-required", headers.Get("X-Oai-Attestation"))
	require.Equal(t, "opaque-state", headers.Get("X-Codex-Turn-State"))
	require.Equal(t, "client-feature", headers.Get("X-Codex-Beta-Features"))
}
