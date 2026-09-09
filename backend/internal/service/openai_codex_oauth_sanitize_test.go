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
		"metadata":{"client":"Pi","unique_marker":"private"},
		"credential_extras":{"source":"private"},
		"client_metadata":{
			"session_id":"session-keep",
			"nested":{"thread_id":"thread-keep","api_key":"sk-leak","device_id":"device-leak","client_id":"client-leak"},
			"unknown_client_marker":"private",
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
			"x-codex-turn-metadata":"{\"session_id\":\"session-keep\",\"window_number\":0,\"context_window_id\":\"019c8c36-4adf-7a04-82b3-bd93a6ed8be0\",\"request_kind\":\"turn\",\"forked_from_ordinal_exclusive\":12,\"turn_trigger\":\"user\",\"sandbox_mode\":\"workspace-write\",\"history_ingest_requested\":true,\"compaction\":{\"trigger\":\"auto\",\"strategy\":\"memento\",\"private\":\"drop\"},\"future_unique\":\"drop\",\"agent_name\":\"/home/user/project\",\"tool_namespaces_info\":{\"private\":{}},\"base_url\":\"https://relay.example\",\"region\":\"CN\",\"device_id\":\"device-leak\",\"app.version\":\"9.9.9\"}"
		}
	}`)

	got, changed := sanitizeCodexOAuthJSONBody(body)
	require.True(t, changed)
	require.Equal(t, "gpt-5.4", gjson.GetBytes(got, "model").String())
	require.Equal(t, "session-keep", gjson.GetBytes(got, "client_metadata.session_id").String())
	for _, path := range []string{
		"base_url",
		"metadata",
		"credential_extras",
		"client_metadata.nested",
		"client_metadata.unknown_client_marker",
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
	require.Zero(t, gjson.Get(turnMetadata, "window_number").Uint())
	require.Equal(t, "019c8c36-4adf-7a04-82b3-bd93a6ed8be0", gjson.Get(turnMetadata, "context_window_id").String())
	require.Equal(t, "turn", gjson.Get(turnMetadata, "request_kind").String())
	require.Equal(t, uint64(12), gjson.Get(turnMetadata, "forked_from_ordinal_exclusive").Uint())
	require.Equal(t, "user", gjson.Get(turnMetadata, "turn_trigger").String())
	require.Equal(t, "workspace-write", gjson.Get(turnMetadata, "sandbox_mode").String())
	require.True(t, gjson.Get(turnMetadata, "history_ingest_requested").Bool())
	require.Equal(t, "auto", gjson.Get(turnMetadata, "compaction.trigger").String())
	require.Equal(t, "memento", gjson.Get(turnMetadata, "compaction.strategy").String())
	require.False(t, gjson.Get(turnMetadata, "compaction.private").Exists())
	require.False(t, gjson.Get(turnMetadata, "future_unique").Exists())
	require.Equal(t, "/root", gjson.Get(turnMetadata, "agent_name").String())
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

func TestSanitizeCodexOAuthJSONBodyForSchemaEnforces01534TopLevelFields(t *testing.T) {
	tests := []struct {
		name          string
		schema        codexOAuthRequestSchema
		body          string
		wantFields    []string
		droppedFields []string
	}{
		{
			name:   "responses",
			schema: codexOAuthRequestSchemaResponses,
			body: `{
				"model":"gpt-5.4","instructions":"test","input":[],"tools":[],
				"tool_choice":"auto","parallel_tool_calls":false,"reasoning":null,
				"store":false,"stream":true,"stream_options":{},"include":[],
				"service_tier":"default","prompt_cache_key":"cache","text":{},
				"client_metadata":{"session_id":"session"},
				"type":"response.create","previous_response_id":"resp_123","generate":true,
				"max_output_tokens":123,"future_field":"drop"
			}`,
			wantFields: []string{
				"model", "instructions", "input", "tools", "tool_choice",
				"parallel_tool_calls", "reasoning", "store", "stream",
				"stream_options", "include", "service_tier", "prompt_cache_key",
				"text", "client_metadata",
			},
			droppedFields: []string{"type", "previous_response_id", "generate", "max_output_tokens", "future_field"},
		},
		{
			name:   "websocket_response_create",
			schema: codexOAuthRequestSchemaWebSocketResponseCreate,
			body: `{
				"type":"response.create","model":"gpt-5.4","input":[],
				"previous_response_id":"resp_123","generate":false,
				"client_metadata":{"session_id":"session"},"background":true,"future_field":"drop"
			}`,
			wantFields:    []string{"type", "model", "input", "previous_response_id", "generate", "client_metadata"},
			droppedFields: []string{"background", "future_field"},
		},
		{
			name:   "compact",
			schema: codexOAuthRequestSchemaCompact,
			body: `{
				"model":"gpt-5.4","input":[],"instructions":"test","tools":[],
				"parallel_tool_calls":false,"reasoning":null,"service_tier":"default",
				"prompt_cache_key":"cache","text":{},
				"tool_choice":"auto","store":false,"stream":false,"include":[],
				"client_metadata":{"session_id":"session"},"previous_response_id":"resp_123"
			}`,
			wantFields: []string{
				"model", "input", "instructions", "tools", "parallel_tool_calls",
				"reasoning", "service_tier", "prompt_cache_key", "text",
			},
			droppedFields: []string{"tool_choice", "store", "stream", "include", "client_metadata", "previous_response_id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := sanitizeCodexOAuthJSONBodyForSchema([]byte(tt.body), tt.schema)
			require.True(t, changed)
			for _, field := range tt.wantFields {
				require.True(t, gjson.GetBytes(got, field).Exists(), field)
			}
			for _, field := range tt.droppedFields {
				require.False(t, gjson.GetBytes(got, field).Exists(), field)
			}
		})
	}
}

func TestSanitizeCodexOAuthJSONBodyForSchemaPreservesNestedPayloads(t *testing.T) {
	body := []byte(`{
		"model":"gpt-5.4",
		"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello","vendor_extension":{"keep":true}}]}],
		"tools":[{"type":"function","name":"lookup","parameters":{"type":"object","properties":{"future":{"type":"string","x-vendor":"keep"}}}}],
		"future_top_level":"drop"
	}`)

	got, changed := sanitizeCodexOAuthJSONBodyForSchema(body, codexOAuthRequestSchemaResponses)
	require.True(t, changed)
	require.False(t, gjson.GetBytes(got, "future_top_level").Exists())
	require.True(t, gjson.GetBytes(got, "input.0.content.0.vendor_extension.keep").Bool())
	require.Equal(t, "keep", gjson.GetBytes(got, "tools.0.parameters.properties.future.x-vendor").String())
}

func TestSanitizeCodexOAuthJSONBodyDropsInvalidClientMetadataShape(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","client_metadata":"Pi/private-marker","Client_Metadata":{"session_id":"case-marker"},"x-codex-turn-metadata":"{\"session_id\":\"top-level-marker\"}"}`)
	got, changed := sanitizeCodexOAuthJSONBody(body)
	require.True(t, changed)
	require.False(t, gjson.GetBytes(got, "client_metadata").Exists())
	require.False(t, gjson.GetBytes(got, "Client_Metadata").Exists())
	require.False(t, gjson.GetBytes(got, "x-codex-turn-metadata").Exists())
}

func TestSanitizeCodexOAuthJSONBodyClientFixtures(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantChanged bool
	}{
		{
			name:        "official_codex",
			body:        `{"model":"gpt-5.4","client_metadata":{"x-codex-installation-id":"install","session_id":"session","thread_id":"thread","turn_id":"turn","x-codex-window-id":"thread:0","x-codex-turn-state":"state","x-codex-ws-stream-request-start-ms":"1787389200123","ws_request_header_x_openai_internal_codex_responses_lite":"true","x-codex-turn-metadata":"{\"session_id\":\"session\",\"thread_id\":\"thread\",\"turn_id\":\"turn\",\"request_kind\":\"turn\"}"}}`,
			wantChanged: false,
		},
		{
			name:        "pi",
			body:        `{"model":"gpt-5.4","client_metadata":{"session_id":"session","client":"pi","runtime":"node","cwd":"/private/pi"}}`,
			wantChanged: true,
		},
		{
			name:        "opencode",
			body:        `{"model":"gpt-5.4","metadata":{"client":"opencode"},"client_metadata":{"session_id":"session","opencode_version":"private"}}`,
			wantChanged: true,
		},
		{
			name:        "cliproxyapi_minimal",
			body:        `{"model":"gpt-5.4","stream":true,"input":"hello"}`,
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := sanitizeCodexOAuthJSONBody([]byte(tt.body))
			require.Equal(t, tt.wantChanged, changed)
			require.Equal(t, "gpt-5.4", gjson.GetBytes(got, "model").String())
			require.False(t, gjson.GetBytes(got, "metadata").Exists())
			require.False(t, gjson.GetBytes(got, "client_metadata.client").Exists())
			require.False(t, gjson.GetBytes(got, "client_metadata.runtime").Exists())
			require.False(t, gjson.GetBytes(got, "client_metadata.cwd").Exists())
			require.False(t, gjson.GetBytes(got, "client_metadata.opencode_version").Exists())
		})
	}
}

func TestSanitizeCodexOAuthJSONBodyValidatesOfficialWSMetadataValues(t *testing.T) {
	body := []byte(`{"model":"gpt-5.4","client_metadata":{"session_id":"session","x-codex-turn-state":"state","x-codex-ws-stream-request-start-ms":"not-a-timestamp","ws_request_header_x_openai_internal_codex_responses_lite":"yes"}}`)

	got, changed := sanitizeCodexOAuthJSONBody(body)
	require.True(t, changed)
	require.Equal(t, "session", gjson.GetBytes(got, "client_metadata.session_id").String())
	require.Equal(t, "state", gjson.GetBytes(got, "client_metadata.x-codex-turn-state").String())
	require.False(t, gjson.GetBytes(got, "client_metadata.x-codex-ws-stream-request-start-ms").Exists())
	require.False(t, gjson.GetBytes(got, "client_metadata.ws_request_header_x_openai_internal_codex_responses_lite").Exists())
}

func TestSanitizeCodexOAuthJSONBodyPreservesValidated01534WSTraceMetadata(t *testing.T) {
	const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	body := []byte(`{"model":"gpt-5.4","client_metadata":{"ws_request_header_traceparent":"` + traceparent + `","ws_request_header_tracestate":"vendor=value"}}`)

	got, changed := sanitizeCodexOAuthJSONBody(body)
	require.False(t, changed)
	require.Equal(t, traceparent, gjson.GetBytes(got, "client_metadata.ws_request_header_traceparent").String())
	require.Equal(t, "vendor=value", gjson.GetBytes(got, "client_metadata.ws_request_header_tracestate").String())

	invalid := []byte(`{"model":"gpt-5.4","client_metadata":{"ws_request_header_traceparent":"00-private","ws_request_header_tracestate":"bad\nvalue"}}`)
	got, changed = sanitizeCodexOAuthJSONBody(invalid)
	require.True(t, changed)
	require.False(t, gjson.GetBytes(got, "client_metadata.ws_request_header_traceparent").Exists())
	require.False(t, gjson.GetBytes(got, "client_metadata.ws_request_header_tracestate").Exists())
}

func TestCodex01534TUIStripsUnavailableAttestationHeader(t *testing.T) {
	require.False(t, openaiAllowedHeaders["x-oai-attestation"])
	require.False(t, openaiPassthroughAllowedHeaders["x-oai-attestation"])
}

func TestBuildOpenAIWSCreatePayloadSanitizesOnlyOAuth(t *testing.T) {
	svc := &OpenAIGatewayService{}
	request := map[string]any{
		"model":            "gpt-5.4",
		"future_top_level": "drop-for-oauth",
		"client_metadata": map[string]any{
			"session_id":  "session-keep",
			"base_url":    "https://relay.example",
			"device_id":   "device-leak",
			"app.version": "9.9.9",
		},
	}

	oauthPayload := svc.buildOpenAIWSCreatePayload(request, &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth})
	oauthMetadata, ok := oauthPayload["client_metadata"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "session-keep", oauthMetadata["session_id"])
	require.NotContains(t, oauthMetadata, "base_url")
	require.NotContains(t, oauthMetadata, "device_id")
	require.NotContains(t, oauthMetadata, "app.version")
	require.NotContains(t, oauthPayload, "future_top_level")

	apiKeyPayload := svc.buildOpenAIWSCreatePayload(request, &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey})
	apiKeyMetadata, ok := apiKeyPayload["client_metadata"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "https://relay.example", apiKeyMetadata["base_url"])
	require.Equal(t, "device-leak", apiKeyMetadata["device_id"])
	require.Equal(t, "9.9.9", apiKeyMetadata["app.version"])
	require.Equal(t, "drop-for-oauth", apiKeyPayload["future_top_level"])
}

func TestSanitizeCodexOAuthTurnMetadataDropsOpaqueSensitiveValue(t *testing.T) {
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`opaque timezone=Asia/Shanghai`))
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`opaque workspace=/home/user/project`))
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`opaque sandbox=workspace-write`))
}

func TestSanitizeCodexOAuthTurnMetadataRejectsInvalid01534FieldTypes(t *testing.T) {
	metadata := sanitizeCodexOAuthTurnMetadataString(`{"session_id":"session-keep","window_number":-1,"forked_from_ordinal_exclusive":1.5,"history_ingest_requested":"true"}`)
	require.Equal(t, "session-keep", gjson.Get(metadata, "session_id").String())
	require.False(t, gjson.Get(metadata, "window_number").Exists())
	require.False(t, gjson.Get(metadata, "forked_from_ordinal_exclusive").Exists())
	require.False(t, gjson.Get(metadata, "history_ingest_requested").Exists())
}

func TestSanitizeCodexOAuthTurnMetadataHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set(openAIWSTurnMetadataHeader, `{"session_id":"session-keep","timezone":"Asia/Shanghai","base_url":"https://relay.example","future_unique":"private"}`)

	require.True(t, sanitizeCodexOAuthTurnMetadataHeader(headers))
	metadata := headers.Get(openAIWSTurnMetadataHeader)
	require.Equal(t, "session-keep", gjson.Get(metadata, "session_id").String())
	require.False(t, gjson.Get(metadata, "timezone").Exists())
	require.False(t, gjson.Get(metadata, "base_url").Exists())
	require.False(t, gjson.Get(metadata, "future_unique").Exists())
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
