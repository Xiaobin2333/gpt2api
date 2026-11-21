//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Codex rust-v0.166.0 codex-api/src/common.rs carries access_programs on
// Responses and WebSocket requests. It is absent from compact requests.
func TestCodex0166AccessProgramsSurviveOAuthSanitization(t *testing.T) {
	for _, schema := range []codexOAuthRequestSchema{codexOAuthRequestSchemaResponses, codexOAuthRequestSchemaWebSocketResponseCreate} {
		body, _ := sanitizeCodexOAuthJSONBodyForSchema([]byte(`{"model":"gpt-6.1-sol","access_programs":{"cyber":"standard"},"local_secret":"discard"}`), schema)
		require.Equal(t, "standard", gjson.GetBytes(body, "access_programs.cyber").String())
		require.False(t, gjson.GetBytes(body, "local_secret").Exists())
	}
}

func TestCodexStableCompiledBaselineWithAutoSyncDisabled(t *testing.T) {
	svc := NewSettingService(&codexVersionSettingRepoStub{values: map[string]string{
		SettingKeyOpenAICodexVersionAutoSyncEnabled: "false",
		SettingKeyOpenAICodexClientVersionSynced:    "0.166.0",
	}}, nil)
	require.Equal(t, "0.171.0", svc.GetOpenAICodexClientVersion(context.Background()))
}

func TestCodex0171PromptCacheOptions(t *testing.T) {
	for _, schema := range []codexOAuthRequestSchema{codexOAuthRequestSchemaResponses, codexOAuthRequestSchemaWebSocketResponseCreate, codexOAuthRequestSchemaCompact} {
		for _, ttl := range []string{"30m", "12h", "unsupported"} {
			body, _ := sanitizeCodexOAuthJSONBodyForSchema([]byte(`{"prompt_cache_options":{"ttl":"`+ttl+`","local_secret":true},"request_country":null}`), schema)
			require.False(t, gjson.GetBytes(body, "request_country").Exists())
			if schema == codexOAuthRequestSchemaCompact || ttl == "unsupported" {
				require.False(t, gjson.GetBytes(body, "prompt_cache_options").Exists())
			} else {
				require.JSONEq(t, `{"ttl":"`+ttl+`"}`, gjson.GetBytes(body, "prompt_cache_options").Raw)
			}
		}
	}
}

func TestCodex0166GuardianMetadata(t *testing.T) {
	valid := sanitizeCodexOAuthTurnMetadataString(`{"guardian_recorded_items":true,"parent_routing_affinity":"transport-only","local_secret":"discard"}`)
	require.JSONEq(t, `{"guardian_recorded_items":true}`, valid)
	require.Empty(t, sanitizeCodexOAuthTurnMetadataString(`{"guardian_recorded_items":"true"}`))
	encoded, err := marshalCodexTurnMetadata(map[string]any{"session_id": "session", "guardian_recorded_items": true})
	require.NoError(t, err)
	require.Equal(t, `{"guardian_recorded_items":true,"session_id":"session"}`, encoded)
}
