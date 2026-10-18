//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Codex rust-v0.163.0 codex-api/src/common.rs carries access_programs on
// Responses and WebSocket requests. It is absent from compact requests.
func TestCodex0163AccessProgramsSurviveOAuthSanitization(t *testing.T) {
	for _, schema := range []codexOAuthRequestSchema{codexOAuthRequestSchemaResponses, codexOAuthRequestSchemaWebSocketResponseCreate} {
		body, _ := sanitizeCodexOAuthJSONBodyForSchema([]byte(`{"model":"gpt-6.1-sol","access_programs":{"cyber":"standard"},"local_secret":"discard"}`), schema)
		require.Equal(t, "standard", gjson.GetBytes(body, "access_programs.cyber").String())
		require.False(t, gjson.GetBytes(body, "local_secret").Exists())
	}
}

func TestCodex0163CompiledBaselineWithAutoSyncDisabled(t *testing.T) {
	svc := NewSettingService(&codexVersionSettingRepoStub{values: map[string]string{
		SettingKeyOpenAICodexVersionAutoSyncEnabled: "false",
		SettingKeyOpenAICodexClientVersionSynced:    "0.154.0",
	}}, nil)
	require.Equal(t, "0.163.0", svc.GetOpenAICodexClientVersion(context.Background()))
}
