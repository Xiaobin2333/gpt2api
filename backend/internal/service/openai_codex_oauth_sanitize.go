package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// sanitizeCodexOAuthJSONBody removes client-local routing, credential, and
// location fields from an OpenAI OAuth request body. Callers are responsible
// for applying the OAuth account gate before invoking this helper.
func sanitizeCodexOAuthJSONBody(body []byte) ([]byte, bool) {
	if len(body) == 0 || !json.Valid(body) {
		return body, false
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil || payload == nil {
		return body, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return body, false
	}
	if !sanitizeCodexOAuthRequestMap(payload) {
		return body, false
	}
	next, err := json.Marshal(payload)
	if err != nil {
		return body, false
	}
	return next, true
}

// sanitizeCodexOAuthRequestMap is deliberately narrow: top-level transport
// hints are removed, while recursive filtering is limited to metadata-bearing
// objects so tool schemas and user content retain their original semantics.
func sanitizeCodexOAuthRequestMap(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	changed := sanitizeCodexOAuthBlockedKeys(payload)
	for key, value := range payload {
		switch normalizeCodexOAuthFieldName(key) {
		case "metadata", "credential_extras", "credentials", "x_codex_turn_metadata":
			delete(payload, key)
			changed = true
		case "client_metadata":
			if key != "client_metadata" {
				delete(payload, key)
				changed = true
				continue
			}
			child, ok := codexOAuthStringMap(value)
			if !ok {
				delete(payload, key)
				changed = true
				continue
			}
			childChanged := sanitizeCodexOAuthClientMetadataMap(child)
			if len(child) == 0 {
				delete(payload, key)
				changed = true
			} else if childChanged {
				payload[key] = child
				changed = true
			}
		}
	}
	return changed
}

var codexOAuthAllowedClientMetadataFields = map[string]struct{}{
	"x-codex-installation-id":            {},
	"session_id":                         {},
	"thread_id":                          {},
	"turn_id":                            {},
	"x-codex-window-id":                  {},
	"x-codex-turn-metadata":              {},
	"x-codex-turn-state":                 {},
	"x-codex-parent-thread-id":           {},
	"x-openai-subagent":                  {},
	"parent_turn_id":                     {},
	"root_turn_id":                       {},
	"x-codex-ws-stream-request-start-ms": {},
	"ws_request_header_x_openai_internal_codex_responses_lite": {},
}

func sanitizeCodexOAuthClientMetadataMap(metadata map[string]any) bool {
	if metadata == nil {
		return false
	}
	changed := sanitizeCodexOAuthMetadataMap(metadata)
	for key, value := range metadata {
		canonical := strings.ToLower(key)
		if key != canonical || strings.TrimSpace(key) != key {
			delete(metadata, key)
			changed = true
			continue
		}
		if _, ok := codexOAuthAllowedClientMetadataFields[canonical]; !ok {
			delete(metadata, key)
			changed = true
			continue
		}
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" || !validCodexOAuthClientMetadataValue(canonical, text) {
			delete(metadata, key)
			changed = true
		}
	}
	return changed
}

func validCodexOAuthClientMetadataValue(key, value string) bool {
	switch key {
	case "ws_request_header_x_openai_internal_codex_responses_lite":
		return value == "true"
	case "x-codex-ws-stream-request-start-ms":
		if len(value) < 10 || len(value) > 16 {
			return false
		}
		for i := range value {
			if value[i] < '0' || value[i] > '9' {
				return false
			}
		}
	}
	return true
}

func sanitizeCodexOAuthMetadataMap(metadata map[string]any) bool {
	if metadata == nil {
		return false
	}
	changed := sanitizeCodexOAuthBlockedKeys(metadata)
	for key, value := range metadata {
		if child, ok := codexOAuthStringMap(value); ok {
			if sanitizeCodexOAuthMetadataMap(child) {
				metadata[key] = child
				changed = true
			}
			continue
		}
		if values, ok := value.([]any); ok && sanitizeCodexOAuthMetadataList(values) {
			metadata[key] = values
			changed = true
		}
	}
	if sanitizeCodexOAuthTurnMetadataFields(metadata) {
		changed = true
	}
	return changed
}

func sanitizeCodexOAuthMetadataList(values []any) bool {
	changed := false
	for i, value := range values {
		if child, ok := codexOAuthStringMap(value); ok {
			if sanitizeCodexOAuthMetadataMap(child) {
				values[i] = child
				changed = true
			}
			continue
		}
		if nested, ok := value.([]any); ok && sanitizeCodexOAuthMetadataList(nested) {
			values[i] = nested
			changed = true
		}
	}
	return changed
}

func sanitizeCodexOAuthBlockedKeys(payload map[string]any) bool {
	changed := false
	for key := range payload {
		if isBlockedCodexOAuthClientField(key) {
			delete(payload, key)
			changed = true
		}
	}
	return changed
}

func sanitizeCodexOAuthTurnMetadataFields(payload map[string]any) bool {
	changed := false
	for key, value := range payload {
		if normalizeCodexOAuthFieldName(key) != "x_codex_turn_metadata" {
			continue
		}
		raw, ok := value.(string)
		if !ok {
			delete(payload, key)
			changed = true
			continue
		}
		next := sanitizeCodexOAuthTurnMetadataString(raw)
		if strings.TrimSpace(next) == "" {
			delete(payload, key)
			changed = true
			continue
		}
		if next != raw {
			payload[key] = next
			changed = true
		}
	}
	return changed
}

func sanitizeCodexOAuthTurnMetadataString(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil || payload == nil {
		return ""
	}
	changed := sanitizeCodexOAuthTurnMetadataMap(payload)
	if len(payload) == 0 {
		return ""
	}
	if !changed {
		return trimmed
	}
	next, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(next)
}

var codexOAuthAllowedTurnMetadataFields = map[string]struct{}{
	"installation_id":                {},
	"session_id":                     {},
	"thread_id":                      {},
	"turn_id":                        {},
	"window_id":                      {},
	"request_kind":                   {},
	"forked_from_thread_id":          {},
	"parent_thread_id":               {},
	"parent_turn_id":                 {},
	"root_turn_id":                   {},
	"subagent_kind":                  {},
	"thread_source":                  {},
	"sandbox":                        {},
	"sandbox_mode":                   {},
	"auto_review_enabled":            {},
	"node_repl_auto_review_required": {},
	"node_repl_disabled":             {},
	"turn_started_at_unix_ms":        {},
	"compaction":                     {},
}

func sanitizeCodexOAuthTurnMetadataMap(metadata map[string]any) bool {
	if metadata == nil {
		return false
	}
	changed := sanitizeCodexOAuthMetadataMap(metadata)
	for key, value := range metadata {
		canonical := strings.ToLower(key)
		if key != canonical || strings.TrimSpace(key) != key {
			delete(metadata, key)
			changed = true
			continue
		}
		_, allowed := codexOAuthAllowedTurnMetadataFields[canonical]
		valid, valueChanged := sanitizeCodexOAuthTurnMetadataValue(canonical, value)
		if !allowed || !valid {
			delete(metadata, key)
			changed = true
			continue
		}
		if valueChanged {
			changed = true
		}
	}
	return changed
}

func sanitizeCodexOAuthTurnMetadataValue(key string, value any) (valid bool, changed bool) {
	switch key {
	case "auto_review_enabled", "node_repl_auto_review_required", "node_repl_disabled":
		_, ok := value.(bool)
		return ok, false
	case "turn_started_at_unix_ms":
		switch value.(type) {
		case json.Number, float64:
			return true, false
		default:
			return false, false
		}
	case "compaction":
		compaction, ok := codexOAuthStringMap(value)
		if !ok {
			return false, false
		}
		for field, item := range compaction {
			if field != strings.ToLower(field) || strings.TrimSpace(field) != field {
				delete(compaction, field)
				changed = true
				continue
			}
			switch field {
			case "trigger", "reason", "implementation", "phase", "strategy":
				if text, ok := item.(string); !ok || strings.TrimSpace(text) == "" {
					delete(compaction, field)
					changed = true
				}
			default:
				delete(compaction, field)
				changed = true
			}
		}
		return len(compaction) > 0, changed
	default:
		text, ok := value.(string)
		return ok && strings.TrimSpace(text) != "", false
	}
}

func sanitizeCodexOAuthTurnMetadataHeader(headers http.Header) bool {
	if headers == nil {
		return false
	}
	raw := headers.Get(openAIWSTurnMetadataHeader)
	if strings.TrimSpace(raw) == "" {
		return false
	}
	next := sanitizeCodexOAuthTurnMetadataString(raw)
	if strings.TrimSpace(next) == "" {
		headers.Del(openAIWSTurnMetadataHeader)
		return true
	}
	if next == raw {
		return false
	}
	headers.Set(openAIWSTurnMetadataHeader, next)
	return true
}

func normalizeCodexOAuthFieldName(key string) string {
	return strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(strings.ToLower(strings.TrimSpace(key)))
}

func isBlockedCodexOAuthClientField(key string) bool {
	normalized := normalizeCodexOAuthFieldName(key)
	switch normalized {
	case "base_url", "custom_base_url", "custom_base_url_enabled", "endpoint",
		"hostname", "host", "api_key", "x_api_key", "key", "authorization",
		"timezone", "time_zone", "tz", "country", "country_code", "countrycode",
		"region", "region_code", "regioncode", "locale", "language", "accept_language",
		"device_id", "deviceid", "client_id", "clientid", "client_info",
		"runtime", "runtime_version", "runtimeversion", "sdk_version", "sdkversion",
		"app_version", "appversion", "telemetry", "environment",
		"os", "os_name", "os_version", "platform", "architecture", "arch", "machine",
		"cwd", "pwd", "working_directory", "current_working_directory",
		"workspace", "workspaces", "workspace_root", "worktree", "repository", "repo",
		"git", "git_branch", "git_commit", "git_remote", "remote_url", "branch", "commit",
		"terminal", "terminal_name", "shell", "shell_name", "agent_name",
		"plugin", "plugins", "skill", "skills", "mcp", "mcp_servers", "tool_namespaces_info",
		"trace", "trace_id", "traceparent", "tracestate", "baggage":
		return true
	}
	for _, prefix := range [...]string{
		"cwd_", "workspace_", "worktree_", "repository_", "repo_", "git_",
		"terminal_", "shell_", "plugin_", "skill_", "mcp_", "trace_",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

var codexOAuthBlockedOutboundHeaders = map[string]struct{}{
	"version":                     {},
	"accept-language":             {},
	"cookie":                      {},
	"traceparent":                 {},
	"tracestate":                  {},
	"baggage":                     {},
	"x-client-locale":             {},
	"x-locale":                    {},
	"x-stainless-timeout":         {},
	"x-stainless-read-timeout":    {},
	"x-stainless-connect-timeout": {},
	"x-request-timeout":           {},
	"request-timeout":             {},
	"grpc-timeout":                {},
	"x-codex-attestation":         {},
	"x-openai-attestation":        {},
	"x-device-attestation":        {},
}

func sanitizeCodexOAuthOutboundHeaders(headers http.Header) bool {
	if headers == nil {
		return false
	}
	changed := false
	for name := range headers {
		if _, ok := codexOAuthBlockedOutboundHeaders[strings.ToLower(strings.TrimSpace(name))]; !ok {
			continue
		}
		delete(headers, name)
		changed = true
	}
	return changed
}

func codexOAuthStringMap(value any) (map[string]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		return typed, true
	case map[string]string:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = item
		}
		return out, true
	default:
		return nil, false
	}
}

func cloneCodexOAuthMetadataValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneCodexOAuthMetadataValue(item)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(typed))
		for key, item := range typed {
			out[key] = item
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneCodexOAuthMetadataValue(item)
		}
		return out
	default:
		return value
	}
}
