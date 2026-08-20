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
	if sanitizeCodexOAuthTurnMetadataFields(payload) {
		changed = true
	}
	for _, key := range [...]string{"metadata", "client_metadata", "credential_extras", "credentials"} {
		if child, ok := codexOAuthStringMap(payload[key]); ok {
			if sanitizeCodexOAuthMetadataMap(child) {
				payload[key] = child
				changed = true
			}
		}
	}
	return changed
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
		if containsBlockedCodexOAuthFieldText(trimmed) {
			return ""
		}
		return trimmed
	}
	if !sanitizeCodexOAuthMetadataMap(payload) {
		return trimmed
	}
	next, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(next)
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
	return strings.NewReplacer("-", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(key)))
}

func isBlockedCodexOAuthClientField(key string) bool {
	switch normalizeCodexOAuthFieldName(key) {
	case "base_url", "custom_base_url", "custom_base_url_enabled", "endpoint",
		"hostname", "host", "api_key", "x_api_key", "key", "authorization",
		"timezone", "time_zone", "tz", "country", "country_code", "countrycode",
		"region", "region_code", "regioncode", "locale", "language", "accept_language":
		return true
	default:
		return false
	}
}

func containsBlockedCodexOAuthFieldText(value string) bool {
	lower := strings.ToLower(value)
	for _, token := range [...]string{
		"base_url", "custom_base_url", "endpoint", "hostname",
		"api_key", "x-api-key", "authorization",
		"time_zone", "timezone", `"tz"`,
		"country_code", "countrycode", `"country"`,
		"region_code", "regioncode", `"region"`,
		`"locale"`, `"language"`, "accept_language", "accept-language",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
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
