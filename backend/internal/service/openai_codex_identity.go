package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// codexUpstreamMinVersion 是上游接受的最低 Codex 客户端版本，用于约束 UA 版本段
// 以及自定义 API Key 上游的历史兼容 Version 头（issue #3901，2026-07 实测）。
const codexUpstreamMinVersion = "0.144.0"

// codexClientVersionMaxLen 官方版本号均为短 ASCII 串，远低于此上限。
const codexClientVersionMaxLen = 64

// codexClientVersionPattern 允许 0.146.0 与 0.147.0-alpha.4 两类官方形态。
var codexClientVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}(-[0-9A-Za-z.]+)?$`)

// NormalizeCodexClientVersion 校验并归一化 Codex 客户端版本号，非法值返回空串。
// 该值会被拼进出站 User-Agent，并用于 /models 的 client_version 查询参数，必须拒绝任意字节，避免管理员误填或
// 自动同步拿到异常值时把不可控内容透给上游。
func NormalizeCodexClientVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || len(version) > codexClientVersionMaxLen || !codexClientVersionPattern.MatchString(version) {
		return ""
	}
	return version
}

// buildCodexCLIUserAgent 按版本号拼出规范 Codex TUI User-Agent。
// UA 形态只在 codexCLIUserAgentSuffix 一处定义，避免多处拼装漂移。
func buildCodexCLIUserAgent(version string) string {
	if version = NormalizeCodexClientVersion(version); version == "" {
		return codexCLIUserAgent
	}
	return openai.CodexDefaultOriginator + "/" + version + codexCLIUserAgentSuffix +
		" (" + openai.CodexDefaultOriginator + "; " + version + ")"
}

// codexIdentityEnforcement 控制 enforceCodexIdentityHeaders 是否强制统一出站身份，
// 由 gateway.disable_codex_identity_enforcement 在服务构造时取反发布。
// 默认开启：上游在容量紧张时按客户端身份分优先级降载，被降载的请求会拿到
// HTTP 200 + 流内 server_is_overloaded，本次请求即失败；强制统一出口可确保没有
// 请求带着第三方或陈旧身份出站。关闭后退回「仅按最终 UA 配对 originator」的收口语义。
var codexIdentityEnforcement = func() *atomic.Bool {
	v := &atomic.Bool{}
	v.Store(true)
	return v
}()

// SetCodexIdentityEnforcementEnabled 发布 Codex 出站身份强制统一开关。
// enforceCodexIdentityHeaders 是所有出站路径共用的纯函数收口点，无法在热路径注入配置，
// 故由持有配置的服务在构造时发布进程级快照。
func SetCodexIdentityEnforcementEnabled(enabled bool) {
	codexIdentityEnforcement.Store(enabled)
}

// codexCanonicalUserAgentResolver 返回当前生效的规范 Codex User-Agent（后台设置 / 自动同步版本号）。
// 由 SettingService 在装配时注入；解析器内部自带 TTL 缓存，热路径不触库。
type codexCanonicalUserAgentResolver func() string

var (
	codexCanonicalUAMu       sync.RWMutex
	codexCanonicalUAResolver codexCanonicalUserAgentResolver
)

// SetCodexCanonicalUserAgentResolver 注入规范 User-Agent 解析器。
// 未注入或解析结果非法时回退到编译期常量 codexCLIUserAgent。
func SetCodexCanonicalUserAgentResolver(resolver func() string) {
	codexCanonicalUAMu.Lock()
	defer codexCanonicalUAMu.Unlock()
	codexCanonicalUAResolver = resolver
}

// CodexCanonicalUserAgent 返回当前生效的规范 Codex User-Agent。
// 取值走与推理相同的解析链：面板 UA 指纹 + 面板/自动同步版本号 + 编译期兜底。
// 供无账号句柄的出站路径（OAuth 换 Token / 刷新）使用。
func CodexCanonicalUserAgent() string {
	return resolveCodexOutboundIdentity("").userAgent
}

// CodexCanonicalAuthIdentity 返回凭据面（auth.openai.com：换 Token / 刷新 / whoami）
// 出站请求的身份对：规范 User-Agent 与配套 originator，与推理解析链同源。
// 凭据面不发 version 头——真实 Codex 客户端在该面只携带 originator 与 User-Agent
// （codex-rs login/default_client.rs 的 default_headers()）。
func CodexCanonicalAuthIdentity() (userAgent, originator string) {
	identity := resolveCodexOutboundIdentity("")
	return identity.userAgent, identity.originator
}

// ApplyCodexCanonicalAuthIdentity 为凭据面出站请求写入身份对（不含 version）。
func ApplyCodexCanonicalAuthIdentity(h http.Header) {
	if h == nil {
		return
	}
	userAgent, originator := CodexCanonicalAuthIdentity()
	h.Set("user-agent", userAgent)
	h.Set("originator", originator)
}

type codexOAuthRequestIdentity struct {
	installationID string
	sessionID      string
	threadID       string
	windowID       string
}

func resolveCodexOAuthRequestIdentity(c *gin.Context, account *Account, h http.Header, body []byte, promptCacheKey string) codexOAuthRequestIdentity {
	identity := codexOAuthRequestIdentity{}
	var inbound http.Header
	if c != nil && c.Request != nil {
		inbound = c.Request.Header
	}
	if ids := stagedCodexFingerprintIDs(c, account); ids != nil {
		identity.installationID = ids.installationID
		identity.sessionID = ids.sessionID
		identity.threadID = ids.threadID
		identity.windowID = ids.windowID
	}
	if identity.installationID == "" {
		identity.installationID = strings.TrimSpace(gjson.GetBytes(body, "client_metadata.x-codex-installation-id").String())
	}
	if identity.installationID == "" && account != nil {
		if seed, ok := codexFingerprintSeed(account.Extra); ok {
			identity.installationID = resolveConvergedInstallationID(account, seed)
		} else {
			identity.installationID = account.GetOpenAIDeviceID()
		}
	}
	if identity.sessionID == "" {
		identity.sessionID = firstNonEmptyCodexIdentityValue(
			gjson.GetBytes(body, "client_metadata.session_id").String(),
			h.Get("session-id"),
			inbound.Get("session-id"),
			promptCacheKey,
			inbound.Get("session_id"),
			h.Get("session_id"),
		)
	}
	if identity.threadID == "" {
		identity.threadID = firstNonEmptyCodexIdentityValue(
			gjson.GetBytes(body, "client_metadata.thread_id").String(),
			h.Get("thread-id"),
			inbound.Get("thread-id"),
			identity.sessionID,
		)
	}
	identity.sessionID = canonicalCodexRequestUUID(c, identity.sessionID)
	identity.threadID = canonicalCodexRequestUUID(c, identity.threadID)
	if identity.windowID == "" {
		identity.windowID = firstNonEmptyCodexIdentityValue(
			gjson.GetBytes(body, "client_metadata.x-codex-window-id").String(),
			h.Get("x-codex-window-id"),
			inbound.Get("x-codex-window-id"),
		)
	}
	identity.windowID = canonicalCodexRequestWindowID(identity.windowID, identity.threadID)
	return identity
}

func firstNonEmptyCodexIdentityValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func canonicalCodexRequestUUID(c *gin.Context, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := uuid.Parse(value); err == nil && parsed != uuid.Nil && parsed.Version() == uuid.Version(7) {
		return parsed.String()
	}
	isolated := isolateOpenAISessionID(getAPIKeyIDFromContext(c), value)
	return deriveStableUUIDv7("sub2api:codex-request-id:v3:"+isolated, value)
}

func canonicalCodexRequestWindowID(value, threadID string) string {
	threadID = strings.TrimSpace(threadID)
	if threadID == "" {
		return ""
	}
	windowNumber := uint64(0)
	if separator := strings.LastIndexByte(strings.TrimSpace(value), ':'); separator >= 0 {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(value)[separator+1:], 10, 64); err == nil {
			windowNumber = parsed
		}
	}
	return threadID + ":" + strconv.FormatUint(windowNumber, 10)
}

func applyCodexOAuthRequestIdentityHeaders(h http.Header, identity codexOAuthRequestIdentity, compact bool) {
	if h == nil {
		return
	}
	h.Del("session_id")
	h.Del("conversation_id")
	if identity.sessionID != "" {
		h.Set("session-id", identity.sessionID)
	}
	if identity.threadID != "" {
		h.Set("thread-id", identity.threadID)
	}
	if identity.windowID != "" {
		h.Set("x-codex-window-id", identity.windowID)
	}
	if compact {
		h.Del("x-client-request-id")
		if identity.installationID != "" {
			h.Set("x-codex-installation-id", identity.installationID)
		}
		return
	}
	h.Del("x-codex-installation-id")
	if identity.threadID != "" {
		h.Set("x-client-request-id", identity.threadID)
	}
}

func normalizeCodexOAuthRequestMetadata(c *gin.Context, account *Account, body []byte, promptCacheKey string) ([]byte, error) {
	if account == nil || !account.IsOpenAIOAuth() || len(body) == 0 || !gjson.ValidBytes(body) {
		return body, nil
	}
	var headers http.Header
	if c != nil && c.Request != nil {
		headers = c.Request.Header
	}
	identity := resolveCodexOAuthRequestIdentity(c, account, headers, body, promptCacheKey)
	if identity.installationID == "" && identity.sessionID == "" && identity.threadID == "" {
		return body, nil
	}

	turnMetadata := make(map[string]any)
	rawTurnMetadata := strings.TrimSpace(gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").String())
	if rawTurnMetadata == "" && headers != nil {
		rawTurnMetadata = strings.TrimSpace(headers.Get(openAIWSTurnMetadataHeader))
	}
	if rawTurnMetadata != "" {
		_ = json.Unmarshal([]byte(rawTurnMetadata), &turnMetadata)
	}

	turnID := strings.TrimSpace(gjson.GetBytes(body, "client_metadata.turn_id").String())
	if turnID == "" {
		turnID, _ = turnMetadata["turn_id"].(string)
	}
	ids := stagedCodexFingerprintIDs(c, account)
	if ids != nil && ids.turnID != "" {
		turnID = ids.turnID
	}
	turnID = canonicalCodexRequestUUID(c, turnID)
	if turnID == "" {
		generated, err := uuid.NewV7()
		if err != nil {
			return body, err
		}
		turnID = generated.String()
	}

	next := body
	var err error
	for path, value := range map[string]string{
		"client_metadata.x-codex-installation-id": identity.installationID,
		"client_metadata.session_id":              identity.sessionID,
		"client_metadata.thread_id":               identity.threadID,
		"client_metadata.turn_id":                 turnID,
		"client_metadata.x-codex-window-id":       identity.windowID,
	} {
		if value == "" {
			continue
		}
		next, err = sjson.SetBytes(next, path, value)
		if err != nil {
			return body, err
		}
	}

	if identity.installationID != "" {
		turnMetadata["installation_id"] = identity.installationID
	}
	if identity.sessionID != "" {
		turnMetadata["session_id"] = identity.sessionID
	}
	if identity.threadID != "" {
		turnMetadata["thread_id"] = identity.threadID
	}
	turnMetadata["turn_id"] = turnID
	if identity.windowID != "" {
		turnMetadata["window_id"] = identity.windowID
	}
	if _, ok := turnMetadata["request_kind"]; !ok {
		turnMetadata["request_kind"] = "turn"
	}
	if _, ok := turnMetadata["turn_started_at_unix_ms"]; !ok {
		turnStartedAt := time.Now().UnixMilli()
		if ids != nil && ids.turnStartedAtUnixMs > 0 {
			turnStartedAt = ids.turnStartedAtUnixMs
		}
		turnMetadata["turn_started_at_unix_ms"] = turnStartedAt
	}
	encodedTurnMetadata, err := marshalCodexTurnMetadata(turnMetadata)
	if err != nil {
		return body, err
	}
	next, err = sjson.SetBytes(next, "client_metadata.x-codex-turn-metadata", encodedTurnMetadata)
	if err != nil {
		return body, err
	}
	return next, nil
}

func applyCodexOAuthTurnMetadataCompatibilityHeader(h http.Header, body []byte) {
	if h == nil {
		return
	}
	value := strings.TrimSpace(gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").String())
	if value == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(value), &metadata); err != nil {
		return
	}
	// The CLI keeps the unbounded tool inventory in client_metadata only. Its
	// compatibility header is the same metadata snapshot without this field.
	delete(metadata, "tool_namespaces_info")
	encoded, err := marshalCodexTurnMetadata(metadata)
	if err == nil {
		h.Set(openAIWSTurnMetadataHeader, encoded)
	}
}

var codexTurnMetadataFieldOrder = [...]string{
	"installation_id",
	"session_id",
	"thread_id",
	"agent_name",
	"turn_id",
	"window_id",
	"request_kind",
	"forked_from_thread_id",
	"parent_thread_id",
	"parent_turn_id",
	"root_turn_id",
	"subagent_kind",
	"thread_source",
	"sandbox",
	"sandbox_mode",
	"auto_review_enabled",
	"node_repl_auto_review_required",
	"node_repl_disabled",
	"workspaces",
	"tool_namespaces_info",
	"turn_started_at_unix_ms",
	"compaction",
}

func marshalCodexTurnMetadata(metadata map[string]any) (string, error) {
	orderedKeys := make([]string, 0, len(metadata))
	known := make(map[string]struct{}, len(codexTurnMetadataFieldOrder))
	for _, key := range codexTurnMetadataFieldOrder {
		known[key] = struct{}{}
		if _, ok := metadata[key]; ok {
			orderedKeys = append(orderedKeys, key)
		}
	}
	extraKeys := make([]string, 0, len(metadata)-len(orderedKeys))
	for key := range metadata {
		if _, ok := known[key]; !ok {
			extraKeys = append(extraKeys, key)
		}
	}
	sort.Strings(extraKeys)
	orderedKeys = append(orderedKeys, extraKeys...)

	var encoded bytes.Buffer
	encoded.WriteByte('{')
	for index, key := range orderedKeys {
		if index > 0 {
			encoded.WriteByte(',')
		}
		keyJSON, err := marshalCodexJSONValue(key)
		if err != nil {
			return "", err
		}
		valueJSON, err := marshalCodexJSONValue(metadata[key])
		if err != nil {
			return "", err
		}
		encoded.Write(keyJSON)
		encoded.WriteByte(':')
		encoded.Write(valueJSON)
	}
	encoded.WriteByte('}')
	return asciiOnlyJSON(encoded.Bytes()), nil
}

func marshalCodexJSONValue(value any) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}), nil
}

func asciiOnlyJSON(encoded []byte) string {
	if bytes.IndexFunc(encoded, func(r rune) bool { return r > 0x7f }) < 0 {
		return string(encoded)
	}
	const hex = "0123456789abcdef"
	var out strings.Builder
	out.Grow(len(encoded))
	for len(encoded) > 0 {
		r, size := utf8.DecodeRune(encoded)
		encoded = encoded[size:]
		if r <= 0x7f {
			out.WriteByte(byte(r))
			continue
		}
		if r <= 0xffff {
			writeCodexJSONUnicodeEscape(&out, uint16(r), hex)
			continue
		}
		r -= 0x10000
		writeCodexJSONUnicodeEscape(&out, uint16(0xd800+(r>>10)), hex)
		writeCodexJSONUnicodeEscape(&out, uint16(0xdc00+(r&0x3ff)), hex)
	}
	return out.String()
}

func writeCodexJSONUnicodeEscape(out *strings.Builder, value uint16, hex string) {
	out.WriteString(`\u`)
	out.WriteByte(hex[(value>>12)&0xf])
	out.WriteByte(hex[(value>>8)&0xf])
	out.WriteByte(hex[(value>>4)&0xf])
	out.WriteByte(hex[value&0xf])
}

// CodexCanonicalClientVersion 返回当前生效的 Codex 客户端版本号。
func CodexCanonicalClientVersion() string {
	return resolveCodexOutboundIdentity("").version
}

// codexCanonicalUserAgent 返回出站规范 User-Agent。
func codexCanonicalUserAgent() string {
	codexCanonicalUAMu.RLock()
	resolver := codexCanonicalUAResolver
	codexCanonicalUAMu.RUnlock()
	if resolver != nil {
		if ua := strings.TrimSpace(resolver()); ua != "" {
			return ua
		}
	}
	return codexCLIUserAgent
}

// codexOutboundIdentity 出站身份三元组，三者必须同源自洽：
// originator 与 User-Agent 首段配套（否则上游 404，issue #3901），
// version 等于 User-Agent 的版本段且不低于上游门槛。
type codexOutboundIdentity struct {
	userAgent  string
	originator string
	version    string
}

// resolveCodexOutboundIdentity 由候选 User-Agent 推导自洽的出站身份。
// candidateUA 为空时使用规范 User-Agent；推导不出官方身份时整体回退为规范 TUI 身份。
//
// 候选 UA（面板 / 账号级的管理员显式配置）只贡献客户端名与 OS / 架构 / 终端指纹，
// 其自带的版本段一律用当前生效版本重建：一条填写于某个历史版本的 UA 否则会把出站身份
// 永久钉死在陈旧版本上，绕过版本自动同步，落回上游优先降载的那一侧。
// 需要固定版本请填「Codex 客户端版本号」并关闭自动同步。
func resolveCodexOutboundIdentity(candidateUA string) codexOutboundIdentity {
	canonical := codexCanonicalUserAgent()
	ua := strings.TrimSpace(candidateUA)
	if ua == "" {
		ua = canonical
	}
	originator, pairedUA, ok := openai.PairCodexClientIdentity(ua)
	if !ok {
		if originator, pairedUA, ok = openai.PairCodexClientIdentity(canonical); !ok {
			originator, pairedUA = openai.CodexDefaultOriginator, codexCLIUserAgent
		}
	}
	// 生效版本只有一个来源：规范身份（面板版本号 → 自动同步值 → 内置常量，见
	// SettingService.GetOpenAICodexClientVersion）。UA 版本段由此单一来源派生。
	version := codexClientVersionFromUA(canonical)
	if rebuilt := openai.SetCodexUserAgentVersion(pairedUA, version); rebuilt != "" {
		pairedUA = rebuilt
	}
	return codexOutboundIdentity{userAgent: pairedUA, originator: originator, version: version}
}

// codexClientVersionFromUA 取 UA 的版本段作为生效版本；
// 非法或低于上游门槛（低于则上游 404，issue #3901）时回退编译期常量。
func codexClientVersionFromUA(ua string) string {
	version := NormalizeCodexClientVersion(openai.CodexUserAgentVersion(ua))
	if version == "" || CompareVersions(version, codexUpstreamMinVersion) < 0 {
		return codexCLIVersion
	}
	return version
}

// ensureCodexIdentityHeaders 补齐 OAuth（ChatGPT 内部接口）HTTP 出站请求所需的 Codex 身份头。
// 已有 User-Agent 保持不变，交给紧随其后的 enforceCodexIdentityHeaders 收口。
// OpenAI-Beta 由具体传输协商：当前 Codex HTTP 不发送旧 responses=experimental，
// WebSocket 则在握手处发送 responses_websockets=2026-02-06。
// 官方客户端不发送独立 version 头；版本仅体现在 User-Agent，以及 /models 的
// client_version 查询参数中。这里主动删除客户端透传值，避免形成额外线协议特征。
func ensureCodexIdentityHeaders(h http.Header) {
	if h == nil {
		return
	}
	identity := resolveCodexOutboundIdentity("")
	if strings.TrimSpace(h.Get("user-agent")) == "" {
		h.Set("user-agent", identity.userAgent)
	}
	if strings.TrimSpace(h.Get("originator")) == "" {
		h.Set("originator", identity.originator)
	}
	h.Del("version")
}

// applyOpenAICodexProbeHeaders 为合成探测请求补齐 Codex 身份和引擎指纹。
func applyOpenAICodexProbeHeaders(h http.Header) {
	if h == nil {
		return
	}
	ensureCodexIdentityHeaders(h)
	// API-key 能力探针仍保留历史兼容协商；OAuth 调用方会在最终出站前按
	// 当前 Codex HTTP 行为移除该 token。
	h.Set("Version", CodexCanonicalClientVersion())
	h.Set("OpenAI-Beta", "responses=experimental")
	h.Set("X-Codex-Window-ID", uuid.NewString())
}

// enforceCodexIdentityHeaders 收口 OAuth（ChatGPT 内部接口）出站请求的客户端身份头。
// 见 enforceCodexIdentityHeadersWithUA；无账号级自定义 User-Agent 时使用本函数。
func enforceCodexIdentityHeaders(h http.Header) {
	enforceCodexIdentityHeadersWithUA(h, "")
}

// enforceCodexIdentityHeadersWithUA 强制统一 OAuth 出站身份：User-Agent / originator
// 一律改写为网关的规范身份，客户端自报身份不参与构造。上游在容量紧张时按客户端身份分优先级
// 降载，被降载的请求会拿到 HTTP 200 + 流内 server_is_overloaded；统一出口可确保没有请求带着
// 第三方或陈旧身份出站，也天然满足 originator 与 UA 首段配套的上游校验（issue #3901）。
//
// overrideUA 是账号级自定义 User-Agent：管理员的显式配置仍然生效，但只贡献客户端名与
// OS / 架构 / 终端指纹——UA 版本段与 originator 都由规范身份重建，不允许出现自相矛盾或陈旧的身份。
//
// 强制统一被 gateway.disable_codex_identity_enforcement 关闭时，退回「按最终 User-Agent 配对
// originator 配对」的收口语义，供上游策略变动时回滚。
//
// 仅对携带 originator 的请求生效：compat 桥接等非 ChatGPT 内部接口路径会显式删除 originator，
// 不应被补回。需要从缺失身份头恢复的调用方应先调用 ensureCodexIdentityHeaders。
// 必须在所有 User-Agent 改写之后调用。
func enforceCodexIdentityHeadersWithUA(h http.Header, overrideUA string) {
	if h == nil {
		return
	}
	// 即使调用方刻意移除了 originator（例如兼容桥），也不能让下游传入的
	// 非官方 version 或 locale 头穿过最终 OAuth 出站边界。官方 Codex 默认
	// 客户端不发送 Accept-Language。
	h.Del("version")
	h.Del("accept-language")
	if h.Get("originator") == "" {
		return
	}
	if !codexIdentityEnforcement.Load() {
		pairCodexIdentityHeaders(h)
		return
	}
	identity := resolveCodexOutboundIdentity(overrideUA)
	h.Set("user-agent", identity.userAgent)
	h.Set("originator", identity.originator)
}

// pairCodexIdentityHeaders 是关闭强制统一后的兜底收口：保留客户端真实身份，
// 仅保证 originator 与最终 User-Agent 首段配套（issue #3901）。
func pairCodexIdentityHeaders(h http.Header) {
	originator, pairedUA, ok := openai.PairCodexClientIdentity(h.Get("user-agent"))
	if !ok {
		identity := resolveCodexOutboundIdentity("")
		originator, pairedUA = identity.originator, identity.userAgent
	}
	h.Set("user-agent", pairedUA)
	h.Set("originator", originator)
	h.Del("version")
}
