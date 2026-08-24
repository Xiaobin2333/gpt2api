package service

import (
	"crypto/sha256"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// openAICodexTurnStateHeader 是 Codex 的回合状态头。上游在响应头中铸造该
// 不透明 blob，客户端在同一回合的后续请求中原样回带（codex-rs 侧从
// /responses SSE、/responses/compact JSON 与 WS 握手三种响应中捕获，见
// codex-api/src/sse/responses.rs 与 endpoint/compact.rs）。
const openAICodexTurnStateHeader = "x-codex-turn-state"

const openAICodexTurnStateIdentityContextKey = "openai_codex_turn_state_identity"

type openAICodexTurnStateIdentity struct {
	sessionID string
	turnID    string
}

// turn-state blob 是上游在"出站身份"（含 #5553 指纹收敛改写后的
// installation/session/thread 标识）下铸造的，同账号回放自洽；跨账号回放
// （failover 换号后客户端仍回带旧账号的 blob）是代理链独有、真实 Codex
// 永远不会产生的矛盾信号。溯源表记录每个下游会话最近一次铸造该 blob 的
// 账号，出站守卫据此剥离已知异账号的回带值。
type openAICodexTurnStateOrigin struct {
	accountID int64
	turnID    string
	stateHash [sha256.Size]byte
	expiresAt time.Time
}

func stageOpenAICodexTurnStateIdentity(c *gin.Context, body []byte) {
	if c == nil {
		return
	}
	c.Set(openAICodexTurnStateIdentityContextKey, resolveOpenAICodexTurnStateIdentity(c, body))
}

func stagedOpenAICodexTurnStateIdentity(c *gin.Context) openAICodexTurnStateIdentity {
	if c == nil {
		return openAICodexTurnStateIdentity{}
	}
	if raw, ok := c.Get(openAICodexTurnStateIdentityContextKey); ok {
		identity, typed := raw.(openAICodexTurnStateIdentity)
		if typed {
			return identity
		}
	}
	return resolveOpenAICodexTurnStateIdentity(c, nil)
}

func resolveOpenAICodexTurnStateIdentity(c *gin.Context, body []byte) openAICodexTurnStateIdentity {
	if c == nil || c.Request == nil {
		return openAICodexTurnStateIdentity{}
	}
	view := openAIRequestPayloadView(body)
	headerMetadata := strings.TrimSpace(c.Request.Header.Get(openAIWSTurnMetadataHeader))
	bodyMetadata := strings.TrimSpace(view.Get("client_metadata.x-codex-turn-metadata").String())
	sessionID, sessionOK := unambiguousOpenAICodexTurnStateValue(
		extractClientSessionID(c.Request.Header),
		view.Get("prompt_cache_key").String(),
		view.Get("client_metadata.session_id").String(),
		gjson.Get(headerMetadata, "session_id").String(),
		gjson.Get(bodyMetadata, "session_id").String(),
	)
	if sessionID == "" {
		sessionID, sessionOK = unambiguousOpenAICodexTurnStateValue(
			c.Request.Header.Get("thread-id"),
			view.Get("client_metadata.thread_id").String(),
			gjson.Get(headerMetadata, "thread_id").String(),
			gjson.Get(bodyMetadata, "thread_id").String(),
		)
	}
	bodyTurnID, bodyTurnOK := unambiguousOpenAICodexTurnStateValue(
		view.Get("client_metadata.turn_id").String(),
		gjson.Get(bodyMetadata, "turn_id").String(),
	)
	turnID := bodyTurnID
	turnOK := bodyTurnOK
	if turnID == "" {
		turnID, turnOK = unambiguousOpenAICodexTurnStateValue(gjson.Get(headerMetadata, "turn_id").String())
	}
	if !sessionOK || !turnOK || sessionID == "" || turnID == "" {
		return openAICodexTurnStateIdentity{}
	}
	return openAICodexTurnStateIdentity{sessionID: sessionID, turnID: turnID}
}

func unambiguousOpenAICodexTurnStateValue(values ...string) (string, bool) {
	resolved := ""
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if resolved != "" && resolved != value {
			return "", false
		}
		resolved = value
	}
	return resolved, true
}

// openAICodexTurnStateSeed 返回溯源表键：API Key + 客户端原始会话标识。
// 会话和 turn 标识在改写前从官方头/体载体中暂存；任一缺失或冲突时返回
// 空串，禁止网关替客户端猜测 turn 边界。
func openAICodexTurnStateSeed(c *gin.Context) string {
	identity := stagedOpenAICodexTurnStateIdentity(c)
	if identity.sessionID == "" || identity.turnID == "" {
		return ""
	}
	return strconv.FormatInt(getAPIKeyIDFromContext(c), 10) + "\x00" + identity.sessionID
}

// relayOpenAICodexTurnState 将上游响应中的 turn-state 显式写入下游响应头，
// 并记录铸造账号。必须在响应头提交点调用（WriteHeader 之前、且确认本次
// 上游响应就是将要写回客户端的响应之后）。上游无该头时主动清除 writer 上
// 可能残留的上一 failover attempt 的值——否则换号后旧账号的 blob 会粘到
// 新账号的响应上，这正是本文件要防止的跨账号矛盾。
func (s *OpenAIGatewayService) relayOpenAICodexTurnState(c *gin.Context, account *Account, upstream http.Header) {
	if c == nil || c.Writer == nil {
		return
	}
	canonical := http.CanonicalHeaderKey(openAICodexTurnStateHeader)
	state := extractOpenAICodexTurnState(upstream)
	if state == "" {
		c.Writer.Header().Del(canonical)
		s.clearOpenAICodexTurnStateProvenance(c)
		return
	}
	c.Writer.Header().Set(canonical, state)
	s.noteOpenAICodexTurnStateProvenance(c, account, state)
}

// stageOpenAICodexTurnState 将上游 turn-state 暂存到延迟提交的响应头集合
// （首输出守卫路径先缓存头、见到首个输出事件才提交）。此处**不**记录铸造
// 账号：该 attempt 仍可能在首输出超时后 failover，暂存头会被整体丢弃，
// 客户端从未收到该 blob。溯源必须在真正提交时记录，见
// noteStagedOpenAICodexTurnStateCommitted。
func stageOpenAICodexTurnState(dst *http.Header, upstream http.Header) {
	if dst == nil {
		return
	}
	canonical := http.CanonicalHeaderKey(openAICodexTurnStateHeader)
	state := extractOpenAICodexTurnState(upstream)
	if state == "" {
		if *dst != nil {
			dst.Del(canonical)
		}
		return
	}
	if *dst == nil {
		*dst = http.Header{}
	}
	dst.Set(canonical, state)
}

// noteStagedOpenAICodexTurnStateCommitted 在暂存响应头真正写入下游时记录
// 铸造账号——只有此刻客户端才确定收到了该 blob，溯源表才与客户端持有的
// 值一致（否则被 failover 丢弃的 attempt 会污染溯源，导致后续误剥离）。
func (s *OpenAIGatewayService) noteStagedOpenAICodexTurnStateCommitted(c *gin.Context, account *Account, staged http.Header) {
	state := extractOpenAICodexTurnState(staged)
	if state == "" {
		return
	}
	s.noteOpenAICodexTurnStateProvenance(c, account, state)
}

func extractOpenAICodexTurnState(upstream http.Header) string {
	if upstream == nil {
		return ""
	}
	return strings.TrimSpace(upstream.Get(openAICodexTurnStateHeader))
}

// noteOpenAICodexTurnStateProvenance 记录（下游会话 → 铸造账号 + blob 摘要）。
func (s *OpenAIGatewayService) noteOpenAICodexTurnStateProvenance(c *gin.Context, account *Account, state string) {
	state = strings.TrimSpace(state)
	if s == nil || account == nil || account.ID <= 0 || state == "" {
		return
	}
	seed := openAICodexTurnStateSeed(c)
	if seed == "" {
		return
	}
	identity := stagedOpenAICodexTurnStateIdentity(c)
	s.openaiCodexTurnStateOrigins.Store(seed, openAICodexTurnStateOrigin{
		accountID: account.ID,
		turnID:    identity.turnID,
		stateHash: sha256.Sum256([]byte(state)),
		expiresAt: time.Now().Add(s.openAIWSSessionStickyTTL()),
	})
	s.sweepOpenAICodexTurnStateOrigins()
}

func (s *OpenAIGatewayService) clearOpenAICodexTurnStateProvenance(c *gin.Context) {
	if s == nil {
		return
	}
	if seed := openAICodexTurnStateSeed(c); seed != "" {
		s.openaiCodexTurnStateOrigins.Delete(seed)
	}
}

// guardOpenAICodexTurnStateEcho 出站守卫：只允许同一 API key 会话在同一 turn
// 内向同一账号回带完全相同的 turn-state。新 turn、账号 failover、过期或来源
// 不明都会剥离；只剥离、不注入。
func (s *OpenAIGatewayService) guardOpenAICodexTurnStateEcho(c *gin.Context, account *Account, h http.Header) {
	if h == nil {
		return
	}
	state := strings.TrimSpace(h.Get(openAICodexTurnStateHeader))
	if s == nil || account == nil || account.ID <= 0 {
		h.Del(openAICodexTurnStateHeader)
		return
	}
	identity := stagedOpenAICodexTurnStateIdentity(c)
	seed := openAICodexTurnStateSeed(c)
	if seed == "" {
		h.Del(openAICodexTurnStateHeader)
		return
	}
	raw, ok := s.openaiCodexTurnStateOrigins.Load(seed)
	if !ok {
		h.Del(openAICodexTurnStateHeader)
		return
	}
	origin, ok := raw.(openAICodexTurnStateOrigin)
	if !ok {
		s.openaiCodexTurnStateOrigins.Delete(seed)
		h.Del(openAICodexTurnStateHeader)
		return
	}
	if !origin.expiresAt.IsZero() && time.Now().After(origin.expiresAt) {
		s.openaiCodexTurnStateOrigins.Delete(seed)
		h.Del(openAICodexTurnStateHeader)
		return
	}
	if origin.turnID != identity.turnID || origin.accountID != account.ID {
		s.openaiCodexTurnStateOrigins.Delete(seed)
		h.Del(openAICodexTurnStateHeader)
		return
	}
	if state == "" || origin.stateHash != sha256.Sum256([]byte(state)) {
		h.Del(openAICodexTurnStateHeader)
	}
}

// sweepOpenAICodexTurnStateOrigins 机会式清扫过期溯源记录：每 256 次写入
// 全量遍历一轮，防止仅靠读侧惰性删除导致的慢泄漏（会话键无上界）。
func (s *OpenAIGatewayService) sweepOpenAICodexTurnStateOrigins() {
	if s.openaiCodexTurnStateWrites.Add(1)%256 != 0 {
		return
	}
	now := time.Now()
	s.openaiCodexTurnStateOrigins.Range(func(key, value any) bool {
		origin, ok := value.(openAICodexTurnStateOrigin)
		if !ok || (!origin.expiresAt.IsZero() && now.After(origin.expiresAt)) {
			s.openaiCodexTurnStateOrigins.Delete(key)
		}
		return true
	})
}
