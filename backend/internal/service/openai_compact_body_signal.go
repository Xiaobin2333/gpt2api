package service

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// openAINativeCompactionV2Key 标记本请求是原生 remote compaction v2
// （裸 /responses + stream:true + compaction_trigger），由 handler 在判定后
// 写入，供上游请求构造时补注协商头。
const openAINativeCompactionV2Key = "openai_native_compaction_v2"

const openAIRemoteCompactionV2Feature = "remote_compaction_v2"

// MarkOpenAINativeCompactionV2 由 handler 在识别出原生 v2 压缩请求时调用。
func MarkOpenAINativeCompactionV2(c *gin.Context) {
	if c != nil {
		c.Set(openAINativeCompactionV2Key, true)
	}
}

func isOpenAINativeCompactionV2(c *gin.Context) bool {
	if c == nil {
		return false
	}
	return c.GetBool(openAINativeCompactionV2Key)
}

// ensureOpenAIRemoteCompactionV2BetaFeature 确保出站 x-codex-beta-features
// 头包含 remote_compaction_v2。真实 Codex 发送 compaction_trigger 时总会同时
// 携带该协商头（codex-rs build_model_client_beta_features_header 对该 feature
// 特判 advertise）；上游或下游网关链剥掉它后，请求会在依赖该头做门控的
// 环节被降级（#5586）。这里在原生 v2 请求出站前补齐，使线型与真实 Codex
// 一致。已存在时保持原样，不重复追加。
func ensureOpenAIRemoteCompactionV2BetaFeature(h http.Header) {
	if h == nil {
		return
	}
	tokens := make([]string, 0, 4)
	for _, value := range h.Values("x-codex-beta-features") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if token == openAIRemoteCompactionV2Feature {
				return
			}
			tokens = append(tokens, token)
		}
	}
	tokens = append(tokens, openAIRemoteCompactionV2Feature)
	h.Set("x-codex-beta-features", strings.Join(tokens, ","))
}

// applyOpenAICodexBetaFeatures 只在请求已由 handler 识别为原生 v2 压缩回合时
// 补齐 remote_compaction_v2。普通请求保留客户端携带的能力集合；客户端没有
// 声明时也保持缺失，避免代理替未知客户端虚构会话级实验能力。
func applyOpenAICodexBetaFeatures(c *gin.Context, _ *Account, h http.Header) {
	if h == nil {
		return
	}
	if isOpenAINativeCompactionV2(c) {
		ensureOpenAIRemoteCompactionV2BetaFeature(h)
	}
}

// HasCompactionTriggerInInput detects an input item with
// type="compaction_trigger". The handler combines this body signal with the
// request path and stream flag to distinguish the native remote compaction v2
// wire from the legacy /responses/compact bridge.
func HasCompactionTriggerInInput(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() {
		return false
	}
	found := false
	input.ForEach(func(_, item gjson.Result) bool {
		if item.Get("type").String() == "compaction_trigger" {
			found = true
			return false
		}
		return true
	})
	return found
}
