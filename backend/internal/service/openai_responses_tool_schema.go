package service

import (
	"bytes"
	"sort"
	"strings"

	"github.com/tidwall/gjson"
)

const (
	// 工具定义在多轮历史里最多再嵌套一层 tools，留出余量后截断，避免畸形请求体
	// 造成无界递归。
	openAIResponsesToolSchemaMaxDepth = 4
	// JSON Schema 里 type 只能是字符串或字符串数组；显式 null 无论哪个方言都非法，
	// 补成 object 与 upstream 对该工具的实际期望一致。
	openAIResponsesToolSchemaFallbackType = `"object"`
	openAIResponsesEmptyObjectSchema      = `{"type":"object","properties":{}}`
	// 显式 null 在 JSON 里只有这一种字面量形态。
	openAIResponsesToolSchemaNullLiteral = "null"
)

// openAIResponsesToolSchemaEdit records one schema repair using absolute byte
// offsets in the original request so all edits can be applied in one pass.
type openAIResponsesToolSchemaEdit struct {
	offset      int
	length      int
	replacement string
}

// sanitizeOpenAIResponsesToolParameterTypes repairs function parameter schemas
// that the OpenAI Responses endpoint rejects at the root.
//
// Codex Desktop 内置的 automation_update 工具可能带 parameters.type = null，
// 也可能使用缺少根 type 的 oneOf Schema。OpenAI 直接回 400
// invalid_function_parameters；该工具定义又会沉进多轮历史，导致之后每一轮
// 继续失败并在账号池里反复重放同一份坏 Schema。
//
// JSON Schema permits a missing root type, but Responses function tools require
// the root to declare type:"object". Keep composed oneOf/$defs content intact
// and only add the required root constraint for function tools. Other tool
// types retain their original missing-type semantics.
//
// 实现上先收集全部命中的绝对偏移，再一次性拼出新 body：逐个 sjson.SetBytes 每次
// 都会重扫并全量拷贝整个文档，命中 N 处就是 N 次全量拷贝，而 /v1/responses 的
// body 上限是 gateway.max_body_size（默认 256MB），构造请求能塞进百万级命中。
func sanitizeOpenAIResponsesToolParameterTypes(body []byte) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	edits := make([]openAIResponsesToolSchemaEdit, 0, 2)
	collectOpenAIResponsesToolSchemaEdits(body, gjson.GetBytes(body, "tools"), 0, &edits)
	if input := gjson.GetBytes(body, "input"); input.IsArray() {
		input.ForEach(func(_, item gjson.Result) bool {
			if item.IsObject() {
				collectOpenAIResponsesToolSchemaEdits(body, item.Get("tools"), 0, &edits)
			}
			return true
		})
	}
	if len(edits) == 0 {
		return body, false, nil
	}

	// tools 与 input 在 body 里的先后顺序由客户端决定，收集顺序不保证单调。
	sort.Slice(edits, func(i, j int) bool { return edits[i].offset < edits[j].offset })

	sanitized := make([]byte, 0, len(body)+len(edits)*len(openAIResponsesEmptyObjectSchema))
	cursor := 0
	for _, edit := range edits {
		// 收集阶段已逐个校验过区间，这里再挡一次重叠，保证拼接严格单调向前。
		if edit.offset < cursor {
			continue
		}
		sanitized = append(sanitized, body[cursor:edit.offset]...)
		sanitized = append(sanitized, edit.replacement...)
		cursor = edit.offset + edit.length
	}
	sanitized = append(sanitized, body[cursor:]...)
	return sanitized, true, nil
}

// collectOpenAIResponsesToolSchemaEdits collects root-schema repairs from one
// tools array. Explicit null type values are invalid for every schema-bearing
// tool; missing root types and null parameter schemas are repaired only for
// function tools.
func collectOpenAIResponsesToolSchemaEdits(
	body []byte, tools gjson.Result, depth int, edits *[]openAIResponsesToolSchemaEdit,
) {
	if depth > openAIResponsesToolSchemaMaxDepth || !tools.IsArray() {
		return
	}
	tools.ForEach(func(_, tool gjson.Result) bool {
		if !tool.IsObject() {
			return true
		}
		isFunction := strings.TrimSpace(tool.Get("type").String()) == "function"
		// Responses 形态用顶层 parameters，ChatCompletions 形态用 function.parameters，
		// 两种都可能出现在 Responses 请求里（见 normalizeCodexTools）。
		for _, suffix := range []string{"parameters", "function.parameters"} {
			params := tool.Get(suffix)
			if isFunction && params.Type == gjson.Null && params.Raw == openAIResponsesToolSchemaNullLiteral {
				appendOpenAIResponsesToolSchemaEdit(body, params, openAIResponsesEmptyObjectSchema, edits)
				continue
			}
			if !params.IsObject() {
				continue
			}
			// gjson 用 Type==Null 同时表示「显式 null」和「路径不存在」，靠 Raw
			// 区分：不存在时 Raw 为空串。
			if typ := params.Get("type"); typ.Type == gjson.Null && typ.Raw == openAIResponsesToolSchemaNullLiteral {
				appendOpenAIResponsesToolSchemaEdit(body, typ, openAIResponsesToolSchemaFallbackType, edits)
			} else if isFunction && typ.Raw == "" {
				appendOpenAIResponsesMissingRootObjectType(body, params, edits)
			}
		}
		// 历史输入里的工具定义会再嵌套一层 tools（upstream 报错路径形如
		// input[234].tools[0].tools[3].parameters）。
		collectOpenAIResponsesToolSchemaEdits(body, tool.Get("tools"), depth+1, edits)
		return true
	})
}

func appendOpenAIResponsesToolSchemaEdit(
	body []byte, target gjson.Result, replacement string, edits *[]openAIResponsesToolSchemaEdit,
) {
	end := target.Index + len(target.Raw)
	if target.Index <= 0 || end > len(body) {
		return
	}
	if !bytes.Equal(body[target.Index:end], []byte(target.Raw)) {
		return
	}
	*edits = append(*edits, openAIResponsesToolSchemaEdit{
		offset: target.Index, length: len(target.Raw), replacement: replacement,
	})
}

func appendOpenAIResponsesMissingRootObjectType(
	body []byte, params gjson.Result, edits *[]openAIResponsesToolSchemaEdit,
) {
	if params.Index <= 0 || len(params.Raw) < 2 || params.Index+len(params.Raw) > len(body) {
		return
	}
	if !bytes.Equal(body[params.Index:params.Index+len(params.Raw)], []byte(params.Raw)) || params.Raw[0] != '{' {
		return
	}
	replacement := `"type":"object"`
	if strings.TrimSpace(params.Raw[1:len(params.Raw)-1]) != "" {
		replacement += ","
	}
	*edits = append(*edits, openAIResponsesToolSchemaEdit{
		offset: params.Index + 1, replacement: replacement,
	})
}
