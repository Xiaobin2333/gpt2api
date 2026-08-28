package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	DefaultWorkerCount    = 4
	MaxWorkerCount        = 32
	DefaultQueueCapacity  = 32768
	MaxQueueCapacity      = 100000
	DefaultTimeoutMS      = 3000
	MinTimeoutMS          = 100
	MaxTimeoutMS          = 30000
	DefaultInputLimit     = 4000
	MinInputLimit         = 128
	MaxInputLimit         = 100000
	DefaultBlockThreshold = "Unsafe"
	DefaultFlagThreshold  = "Controversial"
	DefaultBlockStatus    = 403
	DefaultBlockMessage   = "请检查你的提示词，本次请求被审计系统拦截。"
	MaxBlockMessageRunes  = 512
	DefaultPayloadTTL     = 30 * time.Minute
)

type SecretEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// ConfigStore is the injectable boundary between hot-path prompt auditing and
// the concrete settings/PostgreSQL/Redis-backed configuration manager.
type ConfigStore interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Active() (ActiveConfig, bool)
	EffectiveMode() Mode
	// BlockingActivationDegraded is true when storage intent requires blocking
	// but no usable blocking snapshot is active (cold start or failed reload).
	// It must stay false when blocking is not intended, even if config is
	// untrusted—otherwise default-off deployments fail closed for all traffic.
	BlockingActivationDegraded() bool
	Public() (PublicConfig, error)
	Save(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error)
	RuntimeState() (expected int64, active int64, loadedAt *time.Time, loadError string)
	Encrypt(value string) (string, error)
	Decrypt(value string) (string, error)
}

type StorageEndpoint struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	TokenCiphertext string `json:"token_ciphertext,omitempty"`
	TimeoutMS       int    `json:"timeout_ms"`
	InputLimit      int    `json:"input_limit"`
	Enabled         bool   `json:"enabled"`
}

type CategoryThresholdConfig struct {
	BlockThreshold string `json:"block_threshold,omitempty"`
	FlagThreshold  string `json:"flag_threshold,omitempty"`
}

type storageConfig struct {
	Enabled                bool                               `json:"enabled"`
	BlockingEnabled        bool                               `json:"blocking_enabled"`
	BlockingLatestTurnOnly bool                               `json:"blocking_latest_turn_only"`
	FailOpenOnGuardFailure bool                               `json:"fail_open_on_guard_failure"`
	BlockThreshold         string                             `json:"block_threshold"`
	FlagThreshold          string                             `json:"flag_threshold"`
	CategoryThresholds     map[string]CategoryThresholdConfig `json:"category_thresholds"`
	BlockStatus            int                                `json:"block_status"`
	BlockMessage           string                             `json:"block_message"`
	StorePassEvents        bool                               `json:"store_pass_events"`
	Strategy               string                             `json:"strategy"`
	WorkerCount            int                                `json:"worker_count"`
	QueueCapacity          int                                `json:"queue_capacity"`
	Scanners               []string                           `json:"scanners"`
	AllGroups              bool                               `json:"all_groups"`
	GroupIDs               []int64                            `json:"group_ids"`
	Endpoints              []StorageEndpoint                  `json:"endpoints"`
	ConfigVersion          int64                              `json:"config_version"`
	UpdatedAt              time.Time                          `json:"updated_at"`
	UpdatedBy              int64                              `json:"updated_by"`
	ChangeSummary          string                             `json:"change_summary"`
}

type ActiveEndpoint struct {
	ID         string
	Name       string
	Protocol   string
	BaseURL    string
	Model      string
	Token      string
	TimeoutMS  int
	InputLimit int
	Enabled    bool
	// TokenInvalid marks an endpoint whose persisted token ciphertext cannot be
	// decrypted with the current encryption key (key changed or auto-generated
	// on restart). The endpoint is kept visible for admins but excluded from
	// runtime use until the token is re-entered or cleared (issue #4887).
	TokenInvalid bool
}

type ActiveConfig struct {
	RiskControlEnabled     bool
	Enabled                bool
	BlockingEnabled        bool
	BlockingLatestTurnOnly bool
	FailOpenOnGuardFailure bool
	BlockThreshold         string
	FlagThreshold          string
	CategoryThresholds     map[string]CategoryThresholdConfig
	BlockStatus            int
	BlockMessage           string
	StorePassEvents        bool
	Strategy               string
	WorkerCount            int
	QueueCapacity          int
	Scanners               []string
	AllGroups              bool
	GroupIDs               []int64
	Endpoints              []ActiveEndpoint
	ConfigVersion          int64
	UpdatedAt              time.Time
	UpdatedBy              int64
	ChangeSummary          string
}

type PublicEndpoint struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	BaseURL     string `json:"base_url"`
	Model       string `json:"model"`
	TimeoutMS   int    `json:"timeout_ms"`
	InputLimit  int    `json:"input_limit"`
	Enabled     bool   `json:"enabled"`
	HasToken    bool   `json:"has_token"`
	TokenStatus string `json:"token_status"`
}

type PublicConfig struct {
	Enabled                bool                               `json:"enabled"`
	BlockingEnabled        bool                               `json:"blocking_enabled"`
	BlockingLatestTurnOnly bool                               `json:"blocking_latest_turn_only"`
	FailOpenOnGuardFailure bool                               `json:"fail_open_on_guard_failure"`
	BlockThreshold         string                             `json:"block_threshold"`
	FlagThreshold          string                             `json:"flag_threshold"`
	CategoryThresholds     map[string]CategoryThresholdConfig `json:"category_thresholds"`
	BlockStatus            int                                `json:"block_status"`
	BlockMessage           string                             `json:"block_message"`
	StorePassEvents        bool                               `json:"store_pass_events"`
	EffectiveMode          Mode                               `json:"effective_mode"`
	Strategy               string                             `json:"strategy"`
	WorkerCount            int                                `json:"worker_count"`
	QueueCapacity          int                                `json:"queue_capacity"`
	Scanners               []string                           `json:"scanners"`
	AllGroups              bool                               `json:"all_groups"`
	GroupIDs               []int64                            `json:"group_ids"`
	Endpoints              []PublicEndpoint                   `json:"endpoints"`
	ConfigVersion          int64                              `json:"config_version"`
	UpdatedAt              time.Time                          `json:"updated_at"`
	UpdatedBy              int64                              `json:"updated_by"`
	ChangeSummary          string                             `json:"change_summary"`
}

type UpdateEndpoint struct {
	ID         string `json:"id" binding:"required"`
	Name       string `json:"name" binding:"required"`
	Protocol   string `json:"protocol"`
	BaseURL    string `json:"base_url" binding:"required"`
	Model      string `json:"model"`
	Token      string `json:"token,omitempty"`
	ClearToken bool   `json:"clear_token"`
	TimeoutMS  int    `json:"timeout_ms"`
	InputLimit int    `json:"input_limit"`
	Enabled    bool   `json:"enabled"`
}

type UpdateConfigRequest struct {
	ExpectedConfigVersion  int64                              `json:"expected_config_version" binding:"required"`
	Enabled                bool                               `json:"enabled"`
	BlockingEnabled        bool                               `json:"blocking_enabled"`
	BlockingLatestTurnOnly bool                               `json:"blocking_latest_turn_only"`
	FailOpenOnGuardFailure bool                               `json:"fail_open_on_guard_failure"`
	BlockThreshold         string                             `json:"block_threshold"`
	FlagThreshold          string                             `json:"flag_threshold"`
	CategoryThresholds     map[string]CategoryThresholdConfig `json:"category_thresholds"`
	BlockStatus            int                                `json:"block_status"`
	BlockMessage           string                             `json:"block_message"`
	StorePassEvents        bool                               `json:"store_pass_events"`
	Strategy               string                             `json:"strategy"`
	WorkerCount            int                                `json:"worker_count"`
	QueueCapacity          int                                `json:"queue_capacity"`
	Scanners               []string                           `json:"scanners"`
	AllGroups              bool                               `json:"all_groups"`
	GroupIDs               []int64                            `json:"group_ids"`
	Endpoints              []UpdateEndpoint                   `json:"endpoints"`
}

func DefaultStorageConfig() storageConfig {
	return storageConfig{
		Enabled:                false,
		BlockingEnabled:        false,
		BlockingLatestTurnOnly: false,
		FailOpenOnGuardFailure: false,
		BlockThreshold:         DefaultBlockThreshold,
		FlagThreshold:          DefaultFlagThreshold,
		CategoryThresholds:     DefaultCategoryThresholds(),
		BlockStatus:            DefaultBlockStatus,
		BlockMessage:           DefaultBlockMessage,
		StorePassEvents:        false,
		Strategy:               "priority",
		WorkerCount:            DefaultWorkerCount,
		QueueCapacity:          DefaultQueueCapacity,
		Scanners:               append([]string(nil), AllScannerIDs...),
		AllGroups:              true,
		GroupIDs:               []int64{},
		Endpoints:              []StorageEndpoint{},
		ConfigVersion:          1,
	}
}

func ParseStorageConfig(raw string) (storageConfig, error) {
	cfg := DefaultStorageConfig()
	if strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return storageConfig{}, fmt.Errorf("decode prompt audit config: %w", err)
	}
	_, categoryThresholdsPresent := fields["category_thresholds"]
	if categoryThresholdsPresent {
		// An explicit empty object clears the compatibility defaults. A missing
		// field keeps them for configurations saved before per-category controls.
		cfg.CategoryThresholds = nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return storageConfig{}, fmt.Errorf("decode prompt audit config: %w", err)
	}
	if categoryThresholdsPresent && cfg.CategoryThresholds == nil {
		cfg.CategoryThresholds = map[string]CategoryThresholdConfig{}
	}
	normalizeStorageConfig(&cfg)
	if err := validateStorageConfig(cfg); err != nil {
		return storageConfig{}, err
	}
	return cfg, nil
}

func normalizeStorageConfig(cfg *storageConfig) {
	if cfg == nil {
		return
	}
	if cfg.ConfigVersion < 1 {
		cfg.ConfigVersion = 1
	}
	if strings.TrimSpace(cfg.Strategy) == "" {
		cfg.Strategy = "priority"
	}
	if cfg.WorkerCount == 0 {
		cfg.WorkerCount = DefaultWorkerCount
	}
	if cfg.QueueCapacity == 0 {
		cfg.QueueCapacity = DefaultQueueCapacity
	}
	cfg.BlockThreshold = canonicalSafetyLevel(cfg.BlockThreshold)
	cfg.FlagThreshold = canonicalSafetyLevel(cfg.FlagThreshold)
	cfg.CategoryThresholds = canonicalCategoryThresholds(cfg.CategoryThresholds)
	cfg.BlockMessage = strings.TrimSpace(cfg.BlockMessage)
	if len(cfg.Scanners) == 0 {
		cfg.Scanners = append([]string(nil), AllScannerIDs...)
	}
	cfg.Scanners = canonicalScannerIDs(cfg.Scanners)
	cfg.GroupIDs = canonicalInt64s(cfg.GroupIDs)
	// Preserve an invalid blocking-without-audit combination so validation can
	// reject it instead of silently changing administrator intent.
	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		ep.ID = strings.TrimSpace(ep.ID)
		ep.Name = strings.TrimSpace(ep.Name)
		ep.Protocol = strings.TrimSpace(ep.Protocol)
		if ep.Protocol == "" {
			ep.Protocol = "openai_compatible"
		}
		ep.BaseURL = strings.TrimSpace(ep.BaseURL)
		ep.Model = strings.TrimSpace(ep.Model)
		if ep.Model == "" {
			ep.Model = DefaultGuardModel
		}
		if ep.TimeoutMS == 0 {
			ep.TimeoutMS = DefaultTimeoutMS
		}
		if ep.InputLimit == 0 {
			ep.InputLimit = DefaultInputLimit
		}
	}
}

func validateStorageConfig(cfg storageConfig) error {
	if cfg.BlockingEnabled && !cfg.Enabled {
		return infraerrors.BadRequest(ErrorCodeRequiresEnabled, "开启同步阻止前必须先启用提示词审计")
	}
	if cfg.Strategy != "priority" {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 priority")
	}
	if cfg.WorkerCount < 1 || cfg.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if cfg.QueueCapacity < 1 || cfg.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if err := validateDecisionSettings(cfg.BlockThreshold, cfg.FlagThreshold, cfg.BlockStatus, cfg.BlockMessage); err != nil {
		return err
	}
	if err := validateCategoryThresholds(cfg.BlockThreshold, cfg.FlagThreshold, cfg.CategoryThresholds); err != nil {
		return err
	}
	if !cfg.AllGroups && len(cfg.GroupIDs) == 0 {
		return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
	}
	if len(cfg.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	seen := make(map[string]struct{}, len(cfg.Endpoints))
	enabled := 0
	for _, ep := range cfg.Endpoints {
		if ep.ID == "" || ep.Name == "" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "审计节点 ID 和名称不能为空")
		}
		if _, ok := seen[ep.ID]; ok {
			return infraerrors.BadRequest("prompt_audit_duplicate_endpoint", "审计节点 ID 不能重复")
		}
		seen[ep.ID] = struct{}{}
		if ep.Protocol != "openai_compatible" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_protocol", "审计节点仅支持 OpenAI 兼容协议")
		}
		if _, err := NormalizeBaseURL(ep.BaseURL); err != nil {
			return err
		}
		if ep.TimeoutMS < MinTimeoutMS || ep.TimeoutMS > MaxTimeoutMS {
			return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时超出允许范围")
		}
		if ep.InputLimit < MinInputLimit || ep.InputLimit > MaxInputLimit {
			return infraerrors.BadRequest("prompt_audit_invalid_input_limit", "审计节点输入上限超出允许范围")
		}
		if ep.Enabled {
			enabled++
		}
	}
	if cfg.Enabled && enabled == 0 {
		return infraerrors.BadRequest("prompt_audit_endpoint_required", "启用提示词审计前至少需要启用一个审计节点")
	}
	return nil
}

func validateUpdateConfigRequest(req UpdateConfigRequest) error {
	if strings.TrimSpace(req.Strategy) != "priority" {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 priority")
	}
	if req.WorkerCount < 1 || req.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if req.QueueCapacity < 1 || req.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if err := validateDecisionSettings(req.BlockThreshold, req.FlagThreshold, req.BlockStatus, req.BlockMessage); err != nil {
		return err
	}
	if err := validateCategoryThresholds(req.BlockThreshold, req.FlagThreshold, req.CategoryThresholds); err != nil {
		return err
	}
	if len(req.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	for _, scanner := range req.Scanners {
		if _, ok := ScannerCatalog[NormalizeCategory(scanner)]; !ok {
			return infraerrors.BadRequest("prompt_audit_invalid_scanner", "提示词审计风险分类无效")
		}
	}
	if !req.AllGroups {
		if len(req.GroupIDs) == 0 {
			return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
		}
		for _, groupID := range req.GroupIDs {
			if groupID <= 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_group", "提示词审计分组 ID 无效")
			}
		}
	}
	for _, endpoint := range req.Endpoints {
		if endpoint.TimeoutMS < MinTimeoutMS || endpoint.TimeoutMS > MaxTimeoutMS {
			return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时超出允许范围")
		}
		if endpoint.InputLimit < MinInputLimit || endpoint.InputLimit > MaxInputLimit {
			return infraerrors.BadRequest("prompt_audit_invalid_input_limit", "审计节点输入上限超出允许范围")
		}
	}
	return nil
}

func validateDecisionSettings(blockThreshold, flagThreshold string, blockStatus int, blockMessage string) error {
	blockRank, blockValid := safetyLevelRank(blockThreshold)
	if !blockValid {
		return infraerrors.BadRequest("prompt_audit_invalid_block_threshold", "阻断阈值必须是 Safe、Controversial 或 Unsafe")
	}
	flagRank, flagValid := safetyLevelRank(flagThreshold)
	if !flagValid {
		return infraerrors.BadRequest("prompt_audit_invalid_flag_threshold", "标记阈值必须是 Safe、Controversial 或 Unsafe")
	}
	if flagRank > blockRank {
		return infraerrors.BadRequest("prompt_audit_invalid_threshold_order", "标记阈值不能高于阻断阈值")
	}
	if blockStatus < 400 || blockStatus > 499 {
		return infraerrors.BadRequest("prompt_audit_invalid_block_status", "拦截响应状态码必须在 400 到 499 之间")
	}
	message := strings.TrimSpace(blockMessage)
	if message == "" || len([]rune(message)) > MaxBlockMessageRunes {
		return infraerrors.BadRequest("prompt_audit_invalid_block_message", "拦截提示文案不能为空且不能超过 512 个字符")
	}
	return nil
}

func validateCategoryThresholds(globalBlock, globalFlag string, values map[string]CategoryThresholdConfig) error {
	for category, thresholds := range values {
		category = NormalizeCategory(category)
		if _, ok := ScannerCatalog[category]; !ok {
			return infraerrors.BadRequest("prompt_audit_invalid_category_threshold", "分类阈值包含未知风险分类")
		}
		block := thresholds.BlockThreshold
		if strings.TrimSpace(block) == "" {
			block = globalBlock
		}
		blockRank, blockValid := safetyLevelRank(block)
		if !blockValid {
			return infraerrors.BadRequest("prompt_audit_invalid_category_block_threshold", "分类阻断阈值必须是 Safe、Controversial、Unsafe 或留空继承全局")
		}
		flag := thresholds.FlagThreshold
		if strings.TrimSpace(flag) == "" {
			flag = globalFlag
		}
		flagRank, flagValid := safetyLevelRank(flag)
		if !flagValid {
			return infraerrors.BadRequest("prompt_audit_invalid_category_flag_threshold", "分类标记阈值必须是 Safe、Controversial、Unsafe 或留空继承全局")
		}
		if flagRank > blockRank {
			return infraerrors.BadRequest("prompt_audit_invalid_category_threshold_order", "分类的有效标记阈值不能高于有效阻断阈值")
		}
	}
	return nil
}

func canonicalSafetyLevel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "safe":
		return "Safe"
	case "controversial":
		return "Controversial"
	case "unsafe":
		return "Unsafe"
	default:
		return strings.TrimSpace(value)
	}
}

func safetyLevelRank(value string) (int, bool) {
	switch canonicalSafetyLevel(value) {
	case "Safe":
		return 0, true
	case "Controversial":
		return 1, true
	case "Unsafe":
		return 2, true
	default:
		return 0, false
	}
}

func DefaultCategoryThresholds() map[string]CategoryThresholdConfig {
	return map[string]CategoryThresholdConfig{
		"pii":                   {BlockThreshold: "Controversial"},
		"suicide_and_self_harm": {BlockThreshold: "Controversial"},
		"jailbreak":             {BlockThreshold: "Controversial"},
	}
}

func canonicalCategoryThresholds(values map[string]CategoryThresholdConfig) map[string]CategoryThresholdConfig {
	if values == nil {
		return nil
	}
	result := make(map[string]CategoryThresholdConfig, len(values))
	for category, thresholds := range values {
		result[NormalizeCategory(category)] = CategoryThresholdConfig{
			BlockThreshold: canonicalOptionalSafetyLevel(thresholds.BlockThreshold),
			FlagThreshold:  canonicalOptionalSafetyLevel(thresholds.FlagThreshold),
		}
	}
	return result
}

func canonicalOptionalSafetyLevel(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return canonicalSafetyLevel(value)
}

func cloneCategoryThresholds(values map[string]CategoryThresholdConfig) map[string]CategoryThresholdConfig {
	if values == nil {
		return nil
	}
	result := make(map[string]CategoryThresholdConfig, len(values))
	for category, thresholds := range values {
		result[category] = thresholds
	}
	return result
}

func (cfg ActiveConfig) EffectiveMode() Mode {
	if !cfg.RiskControlEnabled || !cfg.Enabled {
		return ModeOff
	}
	if cfg.BlockingEnabled {
		return ModeBlocking
	}
	return ModeAsync
}

func (cfg ActiveConfig) IncludesGroup(groupID *int64) bool {
	if cfg.AllGroups {
		return true
	}
	if groupID == nil {
		return false
	}
	i := sort.Search(len(cfg.GroupIDs), func(i int) bool { return cfg.GroupIDs[i] >= *groupID })
	return i < len(cfg.GroupIDs) && cfg.GroupIDs[i] == *groupID
}

func (cfg ActiveConfig) EnabledEndpoints() []ActiveEndpoint {
	result := make([]ActiveEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		if ep.Enabled {
			result = append(result, ep)
		}
	}
	return result
}

// InvalidTokenEndpointIDs lists endpoints whose stored token could not be
// decrypted with the current encryption key.
func (cfg ActiveConfig) InvalidTokenEndpointIDs() []string {
	ids := make([]string, 0)
	for _, ep := range cfg.Endpoints {
		if ep.TokenInvalid {
			ids = append(ids, ep.ID)
		}
	}
	return ids
}

func PublicFromStorage(cfg storageConfig, riskControlEnabled bool, invalidTokenEndpointIDs []string) PublicConfig {
	invalid := make(map[string]struct{}, len(invalidTokenEndpointIDs))
	for _, id := range invalidTokenEndpointIDs {
		invalid[id] = struct{}{}
	}
	scanners := append([]string{}, cfg.Scanners...)
	groupIDs := append([]int64{}, cfg.GroupIDs...)
	endpoints := make([]PublicEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		hasToken := strings.TrimSpace(ep.TokenCiphertext) != ""
		status := "missing"
		if hasToken {
			status = "configured"
			if _, ok := invalid[ep.ID]; ok {
				status = "invalid"
			}
		}
		endpoints = append(endpoints, PublicEndpoint{
			ID: ep.ID, Name: ep.Name, Protocol: ep.Protocol, BaseURL: ep.BaseURL,
			Model: ep.Model, TimeoutMS: ep.TimeoutMS, InputLimit: ep.InputLimit,
			Enabled: ep.Enabled, HasToken: hasToken, TokenStatus: status,
		})
	}
	active := ActiveConfig{RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled}
	return PublicConfig{
		Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled, BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly,
		FailOpenOnGuardFailure: cfg.FailOpenOnGuardFailure, BlockThreshold: cfg.BlockThreshold,
		FlagThreshold: cfg.FlagThreshold, CategoryThresholds: cloneCategoryThresholds(cfg.CategoryThresholds),
		BlockStatus: cfg.BlockStatus, BlockMessage: cfg.BlockMessage,
		StorePassEvents: cfg.StorePassEvents,
		EffectiveMode:   active.EffectiveMode(), Strategy: cfg.Strategy, WorkerCount: cfg.WorkerCount,
		QueueCapacity: cfg.QueueCapacity, Scanners: scanners, AllGroups: cfg.AllGroups,
		GroupIDs: groupIDs, Endpoints: endpoints, ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
	}
}

func ActiveFromStorage(cfg storageConfig, riskControlEnabled bool, encryptor SecretEncryptor) (ActiveConfig, error) {
	active := ActiveConfig{
		RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled,
		BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly, FailOpenOnGuardFailure: cfg.FailOpenOnGuardFailure,
		BlockThreshold: cfg.BlockThreshold, FlagThreshold: cfg.FlagThreshold,
		CategoryThresholds: cloneCategoryThresholds(cfg.CategoryThresholds),
		BlockStatus:        cfg.BlockStatus, BlockMessage: cfg.BlockMessage,
		StorePassEvents: cfg.StorePassEvents, Strategy: cfg.Strategy, WorkerCount: cfg.WorkerCount,
		QueueCapacity: cfg.QueueCapacity, Scanners: append([]string(nil), cfg.Scanners...), AllGroups: cfg.AllGroups,
		GroupIDs: append([]int64(nil), cfg.GroupIDs...), ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
		Endpoints: make([]ActiveEndpoint, 0, len(cfg.Endpoints)),
	}
	for _, ep := range cfg.Endpoints {
		token := ""
		tokenInvalid := false
		if ep.TokenCiphertext != "" {
			if encryptor == nil {
				return ActiveConfig{}, fmt.Errorf("prompt audit secret encryptor unavailable")
			}
			plain, err := encryptor.Decrypt(ep.TokenCiphertext)
			if err != nil {
				// An undecryptable token (encryption key changed or regenerated)
				// must not take the whole config down: admins would otherwise be
				// locked out of the real config version and unable to recover
				// (issue #4887). Keep the ciphertext persisted, but exclude the
				// endpoint from runtime use until the token is re-entered.
				tokenInvalid = true
			} else {
				token = plain
			}
		}
		active.Endpoints = append(active.Endpoints, ActiveEndpoint{
			ID: ep.ID, Name: ep.Name, Protocol: ep.Protocol, BaseURL: ep.BaseURL, Model: ep.Model,
			Token: token, TimeoutMS: ep.TimeoutMS, InputLimit: ep.InputLimit,
			Enabled: ep.Enabled && !tokenInvalid, TokenInvalid: tokenInvalid,
		})
	}
	return active, nil
}

func changeSummary(cfg storageConfig) string {
	summary := struct {
		Enabled                bool   `json:"enabled"`
		BlockingEnabled        bool   `json:"blocking_enabled"`
		BlockingLatestTurnOnly bool   `json:"blocking_latest_turn_only"`
		FailOpenOnGuardFailure bool   `json:"fail_open_on_guard_failure"`
		BlockThreshold         string `json:"block_threshold"`
		FlagThreshold          string `json:"flag_threshold"`
		CategoryThresholdCount int    `json:"category_threshold_count"`
		CategoryThresholdHash  string `json:"category_threshold_hash"`
		BlockStatus            int    `json:"block_status"`
		BlockMessageHash       string `json:"block_message_hash"`
		StorePassEvents        bool   `json:"store_pass_events"`
		EndpointCount          int    `json:"endpoint_count"`
		ScannerCount           int    `json:"scanner_count"`
		AllGroups              bool   `json:"all_groups"`
		GroupCount             int    `json:"group_count"`
		GroupHash              string `json:"group_hash"`
	}{
		Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled,
		BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly, FailOpenOnGuardFailure: cfg.FailOpenOnGuardFailure,
		BlockThreshold: cfg.BlockThreshold, FlagThreshold: cfg.FlagThreshold,
		CategoryThresholdCount: len(cfg.CategoryThresholds), BlockStatus: cfg.BlockStatus,
		StorePassEvents: cfg.StorePassEvents, EndpointCount: len(cfg.Endpoints), ScannerCount: len(cfg.Scanners),
		AllGroups: cfg.AllGroups, GroupCount: len(cfg.GroupIDs),
	}
	rawGroups, _ := json.Marshal(cfg.GroupIDs)
	digest := sha256.Sum256(rawGroups)
	summary.GroupHash = hex.EncodeToString(digest[:])
	messageDigest := sha256.Sum256([]byte(cfg.BlockMessage))
	summary.BlockMessageHash = hex.EncodeToString(messageDigest[:])
	rawCategoryThresholds, _ := json.Marshal(cfg.CategoryThresholds)
	categoryThresholdDigest := sha256.Sum256(rawCategoryThresholds)
	summary.CategoryThresholdHash = hex.EncodeToString(categoryThresholdDigest[:])
	raw, _ := json.Marshal(summary)
	return string(raw)
}

func canonicalInt64s(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func canonicalScannerIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id := NormalizeCategory(value)
		if _, ok := ScannerCatalog[id]; ok {
			seen[id] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for _, id := range AllScannerIDs {
		if _, ok := seen[id]; ok {
			result = append(result, id)
		}
	}
	return result
}
