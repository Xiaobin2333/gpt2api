import type {
  PromptAuditConfig,
  PromptAuditCategoryThresholds,
  PromptAuditDraft,
  PromptAuditEndpointDraft,
  PromptAuditSafety,
  PromptAuditUpdateRequest,
  PromptEventFilters,
} from './types'

export const DEFAULT_GUARD_MODEL = 'sileader/qwen3guard:0.6b'
export const SAFETY_LEVELS = ['Safe', 'Controversial', 'Unsafe'] as const satisfies readonly PromptAuditSafety[]
export const DEFAULT_BLOCK_THRESHOLD: PromptAuditSafety = 'Unsafe'
export const DEFAULT_FLAG_THRESHOLD: PromptAuditSafety = 'Controversial'
export const DEFAULT_CATEGORY_THRESHOLDS: PromptAuditCategoryThresholds = {
  pii: { block_threshold: 'Controversial' },
  suicide_and_self_harm: { block_threshold: 'Controversial' },
  jailbreak: { block_threshold: 'Controversial' },
}
export const DEFAULT_BLOCK_STATUS = 403
export const DEFAULT_BLOCK_MESSAGE = '请检查你的提示词，本次请求被审计系统拦截。'

export const SCANNER_CATALOG = [
  { id: 'violent', label: 'Violent' },
  { id: 'non_violent_illegal_acts', label: 'Non-violent Illegal Acts' },
  { id: 'sexual_content_or_sexual_acts', label: 'Sexual Content or Sexual Acts' },
  { id: 'pii', label: 'PII' },
  { id: 'suicide_and_self_harm', label: 'Suicide & Self-Harm' },
  { id: 'unethical_acts', label: 'Unethical Acts' },
  { id: 'politically_sensitive_topics', label: 'Politically Sensitive Topics' },
  { id: 'copyright_violation', label: 'Copyright Violation' },
  { id: 'jailbreak', label: 'Jailbreak' },
] as const

// Vue props/refs are proxies and cannot be passed to structuredClone in every
// browser. Prompt Audit state is JSON-only, so this produces a detached draft
// without retaining reactive proxies or browser storage references.
export function cloneData<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

export function configToDraft(config: PromptAuditConfig): PromptAuditDraft {
  return {
    ...cloneData(config),
    block_threshold: safetyLevelOrDefault(config.block_threshold, DEFAULT_BLOCK_THRESHOLD),
    flag_threshold: safetyLevelOrDefault(config.flag_threshold, DEFAULT_FLAG_THRESHOLD),
    category_thresholds: normalizeCategoryThresholds(config.category_thresholds),
    block_status: Number.isInteger(config.block_status) ? config.block_status : DEFAULT_BLOCK_STATUS,
    block_message: config.block_message?.trim() || DEFAULT_BLOCK_MESSAGE,
    group_ids: [...(config.group_ids ?? [])],
    scanners: [...(config.scanners ?? [])],
    endpoints: (config.endpoints ?? []).map((endpoint) => ({
      ...endpoint,
      token: '',
      clear_token: false,
    })),
  }
}

export function createDefaultEndpoint(index = 1): PromptAuditEndpointDraft {
  return {
    id: `guard-${Date.now()}-${index}`,
    name: `Guard ${index}`,
    protocol: 'openai_compatible',
    base_url: 'http://127.0.0.1:8000',
    model: DEFAULT_GUARD_MODEL,
    timeout_ms: 3000,
    input_limit: 4000,
    enabled: true,
    has_token: false,
    token_status: 'missing',
    token: '',
    clear_token: false,
  }
}

export function buildUpdateRequest(draft: PromptAuditDraft): PromptAuditUpdateRequest {
  return {
    expected_config_version: draft.config_version,
    enabled: draft.enabled,
    blocking_enabled: draft.enabled && draft.blocking_enabled,
    blocking_latest_turn_only: draft.blocking_latest_turn_only,
    fail_open_on_guard_failure: draft.fail_open_on_guard_failure,
    block_threshold: draft.block_threshold,
    flag_threshold: draft.flag_threshold,
    category_thresholds: normalizeCategoryThresholds(draft.category_thresholds, false),
    block_status: Number(draft.block_status),
    block_message: draft.block_message.trim(),
    store_pass_events: draft.store_pass_events,
    strategy: 'priority',
    worker_count: Number(draft.worker_count),
    queue_capacity: Number(draft.queue_capacity),
    scanners: [...draft.scanners],
    all_groups: draft.all_groups,
    group_ids: draft.all_groups ? [] : [...draft.group_ids].sort((a, b) => a - b),
    endpoints: draft.endpoints.map((endpoint) => ({
      id: endpoint.id.trim(),
      name: endpoint.name.trim(),
      protocol: 'openai_compatible',
      base_url: endpoint.base_url.trim(),
      model: endpoint.model.trim() || DEFAULT_GUARD_MODEL,
      token: endpoint.token.trim() || undefined,
      clear_token: endpoint.clear_token,
      timeout_ms: Number(endpoint.timeout_ms),
      input_limit: Number(endpoint.input_limit),
      enabled: endpoint.enabled,
    })),
  }
}

function safetyLevelOrDefault(value: unknown, fallback: PromptAuditSafety): PromptAuditSafety {
  return SAFETY_LEVELS.includes(value as PromptAuditSafety) ? (value as PromptAuditSafety) : fallback
}

function normalizeCategoryThresholds(value: unknown, useCompatibilityDefaults = true): PromptAuditCategoryThresholds {
  const source = value && typeof value === 'object'
    ? value as Record<string, { block_threshold?: unknown; flag_threshold?: unknown }>
    : useCompatibilityDefaults ? DEFAULT_CATEGORY_THRESHOLDS : {}
  const normalized: PromptAuditCategoryThresholds = {}
  for (const scanner of SCANNER_CATALOG) {
    const thresholds = source[scanner.id]
    if (!thresholds || typeof thresholds !== 'object') continue
    const block = SAFETY_LEVELS.includes(thresholds.block_threshold as PromptAuditSafety)
      ? thresholds.block_threshold as PromptAuditSafety
      : undefined
    const flag = SAFETY_LEVELS.includes(thresholds.flag_threshold as PromptAuditSafety)
      ? thresholds.flag_threshold as PromptAuditSafety
      : undefined
    if (block || flag) normalized[scanner.id] = { block_threshold: block, flag_threshold: flag }
  }
  return normalized
}

export function draftFingerprint(draft: PromptAuditDraft | null): string {
  if (!draft) return ''
  return JSON.stringify(buildUpdateRequest(draft))
}

export function emptyEventFilters(): PromptEventFilters {
  return {
    decision: '',
    risk_level: '',
    endpoint: '',
    group_id: '',
    user_id: '',
    api_key_id: '',
    request_id: '',
    prompt_hash: '',
    keyword: '',
    start_at: '',
    end_at: '',
  }
}

function toISO(value: string): string | undefined {
  if (!value.trim()) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

export function eventQueryParams(filters: PromptEventFilters): Record<string, string | number> {
  const result: Record<string, string | number> = {}
  for (const key of ['decision', 'risk_level', 'endpoint', 'request_id', 'prompt_hash', 'keyword'] as const) {
    const value = filters[key].trim()
    if (value) result[key] = value
  }
  for (const key of ['group_id', 'user_id', 'api_key_id'] as const) {
    const value = Number(filters[key])
    if (Number.isInteger(value) && value > 0) result[key] = value
  }
  const start = toISO(filters.start_at)
  const end = toISO(filters.end_at)
  if (start) result.start_at = start
  if (end) result.end_at = end
  return result
}

export function eventFilterPayload(filters: PromptEventFilters): Record<string, unknown> {
  return eventQueryParams(filters)
}

export function hasExplicitDeleteRange(filters: PromptEventFilters): boolean {
  const start = toISO(filters.start_at)
  const end = toISO(filters.end_at)
  return Boolean(start && end && new Date(start).getTime() < new Date(end).getTime())
}

export type DeleteRangePreset = '1d' | '7d' | '30d' | '90d' | 'all' | 'custom'

export const DELETE_RANGE_PRESETS: ReadonlyArray<{ id: DeleteRangePreset; days: number | null }> = [
  { id: '1d', days: 1 },
  { id: '7d', days: 7 },
  { id: '30d', days: 30 },
  { id: '90d', days: 90 },
  { id: 'all', days: null },
  { id: 'custom', days: null },
]

const DAY_MS = 24 * 60 * 60 * 1000

// Presets delete events older than the chosen cutoff: the range always starts
// at the epoch and ends at (now - days) so the backend's explicit-range
// requirement is satisfied without asking the user for a begin date.
export function resolveDeleteRangeFilters(
  filters: PromptEventFilters,
  preset: DeleteRangePreset,
  now: number = Date.now(),
): PromptEventFilters {
  const resolved = cloneData(filters)
  if (preset === 'custom') return resolved
  const days = DELETE_RANGE_PRESETS.find((item) => item.id === preset)?.days ?? null
  resolved.start_at = new Date(0).toISOString()
  resolved.end_at = new Date(days === null ? now : now - days * DAY_MS).toISOString()
  return resolved
}
