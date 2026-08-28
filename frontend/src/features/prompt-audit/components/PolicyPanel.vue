<template>
  <section aria-labelledby="prompt-policy-title" class="py-6">
    <div>
      <h2 id="prompt-policy-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.policy.title') }}</h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.policy.description') }}</p>
    </div>

    <div class="mt-5 grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(260px,0.45fr)]">
      <div class="rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
        <fieldset>
          <legend class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.policy.scope') }}</legend>
          <div class="mt-3 flex flex-wrap gap-5 text-sm text-gray-700 dark:text-dark-200">
            <label class="flex items-center gap-2">
              <input type="radio" name="prompt-audit-scope" :checked="draft.all_groups" @change="patch({ all_groups: true, group_ids: [] })" />
              {{ t('admin.promptAudit.policy.allGroups') }}
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" name="prompt-audit-scope" :checked="!draft.all_groups" @change="patch({ all_groups: false })" />
              {{ t('admin.promptAudit.policy.selectedGroups') }}
            </label>
          </div>
        </fieldset>

        <div v-if="!draft.all_groups" class="mt-4">
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.policy.searchGroups') }}</span>
            <input v-model="groupSearch" type="search" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.searchGroups')" />
          </label>
          <div class="mt-3 max-h-52 overflow-y-auto rounded-lg border border-gray-200 p-2 dark:border-dark-700">
            <label v-for="group in filteredGroups" :key="group.id" class="flex cursor-pointer items-center justify-between gap-3 rounded-md px-2 py-2 text-sm hover:bg-gray-50 dark:hover:bg-dark-800">
              <span class="flex items-center gap-2 text-gray-800 dark:text-dark-100">
                <input type="checkbox" :checked="draft.group_ids.includes(group.id)" @change="toggleGroup(group.id)" />
                {{ group.name }}
              </span>
              <span class="text-xs text-gray-500 dark:text-dark-400">{{ group.platform }} · {{ group.status }}</span>
            </label>
            <p v-if="filteredGroups.length === 0" class="px-2 py-4 text-center text-sm text-gray-500">{{ t('admin.promptAudit.policy.noGroups') }}</p>
          </div>
          <div v-if="missingGroupIds.length" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
            {{ t('admin.promptAudit.policy.missingGroups') }}: {{ missingGroupIds.join(', ') }}
          </div>
          <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.selectedCount', { count: draft.group_ids.length }) }}</p>
        </div>

        <fieldset class="mt-5 border-t border-gray-100 pt-5 dark:border-dark-800">
          <legend class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.policy.scanners') }}</legend>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.categoryThresholdsHint') }}</p>
          <div class="mt-3 divide-y divide-gray-100 dark:divide-dark-800">
            <div v-for="scanner in SCANNER_CATALOG" :key="scanner.id" class="grid grid-cols-2 gap-3 py-3 first:pt-1 sm:grid-cols-[minmax(180px,1fr)_minmax(150px,0.7fr)_minmax(150px,0.7fr)] sm:items-end">
              <label class="col-span-2 flex min-h-10 items-center gap-2 text-sm text-gray-700 dark:text-dark-200 sm:col-span-1">
                <input type="checkbox" :checked="draft.scanners.includes(scanner.id)" :aria-label="scannerLabel(scanner.id)" @change="toggleScanner(scanner.id)" />
                <span>{{ scannerLabel(scanner.id) }}</span>
              </label>
              <label class="block text-xs text-gray-600 dark:text-dark-300">
                <span>{{ t('admin.promptAudit.policy.categoryBlockThreshold') }}</span>
                <select :value="categoryThreshold(scanner.id, 'block_threshold')" class="input mt-1 w-full" :data-test="`category-block-${scanner.id}`" :aria-label="`${scannerLabel(scanner.id)} · ${t('admin.promptAudit.policy.categoryBlockThreshold')}`" @change="setCategoryThreshold(scanner.id, 'block_threshold', ($event.target as HTMLSelectElement).value)">
                  <option value="">{{ t('admin.promptAudit.policy.inheritGlobal', { level: safetyLabel(draft.block_threshold) }) }}</option>
                  <option v-for="level in SAFETY_LEVELS" :key="level" :value="level">{{ safetyLabel(level) }}</option>
                </select>
              </label>
              <label class="block text-xs text-gray-600 dark:text-dark-300">
                <span>{{ t('admin.promptAudit.policy.categoryFlagThreshold') }}</span>
                <select :value="categoryThreshold(scanner.id, 'flag_threshold')" class="input mt-1 w-full" :data-test="`category-flag-${scanner.id}`" :aria-label="`${scannerLabel(scanner.id)} · ${t('admin.promptAudit.policy.categoryFlagThreshold')}`" @change="setCategoryThreshold(scanner.id, 'flag_threshold', ($event.target as HTMLSelectElement).value)">
                  <option value="">{{ t('admin.promptAudit.policy.inheritGlobal', { level: safetyLabel(draft.flag_threshold) }) }}</option>
                  <option v-for="level in SAFETY_LEVELS" :key="level" :value="level">{{ safetyLabel(level) }}</option>
                </select>
              </label>
            </div>
          </div>
        </fieldset>
      </div>

      <div class="space-y-4 rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5">
        <div>
          <h3 class="text-sm font-medium text-gray-900 dark:text-white">{{ t('admin.promptAudit.policy.decisionSettings') }}</h3>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.decisionSettingsHint') }}</p>
        </div>
        <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.policy.blockThreshold') }}</span>
            <select :value="draft.block_threshold" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.blockThreshold')" @change="patch({ block_threshold: ($event.target as HTMLSelectElement).value as PromptAuditSafety })">
              <option v-for="level in SAFETY_LEVELS" :key="level" :value="level">{{ t(`admin.promptAudit.policy.safetyLevels.${level}`) }}</option>
            </select>
            <span class="mt-1 block text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.blockThresholdHint') }}</span>
          </label>
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.policy.flagThreshold') }}</span>
            <select :value="draft.flag_threshold" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.flagThreshold')" @change="patch({ flag_threshold: ($event.target as HTMLSelectElement).value as PromptAuditSafety })">
              <option v-for="level in SAFETY_LEVELS" :key="level" :value="level">{{ t(`admin.promptAudit.policy.safetyLevels.${level}`) }}</option>
            </select>
            <span class="mt-1 block text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.flagThresholdHint') }}</span>
          </label>
        </div>
        <label class="block text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.policy.blockStatus') }}</span>
          <input :value="draft.block_status" type="number" min="400" max="499" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.blockStatus')" @input="patch({ block_status: Number(($event.target as HTMLInputElement).value) })" />
          <span class="mt-1 block text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.blockStatusHint') }}</span>
        </label>
        <label class="block text-sm text-gray-700 dark:text-dark-200">
          <span>{{ t('admin.promptAudit.policy.blockMessage') }}</span>
          <textarea :value="draft.block_message" rows="3" maxlength="512" class="input mt-1.5 w-full resize-y" :aria-label="t('admin.promptAudit.policy.blockMessage')" @input="patch({ block_message: ($event.target as HTMLTextAreaElement).value })" />
          <span class="mt-1 block text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.policy.blockMessageHint') }}</span>
        </label>
        <div class="space-y-4 border-t border-gray-100 pt-4 dark:border-dark-800">
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.policy.workerCount') }}</span>
            <input :value="draft.worker_count" type="number" min="1" max="32" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.workerCount')" @input="patch({ worker_count: Number(($event.target as HTMLInputElement).value) })" />
          </label>
          <label class="block text-sm text-gray-700 dark:text-dark-200">
            <span>{{ t('admin.promptAudit.policy.queueCapacity') }}</span>
            <input :value="draft.queue_capacity" type="number" min="1" max="100000" class="input mt-1.5 w-full" :aria-label="t('admin.promptAudit.policy.queueCapacity')" @input="patch({ queue_capacity: Number(($event.target as HTMLInputElement).value) })" />
          </label>
          <div class="rounded-lg bg-gray-50 px-4 py-3 text-sm text-gray-600 dark:bg-dark-900/50 dark:text-dark-300">
            <p class="font-medium text-gray-800 dark:text-dark-100">{{ t('admin.promptAudit.policy.strategy') }}</p>
            <p class="mt-1">priority · {{ t('admin.promptAudit.policy.strategyHint') }}</p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PromptAuditDraft, PromptAuditGroup, PromptAuditSafety } from '../types'
import { cloneData, SAFETY_LEVELS, SCANNER_CATALOG } from '../viewModel'

const props = defineProps<{ draft: PromptAuditDraft; groups: PromptAuditGroup[] }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { t } = useI18n()
const groupSearch = ref('')

const filteredGroups = computed(() => {
  const query = groupSearch.value.trim().toLowerCase()
  if (!query) return props.groups
  return props.groups.filter((group) => `${group.name} ${group.id} ${group.platform}`.toLowerCase().includes(query))
})
const knownGroupIds = computed(() => new Set(props.groups.map((group) => group.id)))
const missingGroupIds = computed(() => props.draft.group_ids.filter((id) => !knownGroupIds.value.has(id)))

function patch(value: Partial<PromptAuditDraft>) {
  emit('update:draft', { ...cloneData(props.draft), ...value })
}
function toggleGroup(id: number) {
  const selected = new Set(props.draft.group_ids)
  if (selected.has(id)) selected.delete(id)
  else selected.add(id)
  patch({ group_ids: [...selected].sort((a, b) => a - b) })
}
function toggleScanner(id: string) {
  const selected = new Set(props.draft.scanners)
  if (selected.has(id)) selected.delete(id)
  else selected.add(id)
  patch({ scanners: SCANNER_CATALOG.map((item) => item.id).filter((item) => selected.has(item)) })
}
function categoryThreshold(id: string, field: 'block_threshold' | 'flag_threshold'): string {
  return props.draft.category_thresholds[id]?.[field] ?? ''
}
function setCategoryThreshold(id: string, field: 'block_threshold' | 'flag_threshold', value: string) {
  const thresholds = cloneData(props.draft.category_thresholds ?? {})
  const category = { ...(thresholds[id] ?? {}) }
  if (SAFETY_LEVELS.includes(value as PromptAuditSafety)) category[field] = value as PromptAuditSafety
  else delete category[field]
  if (category.block_threshold || category.flag_threshold) thresholds[id] = category
  else delete thresholds[id]
  patch({ category_thresholds: thresholds })
}
function scannerLabel(id: string): string {
  return t(`admin.promptAudit.scanners.${id}`)
}
function safetyLabel(level: PromptAuditSafety): string {
  return t(`admin.promptAudit.policy.safetyLevels.${level}`)
}
</script>
