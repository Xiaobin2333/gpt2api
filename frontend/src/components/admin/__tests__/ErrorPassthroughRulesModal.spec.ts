import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import ErrorPassthroughRulesModal from '../ErrorPassthroughRulesModal.vue'

const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), update: vi.fn() }))
const showError = vi.hoisted(() => vi.fn())
vi.mock('@/api/admin', () => ({ adminAPI: { errorPassthrough: api } }))
vi.mock('@/stores/app', () => ({ useAppStore: () => ({ showError, showSuccess: vi.fn() }) }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

const rule = (id: number, name: string, account_ids: number[], platforms: string[] = []) => ({
  id, name, account_ids, platforms, enabled: true, priority: id,
  error_codes: [403], keywords: [], match_mode: 'any', passthrough_code: true,
  passthrough_body: true, response_code: null, custom_message: null,
  description: null, skip_monitoring: false
})

async function open(account: { id: number; name: string; platform: string } | null = null) {
  const wrapper = mount(ErrorPassthroughRulesModal, {
    props: { show: false, account },
    global: { stubs: {
      BaseDialog: { props: ['show'], template: '<div v-if="show"><slot /><slot name="footer" /></div>' },
      ConfirmDialog: true, Icon: true
    } }
  })
  await wrapper.setProps({ show: true })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  api.list.mockResolvedValue([
    rule(1, 'global-rule', []), rule(2, 'account-seven', [7]),
    rule(3, 'account-eight', [8]), rule(4, 'other-platform', [], ['openai'])
  ])
  api.create.mockResolvedValue({})
})

describe('account error passthrough rules', () => {
  it('shows applicable global and account rules together in priority order', async () => {
    const wrapper = await open({ id: 7, name: 'Kimi account', platform: 'kimi' })
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]!.text()).toContain('global-rule')
    expect(rows[1]!.text()).toContain('account-seven')
    wrapper.unmount()
  })

  it('prefills account scope and rejects invalid IDs instead of broadening to global', async () => {
    const wrapper = await open({ id: 7, name: 'Kimi account', platform: 'kimi' })
    await wrapper.findAll('button').find(b => b.text() === 'admin.errorPassthrough.createRule')!.trigger('click')
    const ids = wrapper.get('#passthrough-account-ids')
    expect((ids.element as HTMLInputElement).value).toBe('7')
    await wrapper.get('input[placeholder="admin.errorPassthrough.form.namePlaceholder"]').setValue('new rule')
    await wrapper.get('input[placeholder="admin.errorPassthrough.form.errorCodesPlaceholder"]').setValue('403')
    await ids.setValue('invalid')
    await wrapper.get('form').trigger('submit')
    expect(api.create).not.toHaveBeenCalled()
    expect(showError).toHaveBeenCalledWith('admin.errorPassthrough.invalidAccountIDs')
    await ids.setValue('7, 7, 8')
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(api.create).toHaveBeenCalledWith(expect.objectContaining({ account_ids: [7, 8] }))
    wrapper.unmount()
  })

  it('keeps the global entry unfiltered and defaults new rules to global', async () => {
    const wrapper = await open()
    expect(wrapper.findAll('tbody tr')).toHaveLength(4)
    await wrapper.findAll('button').find(b => b.text() === 'admin.errorPassthrough.createRule')!.trigger('click')
    expect((wrapper.get('#passthrough-account-ids').element as HTMLInputElement).value).toBe('')
    wrapper.unmount()
  })
})
