import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'

import { copyText } from '../src/utils/copy.ts'
import { scheduleEditUntouched } from '../src/utils/securityLibraries.ts'
import { popperViewportSafe } from '../src/utils/popper.ts'
import { member, section, source, stripComments } from './_helpers.ts'

// 零引用产品单元的覆盖补齐：
// - copy.ts：Safari/内网非 HTTPS 必走的 textarea + execCommand 降级路径，
//   失败静默返回 false（调用方据此提示）——分支错则复制功能整体失效；
// - scheduleEditUntouched：父级轮询回填判据，判错会覆盖用户编辑中的值；
// - proxy 超时字段集 / popper 选项 / echarts 注册点 / 集群同步错误展示接线。

interface FakeTextarea {
  value: string
  readonly style: Record<string, string>
  readonly attributes: Record<string, string>
  removed: boolean
  setAttribute(name: string, value: string): void
  select(): void
  setSelectionRange(start: number, end: number): void
  remove(): void
}

interface CopyHost {
  readonly log: string[]
  readonly textareas: FakeTextarea[]
  restore(): void
}

/** 注入最小 document/navigator 宿主（按描述符还原，node 的 navigator 只有 getter）。 */
const installCopyHost = (options: {
  clipboard?: { writeText(text: string): Promise<void> }
  execCommand?: () => boolean
}): CopyHost => {
  const documentDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'document')
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
  const log: string[] = []
  const textareas: FakeTextarea[] = []
  const documentStub = {
    body: { appendChild: () => { log.push('append') } },
    createElement: (tag: string): FakeTextarea => {
      log.push(`create:${tag}`)
      const node: FakeTextarea = {
        value: '',
        style: {},
        attributes: {},
        removed: false,
        setAttribute(name, value) { node.attributes[name] = value },
        select() { log.push('select') },
        setSelectionRange(start, end) { log.push(`range:${start}-${end}`) },
        remove() { node.removed = true; log.push('remove') },
      }
      textareas.push(node)
      return node
    },
    execCommand: (command: string) => {
      log.push(`exec:${command}`)
      return options.execCommand ? options.execCommand() : false
    },
  }
  Object.defineProperty(globalThis, 'document', { value: documentStub, configurable: true, writable: true })
  Object.defineProperty(globalThis, 'navigator', {
    value: options.clipboard ? { clipboard: options.clipboard } : {},
    configurable: true,
    writable: true,
  })
  return {
    log,
    textareas,
    restore: () => {
      if (documentDescriptor) Object.defineProperty(globalThis, 'document', documentDescriptor)
      else Reflect.deleteProperty(globalThis, 'document')
      if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor)
      else Reflect.deleteProperty(globalThis, 'navigator')
      assert.deepEqual(Object.getOwnPropertyDescriptor(globalThis, 'document'), documentDescriptor, 'document 必须还原')
      assert.deepEqual(Object.getOwnPropertyDescriptor(globalThis, 'navigator'), navigatorDescriptor, 'navigator 必须还原')
    },
  }
}

test('copyText：clipboard 可用时直接成功，不创建降级节点', async (t) => {
  const copied: string[] = []
  const host = installCopyHost({ clipboard: { writeText: async (text) => { copied.push(text) } }, execCommand: () => true })
  t.after(host.restore)
  assert.equal(await copyText('hello'), true)
  assert.deepEqual(copied, ['hello'])
  assert.equal(host.log.some((entry) => entry.startsWith('create:')), false, 'clipboard 成功不得走 textarea 降级')
})

test('copyText：clipboard 缺失时降级 textarea + execCommand，成功返回 true 并移除节点', async (t) => {
  const host = installCopyHost({ execCommand: () => true })
  t.after(host.restore)
  assert.equal(await copyText('api-key'), true)
  assert.equal(host.textareas.length, 1)
  const textarea = host.textareas[0]
  assert.equal(textarea?.value, 'api-key')
  assert.equal(textarea?.attributes.readonly, '', '降级节点须只读（避免移动端键盘弹出）')
  assert.deepEqual(textarea?.style, { position: 'fixed', opacity: '0', pointerEvents: 'none' })
  assert.deepEqual(host.log, ['create:textarea', 'append', 'select', 'range:0-7', 'exec:copy', 'remove'])
  assert.equal(textarea?.removed, true)
})

test('copyText：clipboard 被拒时降级成功，仍返回 true', async (t) => {
  const host = installCopyHost({ clipboard: { writeText: async () => { throw new Error('denied') } }, execCommand: () => true })
  t.after(host.restore)
  assert.equal(await copyText('x'), true)
  assert.ok(host.log.includes('exec:copy'), '拒绝必须降级')
})

test('copyText：拒绝且 execCommand 为 false 时如实返回 false', async (t) => {
  const host = installCopyHost({ clipboard: { writeText: async () => { throw new Error('denied') } }, execCommand: () => false })
  t.after(host.restore)
  assert.equal(await copyText('x'), false)
  assert.equal(host.textareas[0]?.removed, true, '失败路径也必须移除节点')
})

test('copyText：execCommand 抛错不外抛，按失败返回并移除节点', async (t) => {
  const host = installCopyHost({ execCommand: () => { throw new Error('blocked') } })
  t.after(host.restore)
  assert.equal(await copyText('x'), false)
  assert.equal(host.textareas[0]?.removed, true)
})

test('scheduleEditUntouched：未编辑才回填，编辑中不得覆盖用户输入', () => {
  assert.equal(scheduleEditUntouched({ days: [1, 3], time: '04:00' }, { days: [1, 3], time: '04:00' }), true)
  assert.equal(scheduleEditUntouched({ days: [1, 3], time: '05:00' }, { days: [1, 3], time: '04:00' }), false, '改过时间不得回填')
  assert.equal(scheduleEditUntouched({ days: [2], time: '04:00' }, { days: [1, 3], time: '04:00' }), false, '改过星期不得回填')
  assert.equal(scheduleEditUntouched({ days: [1, 2], time: '04:00' }, { days: [2, 1], time: '04:00' }), false, '星期顺序敏感')
  assert.equal(scheduleEditUntouched({ days: [1], time: '04:00' }, { days: [1], time: '' }), true, '上一次时间为空按默认 04:00 比较')
  assert.equal(scheduleEditUntouched({ days: [], time: '04:00' }, {}), true, '上一次缺失按空/默认比较')
})

test('ProxyTimeoutFields：字段集与 ProxyTimeoutConfig 同集同序，undefined 归一为 0', () => {
  const types = source('src/types/rules.ts')
  const block = section(types, 'export interface ProxyTimeoutConfig {', '\n}')
  const typeKeys = [...block.matchAll(/^\s+(proxy_\w+):/gm)].map((m) => m[1])
  assert.ok(typeKeys.length >= 7, `ProxyTimeoutConfig 键解析失败（${typeKeys.length}）`)

  const component = source('src/components/rules/ProxyTimeoutFields.vue')
  const fieldKeys = [...component.matchAll(/\{ key: '(proxy_\w+)'/g)].map((m) => m[1])
  assert.deepEqual(fieldKeys, typeKeys, '字段集/顺序必须与类型单源一致（漏字段即静默不可编辑）')

  const update = member(component, 'const update = ')
  assert.match(update, /emit\('update', field, value \?\? 0\)/, 'undefined 归一到 0（后端不接受 null）')
})

test('popper：flip 四向回退 + preventOverflow 8px 视口余量', () => {
  assert.equal(popperViewportSafe.modifiers.length, 2)
  const [flip, preventOverflow] = popperViewportSafe.modifiers
  assert.equal(flip?.name, 'flip')
  assert.deepEqual(flip?.options, { fallbackPlacements: ['right', 'left', 'top', 'bottom'] })
  assert.equal(preventOverflow?.name, 'preventOverflow')
  assert.deepEqual(preventOverflow?.options, { padding: 8 })
})

test('echarts 全站单一注册点：只有 utils/echarts 引内核，三页面必须引注册模块', () => {
  const walk = (dir: URL): URL[] => {
    const files: URL[] = []
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const child = new URL(`${entry.name}${entry.isDirectory() ? '/' : ''}`, dir)
      if (entry.isDirectory()) files.push(...walk(child))
      else files.push(child)
    }
    return files
  }
  const srcRoot = new URL('../src/', import.meta.url)
  const offenders: string[] = []
  for (const file of walk(srcRoot)) {
    if (!/\.(?:ts|vue)$/.test(file.pathname)) continue
    const relative = file.pathname.slice(srcRoot.pathname.length)
    const text = stripComments(readFileSync(file, 'utf8'))
    if (/from ['"]echarts\//.test(text) && relative !== 'utils/echarts.ts') offenders.push(relative)
  }
  assert.deepEqual(offenders, [], '内核 import 只允许出现在 utils/echarts.ts（注册面随路由漂移会静默缺序列）')

  const echarts = source('src/utils/echarts.ts')
  for (const symbol of ['CanvasRenderer', 'LineChart', 'PieChart', 'BarChart', 'GridComponent', 'TooltipComponent', 'LegendComponent']) {
    assert.match(echarts, new RegExp(`\\b${symbol}\\b`), `注册面缺少 ${symbol}`)
  }
  for (const page of ['src/views/Dashboard.vue', 'src/views/security/SecurityOverview.vue', 'src/views/settings/TaskMonitor.vue']) {
    assert.match(stripComments(source(page)), /import '@\/utils\/echarts'/, `${page} 必须引统一注册模块`)
  }
})

test('集群同步错误展示单源：两个面板都消费 formatSyncErrorDisplay，不得复刻标记翻译', () => {
  for (const file of [
    'src/views/settings/cluster/ClusterSlavePanel.vue',
    'src/views/settings/cluster/ClusterStatusCard.vue',
  ]) {
    const text = stripComments(source(file))
    assert.match(text, /formatSyncErrorDisplay\(props\.status\)/, `${file} 必须消费共享翻译`)
    assert.doesNotMatch(text, /apply_ok_reload_failed/, `${file} 不得复刻机内标记`)
  }
})
