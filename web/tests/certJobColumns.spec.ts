// 证书任务表「按容器宽收敛」：固定列宽会把表格撑出卡片容器产生水平滚动条
// （实测 1366/1280/1024 视口均有滚动）。收敛口径 = 容器不足时按优先级隐藏
// 低价值列，并把被隐藏列的信息并入相邻单元格（规则 ID→域名副行、冷却→重试
// tooltip）。收敛下限 = 不可让位列合计 619px：容器 ≥619px 由 .cert-jobs-wrap
// 的 overflow:hidden 兜底（卡片/页面级不出现横向滚动）；<619px 切
// .cert-jobs-wrap--scroll 的 overflow-x:auto——可滚动优先，操作列保持可达。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section, source } from './_helpers.ts'
import {
  CERT_JOB_COLUMNS,
  CERT_JOB_COLUMNS_MIN_WIDTH,
  CERT_JOB_COLUMN_WIDTHS,
  certJobColumnsWidth,
  pickVisibleCertJobColumns,
} from '../src/utils/certJobColumns.ts'

const page = source('src/views/settings/CertJobs.vue')
const tableBody = section(page, 'class="cert-jobs-table"', '</el-table>')

test('模板列宽必须取自单源表（列数与总宽基线由表布局用例承担）', () => {
  for (const id of CERT_JOB_COLUMNS) {
    const width = CERT_JOB_COLUMN_WIDTHS[id]
    assert.ok(width > 0, `${id} 缺少正宽度`)
  }
  // 组件模板里每个宽度都必须能在常量表找到（防两处漂移）；列数/1209 总宽
  // 由 certJobsTableLayout（按 label 的映射更严）唯一承担，不在此重复。
  const declared = [...tableBody.matchAll(/(?:min-)?width="(\d+)"/g)].map((m) => Number(m[1]))
  assert.ok(declared.length > 0)
  for (const w of declared) {
    assert.ok(Object.values(CERT_JOB_COLUMN_WIDTHS).includes(w), `组件宽度 ${w} 不在单源表内`)
  }
})

test('贪心让位：容器不足时按优先级隐藏，且隐藏后合计不超过容器', () => {
  // 让位顺序：冷却 → 颁发者 → 自动重签 → 更新时间 → 规则 ID（主键最后让位）
  const cases: Array<{ width: number; hidden: string[] }> = [
    { width: 1268, hidden: [] },
    { width: 1209, hidden: [] },
    { width: 1140, hidden: ['cooling'] },
    { width: 1066, hidden: ['cooling', 'issuer'] },
    { width: 980, hidden: ['cooling', 'issuer', 'renewal'] },
    { width: 860, hidden: ['cooling', 'issuer', 'renewal', 'updated'] },
    { width: 600, hidden: ['cooling', 'issuer', 'renewal', 'updated', 'rule_id'] },
  ]
  for (const { width, hidden } of cases) {
    const visible = pickVisibleCertJobColumns(width)
    for (const id of hidden) assert.equal(visible.has(id as never), false, `${width}px 应隐藏 ${id}`)
    for (const id of ['domain', 'status', 'validity', 'attempts', 'actions'] as const) {
      assert.equal(visible.has(id), true, `${width}px 不得隐藏 ${id}`)
    }
    const total = certJobColumnsWidth(visible)
    if (hidden.length < 5) {
      assert.ok(total <= width, `${width}px 可见列合计 ${total} 仍超出容器`)
    } else {
      // 让位耗尽后仍可能超宽：不可让位列合计 619px > 600px 容器——此时由消费方
      // 切 .cert-jobs-wrap--scroll 横向滚动（见下方用例），该超宽是显式口径而
      // 非断言豁免。
      assert.ok(total > width, `${width}px 让位耗尽后合计 ${total} 应仍超宽（下限 619px）`)
      assert.equal(total, CERT_JOB_COLUMNS_MIN_WIDTH)
    }
  }
})

test('容器宽度未知（未测量）时按全列渲染，不闪列', () => {
  assert.equal(pickVisibleCertJobColumns(Number.POSITIVE_INFINITY).size, CERT_JOB_COLUMNS.length)
  assert.equal(pickVisibleCertJobColumns(0).size, CERT_JOB_COLUMNS.length)
  assert.equal(pickVisibleCertJobColumns(Number.NaN).size, CERT_JOB_COLUMNS.length)
})

test('组件接线：ResizeObserver 驱动列让位且卸载时断开', () => {
  assert.match(page, /new ResizeObserver\(/)
  assert.match(page, /tableWrapObserver\?\.disconnect\(\)/)
  assert.match(page, /const visibleColumns = computed\(\(\) => pickVisibleCertJobColumns\(/)
  // 可让位列必须条件渲染
  for (const id of ['rule_id', 'issuer', 'renewal', 'updated', 'cooling']) {
    assert.match(tableBody, new RegExp(`v-if="visibleColumns\\.has\\('${id}'\\)"`), `${id} 列缺少条件渲染`)
  }
  // 不可让位列不得挂条件
  for (const id of ['domain', 'status', 'validity', 'attempts', 'actions']) {
    assert.doesNotMatch(tableBody, new RegExp(`visibleColumns\\.has\\('${id}'\\)`), `${id} 列不应被隐藏`)
  }
})

test('隐藏列信息不丢失：规则 ID 并入域名副行、冷却并入重试 tooltip', () => {
  const domainCol = section(tableBody, 'label="域名"', '</el-table-column>')
  assert.match(domainCol, /v-if="!visibleColumns\.has\('rule_id'\)"/)
  assert.match(domainCol, /#\{\{ row\.rule_id \}\}/)
  const attemptsCol = section(tableBody, 'label="重试次数"', '</el-table-column>')
  assert.match(attemptsCol, /coolingHint\(row\)/)
})

test('容器 overflow 裁断，杜绝卡片/页面级横向滚动', () => {
  const style = section(page, '<style scoped>', '</style>')
  assert.match(style, /\.cert-jobs-wrap\s*\{[^}]*overflow:\s*hidden/)
})

test('冷却提示文案形态：waiting_ca 且带冷却时间时返回「冷却：…」', () => {
  const wrap = member(code('src/views/settings/CertJobs.vue'), 'const coolingHint')
  assert.match(wrap, /冷却：/, '冷却提示并入重试 tooltip 的文案形态')
  assert.match(wrap, /row\.status !== 'waiting_ca'/, '非 waiting_ca 不得显示冷却提示')
  assert.match(wrap, /!row\.ca_available_after/, '冷却时间缺失必须先返回（否则显示「冷却：」空值）')
})
