// 系统设置分页清单单源（utils/settingsPages）：Settings.vue 页头标题/描述与
// AppLayout.vue 面包屑曾各持一份映射——此处钉住单源数据本身（含现有可见文案，
// 改名必须显式改这里）、页键映射，以及两处消费方不再自带第二份字面量。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  SETTINGS_BREADCRUMB_PARENT,
  SETTINGS_TAB_DESCS,
  SETTINGS_TAB_IDS,
  SETTINGS_TAB_TITLES,
  settingsTabOfPage,
} from '../src/utils/settingsPages.ts'
import { source } from './_helpers.ts'

test('分页清单：页键 ↔ 页头标题/描述一一对应（可见文案即契约）', () => {
  assert.deepEqual([...SETTINGS_TAB_IDS], ['basic', 'cluster', 'certificates', 'apikeys', 'tasks'])
  assert.deepEqual(SETTINGS_TAB_TITLES, {
    basic: '基础设置',
    cluster: '集群管理',
    certificates: '免费证书',
    apikeys: 'API 密钥',
    tasks: '任务监控',
  })
  assert.deepEqual(SETTINGS_TAB_DESCS, {
    basic: '配置系统日志、访问日志和基础行为',
    cluster: '配置主从节点模式和同步策略',
    certificates: '配置 ACME 邮箱、DNS 提供商和证书签发任务',
    apikeys: '管理 API 访问密钥',
    tasks: '全部定时与后台任务的运行监控、手动触发与取消',
  })
  assert.equal(SETTINGS_BREADCRUMB_PARENT, '系统设置')
})

test('分页清单：settings-<tab> 页键可逆映射，非设置页与未知分页返回 null', () => {
  for (const tab of SETTINGS_TAB_IDS) {
    assert.equal(settingsTabOfPage(`settings-${tab}`), tab)
  }
  assert.equal(settingsTabOfPage('dashboard'), null)
  assert.equal(settingsTabOfPage('security-policies'), null)
  assert.equal(settingsTabOfPage('settings-unknown'), null)
  assert.equal(settingsTabOfPage('settings-'), null)
})

test('分页清单：两处消费方共用单源，不再自带第二份映射', () => {
  const settings = source('src/views/Settings.vue')
  assert.match(settings, /from '@\/utils\/settingsPages'/)
  assert.match(settings, /SETTINGS_TAB_TITLES\[activeTab\.value\]/)
  assert.match(settings, /settingsTabOfPage\(authStore\.currentPage\) \?\? 'basic'/)
  assert.doesNotMatch(settings, /const titles: Record<string, string>/)
  assert.doesNotMatch(settings, /const descs: Record<string, string>/)

  const layout = source('src/components/layout/AppLayout.vue')
  assert.match(layout, /from '@\/utils\/settingsPages'/)
  assert.match(layout, /SETTINGS_TAB_IDS\.map\(\(tab\) => \[`settings-\$\{tab\}`, `\$\{SETTINGS_BREADCRUMB_PARENT\} \/ \$\{SETTINGS_TAB_TITLES\[tab\]\}`\]\)/)
  assert.doesNotMatch(layout, /'settings-basic': '系统设置 \/ 基础设置'/)
})
