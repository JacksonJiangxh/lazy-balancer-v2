import { test } from 'node:test'
import assert from 'node:assert/strict'

import { initialNodeSiteForm, nearestSiteLocation, nodeSiteCoordsChanged } from '../src/utils/siteLocation.ts'
import { validateClusterUrl } from '../src/utils/clusterUrl.ts'
import { repoSource, section, source } from './_helpers.ts'

// 问题：继承主节点默认坐标的节点（site_inherited=true，列表接口返回的
// server_map_lat/lon 是主节点坐标副本），弹框初值必须还原为 0,0 + 空选择——
// 不得把继承值预填为可保存值（原样保存会把继承静默固化为显式坐标）。
test('继承节点表单初值还原为 0,0 + 空选择', () => {
  const form = initialNodeSiteForm({ server_map_lat: 35.19, server_map_lon: 108.87, site_inherited: true })
  assert.equal(form.lat, 0)
  assert.equal(form.lon, 0)
  assert.equal(form.siteLocationKey, '')
})

test('显式坐标节点表单初值保留自身坐标并回显最近地点', () => {
  const form = initialNodeSiteForm({ server_map_lat: 40.19, server_map_lon: 116.42, site_inherited: false })
  assert.equal(form.lat, 40.19)
  assert.equal(form.lon, 116.42)
  assert.equal(form.siteLocationKey, nearestSiteLocation(40.19, 116.42))
  assert.notEqual(form.siteLocationKey, '')
})

test('无变更保存判定为 no-op（直接关闭，不发 PUT 不 bump）', () => {
  assert.equal(nodeSiteCoordsChanged({ lat: 0, lon: 0 }, { lat: 0, lon: 0 }), false)
  assert.equal(nodeSiteCoordsChanged({ lat: 31.23, lon: 121.47 }, { lat: 31.23, lon: 121.47 }), false)
  assert.equal(nodeSiteCoordsChanged({ lat: 0, lon: 0 }, { lat: 31.23, lon: 121.47 }), true)
  assert.equal(nodeSiteCoordsChanged({ lat: 31.23, lon: 121.47 }, { lat: 0, lon: 0 }), true)
})

// 主节点地址与节点访问地址在后端共用 models.ValidateClusterAccessURL
// （scheme∈{http,https}、host 非空、无 userinfo/query/fragment）。前端曾两份实现
// ——主节点地址只校验 scheme，带凭证/query 的地址到提交时才被后端拒绝（晚失败）。
// 本条把共享校验器逐条对表后端规则，并钉住两个弹框的单源接线。
test('主节点地址与访问地址共用校验器（后端 ValidateClusterAccessURL 同规则）', () => {
  // 规则集机械对表：「后端仍拒绝这五类输入」是前端文案/行为的依据；Go 侧
  // 删改任一条件（而前端继续拒绝）即红。Go 未来新增条件无法机械推断前端
  // 等价实现，须人工同步并加到这里。
  const go = section(repoSource('internal/models/cluster.go'), 'func ValidateClusterAccessURL(', '\n}\n')
  for (const condition of [
    'parsed.Scheme != "http" && parsed.Scheme != "https"',
    'parsed.Host == ""',
    'parsed.User != nil',
    'parsed.RawQuery != ""',
    'parsed.Fragment != ""',
  ]) {
    assert.ok(go.includes(condition), `后端校验条件与前端对表项缺失：${condition}`)
  }
  const url = (value: string, label = '访问地址') => validateClusterUrl(value, { label })
  assert.equal(url(''), null, '访问地址允许留空（回退注册地址）')
  assert.equal(validateClusterUrl('', { label: '主节点地址', emptyMessage: '请输入主节点地址' }), '请输入主节点地址')
  assert.equal(url('https://master.example.com:8000'), null)
  assert.equal(url('http://127.0.0.1:8001/'), null)
  assert.equal(url('ftp://master:21'), '访问地址必须使用 HTTP 或 HTTPS')
  assert.equal(url('not a url'), '访问地址格式不正确')
  assert.equal(url('https://user:pass@master:8000'), '访问地址不能包含用户名或密码')
  assert.equal(url('https://master:8000/?x=1'), '访问地址不能包含查询参数')
  assert.equal(url('https://master:8000/#frag'), '访问地址不能包含片段')
  assert.equal(validateClusterUrl('https://user@master', { label: '主节点地址' }), '主节点地址不能包含用户名或密码')

  const dialog = source('src/views/settings/cluster/ClusterNodeConfigDialog.vue')
  const card = source('src/views/settings/cluster/ClusterModeCard.vue')
  for (const vue of [dialog, card]) {
    assert.match(vue, /import \{ validateClusterUrl \} from '@\/utils\/clusterUrl'/)
  }
  assert.doesNotMatch(section(dialog, 'const validateAccessUrl', 'const rules'), /new URL\(/)
  assert.doesNotMatch(section(card, 'const validateMasterUrl', 'const rules'), /new URL\(/)
})
