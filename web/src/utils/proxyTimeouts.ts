// 代理超时字段定义与预览摘要单源。
//
// 表单控件（components/rules/ProxyTimeoutFields.vue）与规则向导的「配置预览」
// 必须给出同一组字段标签与继承语义——预览曾漏掉整组 7 项，用户只能保存后从
// 单规则配置查看器发现改错。字段描述/建议值只在此维护，控件与预览都读它。
//
// 上限口径：后端 rule_features.go 仅校验「不能为负」与 flush_interval >= -1，
// 无上限——长连接/流式（SSE/LLM 长响应、WebSocket 代理）合法需要 >24h。
// 前端不设 max，避免把带外/导入的更大值静默夹回。
import type { ProxyTimeoutConfig } from '@/types/rules.ts'

interface ProxyTimeoutField {
  readonly key: keyof ProxyTimeoutConfig
  readonly label: string
  readonly min: number
  readonly desc: string
  readonly suggest?: number
}

export const PROXY_TIMEOUT_FIELDS: readonly ProxyTimeoutField[] = [
  { key: 'proxy_dial_timeout', label: '连接超时', min: 0, desc: '建立到上游 TCP 连接', suggest: 10 },
  { key: 'proxy_response_header_timeout', label: '响应头超时', min: 0, desc: '等待上游响应头返回', suggest: 30 },
  { key: 'proxy_read_timeout', label: '读超时', min: 0, desc: '两次读上游数据的间隔；流式需大于静默期', suggest: 60 },
  { key: 'proxy_write_timeout', label: '写超时', min: 0, desc: '两次写客户端的间隔；流式需大于静默期', suggest: 60 },
  { key: 'proxy_stream_timeout', label: '流式超时', min: 0, desc: '整个流式会话总时长；用于 SSE/LLM' },
  { key: 'proxy_flush_interval', label: '刷新间隔', min: -1, desc: '默认仅 SSE 无缓冲；-1=所有响应无缓冲；>0=每 N 秒一次' },
  { key: 'proxy_stream_close_delay', label: '流关闭延迟', min: 0, desc: '>0=reload 时延迟 N 秒关旧 WebSocket/SSE' },
]

/** 单个超时值的人读形态：0=继承全局；-1=立即透传（仅刷新间隔）。 */
const timeoutValueLabel = (field: keyof ProxyTimeoutConfig, value: number | undefined): string => {
  const seconds = value ?? 0
  if (field === 'proxy_flush_interval') {
    if (seconds === -1) return '立即透传'
    return seconds > 0 ? `${seconds}s` : '全局'
  }
  return seconds > 0 ? `${seconds}s` : '全局'
}

/** 预览用一行摘要：七项全列，避免任何一项在核对面缺席。 */
export const proxyTimeoutSummary = (value: ProxyTimeoutConfig): string =>
  PROXY_TIMEOUT_FIELDS
    .map((field) => `${field.label} ${timeoutValueLabel(field.key, value[field.key])}`)
    .join(' / ')
