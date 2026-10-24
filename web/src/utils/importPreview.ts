/**
 * 导入预览校验的复用层。
 *
 * 预览校验只按所选分类过滤校验面，备份字节始终是同一份——每次勾选分类都重传
 * 整份备份（上限 128MB）是纯带宽浪费，连续切换时还会让多轮上传互相抢带宽。
 * 本模块按「内容指纹 + 所选分类」缓存校验结果，并在新选择到来时取消上一轮
 * 在途请求（旧选择的结果已被取代，没必要把整份备份传完）。
 *
 * 缓存只影响预览文案：确认导入时后端对同一份字节重跑完整校验（校验和 + 行级
 * 门），冲突/警告以那次真实结果为准，陈旧预览不会让问题备份被静默写入。
 *
 * 预览事实依赖服务端当时的库状态，故缓存有两条时效边界：条目 TTL 5 分钟，且
 * 导入/还原弹框每次打开时由调用方 invalidateImportPreviews() 清空。
 */

/** 单个会话的校验结果缓存上限（一份备份通常只会被勾选几次；防止长会话无界增长）。 */
const MAX_CACHED_PREVIEWS = 32

/** 缓存有效期。预览事实（冲突、悬挂告警、策略引用）依赖服务端「当时」的库
 *  状态，而键只有内容指纹 + 分类集合——不加时效就可能在配置改变后仍返回旧
 *  预览（管理员刚删掉一个 CA 提供商，预览却仍显示无悬挂告警）。 */
const PREVIEW_CACHE_TTL_MS = 5 * 60 * 1000

interface PreviewCacheEntry {
  readonly value: unknown
  readonly at: number
}

const previewCache = new Map<string, PreviewCacheEntry>()

/**
 * 清空跨会话预览缓存。
 *
 * 导入/还原弹框每次打开时调用：用户可能在两次预览之间改了配置（删 CA 提供商、
 * 改规则），旧结果已不代表当前库状态。TTL 只是第二道保险，打开弹框即清空才能
 * 保证「同一份备份的第二次预览 = 当前库状态」。
 */
export const invalidateImportPreviews = (): void => {
  previewCache.clear()
}

export interface ImportPreviewResult<T> {
  readonly value: T
  /** true = 命中缓存（未发起请求）。 */
  readonly cached: boolean
}

export interface ImportPreviewSession<T> {
  /** 校验所选分类；命中缓存直接返回，否则发请求并取消上一轮在途请求。 */
  validate(sections: readonly string[]): Promise<ImportPreviewResult<T>>
  /** 关闭弹框/换文件：取消在途请求。 */
  dispose(): void
}

export interface ImportPreviewSessionOptions<T> {
  /** 备份内容指纹（见 importPreviewFingerprint）；同指纹跨会话复用缓存。 */
  readonly fingerprint: string
  /** 发送一次预览校验；signal 在新选择到来或 dispose 时被 abort。 */
  readonly send: (sections: readonly string[], signal: AbortSignal) => Promise<T>
}

export const createImportPreviewSession = <T>(options: ImportPreviewSessionOptions<T>): ImportPreviewSession<T> => {
  let controller: AbortController | null = null
  return {
    async validate(sections) {
      // 分类集合与顺序无关（后端按集合过滤），去重排序后才是一个稳定的键
      const key = `${options.fingerprint}\u0000${[...new Set(sections)].sort().join(',')}`
      const cached = previewCache.get(key)
      if (cached && Date.now() - cached.at < PREVIEW_CACHE_TTL_MS) {
        return { value: cached.value as T, cached: true }
      }
      if (cached) previewCache.delete(key)
      controller?.abort()
      const current = new AbortController()
      controller = current
      try {
        const value = await options.send(sections, current.signal)
        previewCache.set(key, { value, at: Date.now() })
        if (previewCache.size > MAX_CACHED_PREVIEWS) {
          const oldest = previewCache.keys().next()
          if (!oldest.done) previewCache.delete(oldest.value)
        }
        return { value, cached: false }
      } finally {
        if (controller === current) controller = null
      }
    },
    dispose() {
      controller?.abort()
      controller = null
    },
  }
}

/** 指纹采样窗口：首尾各 512KB（或 512K 字符）。 */
const FINGERPRINT_SAMPLE = 512 * 1024

/**
 * 备份内容指纹 = FNV-1a(首段采样 + 尾段采样) + 长度。
 *
 * 只作缓存键，不做完整性校验（完整性由后端校验和负责），故用非加密滚动哈希：
 * `crypto.subtle` 在非安全上下文（面板常经 `http://<host>:8000` 访问）不可用，
 * 依赖它会让「选文件」在 HTTP 访问下直接失败。整份摘要也做不到——lbbak 直传
 * Blob 的意义就是不在标签页里再复制一份最大 128MB 的备份字节；采样指纹足以
 * 区分「同一份备份」与「换了一份备份」：同一内容稳定复现，长度或首尾采样变化
 * 即分离。
 */
export const importPreviewFingerprint = async (content: string | Blob): Promise<string> => {
  const encoder = new TextEncoder()
  const head = typeof content === 'string'
    ? encoder.encode(content.slice(0, FINGERPRINT_SAMPLE))
    : new Uint8Array(await content.slice(0, FINGERPRINT_SAMPLE).arrayBuffer())
  const tail = typeof content === 'string'
    ? encoder.encode(content.slice(-FINGERPRINT_SAMPLE))
    : new Uint8Array(await content.slice(Math.max(0, content.size - FINGERPRINT_SAMPLE)).arrayBuffer())
  const size = typeof content === 'string' ? content.length : content.size
  let hash = 2166136261
  for (const chunk of [head, tail]) {
    for (const byte of chunk) {
      hash = Math.imul(hash ^ byte, 16777619)
    }
  }
  return `fnv1a:${(hash >>> 0).toString(16)}:${size}`
}
