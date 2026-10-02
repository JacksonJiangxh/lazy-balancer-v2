import Prism from 'prismjs'
import 'prismjs/themes/prism-okaidia.css'
import 'prismjs/components/prism-markup'
import 'prismjs/components/prism-css'
import 'prismjs/components/prism-clike'
import 'prismjs/components/prism-apacheconf'
import 'prismjs/components/prism-nginx'
import 'prismjs/components/prism-http'
import 'prismjs/components/prism-ini'
import 'prismjs/components/prism-json'
import { escapeHtml } from '@/utils/escape'

export const highlightCode = (content: string, language: string): string => {
  if (!content) return ''
  const lang = language || 'markup'
  const grammar = Prism.languages[lang] || Prism.languages.markup
  try {
    return Prism.highlight(content, grammar, lang)
  } catch {
    // FE65-9：兜底转义收敛到 utils/escape 的 escapeHtml（含引号转义，与 ansi/
    // branding 版同口径），HTML 属性上下文复用该输出不再有引号注入面
    return escapeHtml(content)
  }
}
