// Markdown -> sanitized HTML, for remote content (release notes).
import { marked } from 'marked'
import DOMPurify from 'dompurify'

// Links open in a new tab, without leaking the opener.
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A') {
    node.setAttribute('target', '_blank')
    node.setAttribute('rel', 'noopener noreferrer')
  }
})

export function renderMarkdown(src) {
  if (!src) return ''
  return DOMPurify.sanitize(marked.parse(String(src), { gfm: true, breaks: false, async: false }), {
    FORBID_TAGS: ['style', 'img', 'iframe', 'form', 'input'],
  })
}
