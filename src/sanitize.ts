import { createHash } from 'node:crypto'
import { classify } from './detect.js'
import type { Change, SanitizeResult } from './types.js'

function pseudonym(category: string, value: string): string {
  const digest = createHash('sha256').update(`harbor-har:v1:${category}:${value}`).digest('hex').slice(0, 12)
  if (category === 'email') return `user-${digest}@example.invalid`
  if (category === 'ip-address') return `192.0.2.${(Number.parseInt(digest.slice(0, 2), 16) % 253) + 1}`
  return `[HARbor:${category}:${digest}]`
}

export function sanitizeHar(input: unknown): SanitizeResult {
  const clone = structuredClone(input)
  const changes: Change[] = []
  const visit = (value: unknown, path: string, key = ''): unknown => {
    if (typeof value === 'string') {
      const hit = classify(path, key, value)
      if (!hit) return value
      const placeholder = pseudonym(hit.category, value)
      changes.push({ path, category: hit.category, severity: hit.severity, confidence: hit.confidence, fingerprint: hit.fingerprint, placeholder })
      return placeholder
    }
    if (Array.isArray(value)) return value.map((item, index) => visit(item, `${path}[${index}]`, key))
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>
      if (typeof record.name === 'string' && typeof record.value === 'string') {
        const hit = classify(`${path}.value`, record.name, record.value)
        if (hit) {
          const placeholder = pseudonym(hit.category, record.value)
          changes.push({ path: `${path}.value`, category: hit.category, severity: hit.severity, confidence: hit.confidence, fingerprint: hit.fingerprint, placeholder })
          record.value = placeholder
        }
      }
      for (const [childKey, child] of Object.entries(record)) {
        if (childKey === 'value' && typeof record.name === 'string') continue
        record[childKey] = visit(child, `${path}.${childKey}`, childKey)
      }
    }
    return value
  }
  return { har: visit(clone, '$'), manifest: { version: 1, changes } }
}
