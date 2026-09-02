import { createHash } from 'node:crypto'
import type { Finding, Severity } from './types.js'

const secretKeys = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[-_]?key|access[-_]?token|refresh[-_]?token|client[-_]?secret|password|passwd|session|sessionid|csrf|xsrf)$/i
const piiKeys = /^(email|e-mail|phone|telephone|mobile|ip|ip_address|address|ssn)$/i
const jwt = /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/
const bearer = /^(bearer|basic)\s+\S+/i
const email = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i
const ipv4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/
const privateKey = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/
const tokenish = /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/
const embeddedSecret = /["'](?:password|passwd|access[_-]?token|refresh[_-]?token|api[_-]?key|client[_-]?secret|session)["']\s*:\s*["'][^"']+["']/i

export function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 16)
}

function preview(value: string): string {
  if (!value) return '[empty]'
  return `[redacted:${value.length}:sha256:${fingerprint(value)}]`
}

function finding(path: string, category: string, severity: Severity, confidence: Finding['confidence'], value: string): Finding {
  return { path, category, severity, confidence, preview: preview(value), fingerprint: fingerprint(value) }
}

export function classify(path: string, key: string, value: string): Finding | null {
  if (/^\[HARbor:[a-z-]+:[a-f0-9]{12}\]$/.test(value) || /^(user-[a-f0-9]{12}@example\.invalid|192\.0\.2\.\d{1,3})$/.test(value)) return null
  if (secretKeys.test(key)) return finding(path, 'credential-field', 'high', 'confirmed', value)
  if (privateKey.test(value)) return finding(path, 'private-key', 'critical', 'confirmed', value)
  if (jwt.test(value)) return finding(path, 'jwt', 'high', 'confirmed', value)
  if (bearer.test(value)) return finding(path, 'authorization-value', 'high', 'confirmed', value)
  if (tokenish.test(value)) return finding(path, 'token-pattern', 'high', 'confirmed', value)
  if (embeddedSecret.test(value)) return finding(path, 'embedded-credential', 'high', 'confirmed', value)
  if (piiKeys.test(key)) return finding(path, 'pii-field', 'medium', 'heuristic', value)
  if (email.test(value)) return finding(path, 'email', 'medium', 'heuristic', value)
  if (ipv4.test(value)) return finding(path, 'ip-address', 'low', 'heuristic', value)
  return null
}

export function scanObject(root: unknown): Finding[] {
  const findings: Finding[] = []
  const visit = (value: unknown, path: string, key = ''): void => {
    if (typeof value === 'string') {
      const hit = classify(path, key, value)
      if (hit) findings.push(hit)
      return
    }
    if (Array.isArray(value)) return value.forEach((item, index) => visit(item, `${path}[${index}]`, key))
    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>
      if (typeof record.name === 'string' && typeof record.value === 'string') {
        const named = classify(`${path}.value`, record.name, record.value)
        if (named) findings.push(named)
      }
      for (const [childKey, child] of Object.entries(record)) {
        if (childKey === 'value' && typeof record.name === 'string') continue
        visit(child, `${path}.${childKey}`, childKey)
      }
    }
  }
  visit(root, '$')
  return findings
}
