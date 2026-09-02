import type { Har, ScanResult } from './types.js'
import { scanObject } from './detect.js'

export { parseHar, readHar } from './har.js'
export { scanObject, classify } from './detect.js'
export { sanitizeHar } from './sanitize.js'
export { atomicWrite } from './io.js'
export type { Har, ScanResult, Finding, Change, SanitizeResult } from './types.js'

export function scanHar(har: Har): ScanResult {
  return { valid: true, entries: har.log.entries.length, findings: scanObject(har) }
}

export function structuralSummary(har: Har): { version: string; entries: number; pages: number } {
  return { version: har.log.version, entries: har.log.entries.length, pages: Array.isArray(har.log.pages) ? har.log.pages.length : 0 }
}
