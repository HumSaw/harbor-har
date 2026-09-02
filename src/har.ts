import { readFile } from 'node:fs/promises'
import type { Har } from './types.js'

export function parseHar(input: string): Har {
  let value: unknown
  try { value = JSON.parse(input) } catch { throw new Error('Malformed JSON') }
  if (!value || typeof value !== 'object' || !('log' in value)) throw new Error('Missing HAR log object')
  const log = (value as { log?: unknown }).log
  if (!log || typeof log !== 'object') throw new Error('Invalid HAR log object')
  const candidate = log as Record<string, unknown>
  if (typeof candidate.version !== 'string' || !Array.isArray(candidate.entries)) throw new Error('HAR log requires version and entries')
  return value as Har
}

export async function readHar(path: string, maxBytes = 256 * 1024 * 1024): Promise<Har> {
  const input = await readFile(path)
  if (input.byteLength > maxBytes) throw new Error(`HAR exceeds ${maxBytes} bytes`)
  return parseHar(input.toString('utf8'))
}
