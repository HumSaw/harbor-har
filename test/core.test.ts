import assert from 'node:assert/strict'
import { readFile, mkdtemp, readFile as read, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { atomicWrite, parseHar, sanitizeHar, scanHar } from '../src/index.js'

const fixture = new URL('./fixtures/sensitive.har', import.meta.url)

test('parses valid HAR and rejects malformed documents', async () => {
  const har = parseHar(await readFile(fixture, 'utf8'))
  assert.equal(har.log.entries.length, 1)
  assert.throws(() => parseHar('{nope'), /Malformed JSON/)
  assert.throws(() => parseHar('{}'), /Missing HAR log/)
})

test('findings never contain original values', async () => {
  const input = await readFile(fixture, 'utf8')
  const findings = scanHar(parseHar(input)).findings
  assert.ok(findings.length >= 5)
  const report = JSON.stringify(findings)
  for (const secret of ['secret-token-value', 'private-session-value', 'person@example.com', 'hunter-two']) assert.equal(report.includes(secret), false)
})

test('sanitization is deterministic, idempotent, and verifies clean', async () => {
  const har = parseHar(await readFile(fixture, 'utf8'))
  const first = sanitizeHar(har)
  const second = sanitizeHar(har)
  assert.deepEqual(first, second)
  assert.deepEqual(sanitizeHar(first.har).har, first.har)
  assert.equal(scanHar(first.har as typeof har).findings.length, 0)
  assert.ok(first.manifest.changes.length >= 5)
})

test('atomic output refuses input overwrite and symlinks', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'harbor-test-'))
  const input = join(dir, 'input.har')
  await atomicWrite(input, '{}')
  await assert.rejects(() => atomicWrite(input, '{}', input), /overwrite input/)
  const target = join(dir, 'target.har'); const link = join(dir, 'link.har')
  await atomicWrite(target, '{}'); await symlink(target, link)
  await assert.rejects(() => atomicWrite(link, '{}'), /symbolic link/)
  assert.equal(await read(target, 'utf8'), '{}')
})
