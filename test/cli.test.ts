import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const exec = promisify(execFile)
const cli = fileURLToPath(new URL('../bin/harbor-har.ts', import.meta.url))
const fixture = fileURLToPath(new URL('./fixtures/sensitive.har', import.meta.url))

async function run(args: string[]) {
  try { return await exec(process.execPath, ['--import', 'tsx', cli, ...args]) }
  catch (error) { return error as { stdout: string; stderr: string; code: number } }
}

test('scan uses exit 1 and emits redacted JSON', async () => {
  const result = await run(['scan', fixture, '--json'])
  assert.equal('code' in result ? result.code : 0, 1)
  assert.match(result.stdout, /credential-field/)
  assert.doesNotMatch(result.stdout + result.stderr, /secret-token-value|person@example\.com/)
})

test('sanitize writes clean HAR and manifest', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'harbor-cli-')); const output = join(dir, 'safe.har')
  const sanitized = await run(['sanitize', fixture, '--out', output])
  assert.equal('code' in sanitized ? sanitized.code : 0, 0)
  const verify = await run(['verify', output, '--json'])
  assert.equal('code' in verify ? verify.code : 0, 0)
  assert.match(await readFile(output, 'utf8'), /HARbor/)
  assert.doesNotMatch(await readFile(output, 'utf8'), /secret-token-value|person@example\.com/)
  assert.match(await readFile(`${output}.manifest.json`, 'utf8'), /fingerprint/)
})
