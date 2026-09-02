#!/usr/bin/env node
import { Command } from 'commander'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { atomicWrite, parseHar, readHar, sanitizeHar, scanHar, structuralSummary } from '../src/index.js'

const program = new Command().name('harbor-har').description('Audit and sanitize HAR files locally').version('1.0.0')
const print = (value: unknown, json = false) => console.log(json ? JSON.stringify(value, null, 2) : value)
const fail = (message: string, code = 2): never => { console.error(`HARbor: ${message}`); process.exit(code) }

program.command('scan').argument('<file>').option('--json', 'JSON output').action(async (file, options) => {
  try {
    const result = scanHar(await readHar(file))
    if (options.json) print(result, true)
    else {
      console.log(`HARbor scan: ${result.entries} entries, ${result.findings.length} findings`)
      for (const finding of result.findings) console.log(`${finding.severity.toUpperCase()} ${finding.category} ${finding.path} ${finding.preview}`)
    }
    process.exitCode = result.findings.length ? 1 : 0
  } catch (error) { fail((error as Error).message) }
})

program.command('sanitize').argument('<file>').requiredOption('-o, --out <file>').option('--manifest <file>').action(async (file, options) => {
  try {
    const har = await readHar(file)
    const result = sanitizeHar(har)
    await atomicWrite(options.out, `${JSON.stringify(result.har, null, 2)}\n`, file)
    const manifestPath = options.manifest ?? `${options.out}.manifest.json`
    await atomicWrite(manifestPath, `${JSON.stringify(result.manifest, null, 2)}\n`)
    const remaining = scanHar(result.har as typeof har).findings
    console.log(`Sanitized ${result.manifest.changes.length} values; ${remaining.length} findings remain; wrote ${resolve(options.out)}`)
    process.exitCode = remaining.length ? 1 : 0
  } catch (error) { fail((error as Error).message, 3) }
})

program.command('verify').argument('<file>').option('--json').action(async (file, options) => {
  try {
    const result = scanHar(await readHar(file))
    print(options.json ? result : `HARbor verify: ${result.findings.length ? `${result.findings.length} findings remain` : 'clean'}`, Boolean(options.json))
    process.exitCode = result.findings.length ? 1 : 0
  } catch (error) { fail((error as Error).message) }
})

program.command('diff').argument('<before>').argument('<after>').option('--json').action(async (before, after, options) => {
  try {
    const a = parseHar(await readFile(before, 'utf8')); const b = parseHar(await readFile(after, 'utf8'))
    const left = scanHar(a).findings; const right = scanHar(b).findings
    const result = { before: structuralSummary(a), after: structuralSummary(b), findingsBefore: left.length, findingsAfter: right.length, removed: Math.max(0, left.length - right.length), structurePreserved: a.log.entries.length === b.log.entries.length }
    print(options.json ? result : `HARbor diff: ${result.removed} findings removed; structure ${result.structurePreserved ? 'preserved' : 'changed'}`, Boolean(options.json))
  } catch (error) { fail((error as Error).message) }
})

program.parseAsync().catch(error => fail(error.message))
