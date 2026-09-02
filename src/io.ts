import { lstat, mkdir, open, rename, rm } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'

export async function atomicWrite(path: string, contents: string, inputPath?: string): Promise<void> {
  const target = resolve(path)
  if (inputPath && target === resolve(inputPath)) throw new Error('Refusing to overwrite input without explicit in-place workflow')
  try {
    const stat = await lstat(target)
    if (stat.isSymbolicLink()) throw new Error('Refusing to write through a symbolic link')
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
  }
  await mkdir(dirname(target), { recursive: true })
  const temporary = `${target}.harbor-${randomUUID()}.tmp`
  const handle = await open(temporary, 'wx', 0o600)
  try {
    await handle.writeFile(contents, 'utf8')
    await handle.sync()
    await handle.close()
    await rename(temporary, target)
  } catch (error) {
    await handle.close().catch(() => undefined)
    await rm(temporary, { force: true }).catch(() => undefined)
    throw error
  }
}
