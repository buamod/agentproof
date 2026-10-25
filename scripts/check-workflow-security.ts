/**
 * Workflow hardening gate.
 *
 * GitHub Actions is part of the attack surface. This check enforces the rules
 * we can verify statically: no `pull_request_target`, least-privilege
 * permissions, and third-party actions pinned to a version or commit.
 *
 * Escape hatch: add `workflow-allow: <reason>` on the line.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const DIR = '.github/workflows'
const findings: string[] = []
let checks = 0

function fail(file: string, line: number, message: string): void {
  findings.push(`${file}:${line}  ${message}`)
}

const files = readdirSync(DIR).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'))

for (const name of files) {
  const file = join(DIR, name)
  const text = readFileSync(file, 'utf8')
  const lines = text.split('\n')

  const hasPermissions = /^permissions:/m.test(text)
  checks++
  if (!hasPermissions) fail(file, 1, 'workflow must declare top-level permissions')

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const lineNo = i + 1
    if (line.includes('workflow-allow:')) continue

    if (/^\s*pull_request_target\s*:/.test(line)) {
      fail(file, lineNo, 'pull_request_target is forbidden (untrusted code with write access)')
    }

    if (/permissions:\s*write-all/.test(line)) {
      fail(file, lineNo, 'permissions: write-all is forbidden')
    }

    const uses = line.match(/^\s*-?\s*uses:\s*([^\s#]+)/)
    if (uses) {
      const ref = uses[1]
      // Local actions and docker references are evaluated separately.
      if (ref.startsWith('./') || ref.startsWith('docker://')) continue

      const at = ref.lastIndexOf('@')
      if (at === -1) {
        fail(file, lineNo, `action has no ref: ${ref}`)
        continue
      }
      const pin = ref.slice(at + 1)
      const pinned = /^v\d+(\.\d+){0,2}$/.test(pin) || /^[0-9a-f]{40}$/.test(pin)
      checks++
      if (!pinned) fail(file, lineNo, `action must be pinned to a version tag or SHA: ${ref}`)
    }

    if (/runs-on:\s*self-hosted/.test(line)) {
      fail(file, lineNo, 'self-hosted runners require an explicit review')
    }
  }
}

checks++ // file count
if (files.length === 0) fail(DIR, 0, 'no workflow files found')

console.log(`Workflow hardening: ${files.length} files, ${checks} checks`)
if (findings.length > 0) {
  console.error('\nWorkflow hardening failed:\n')
  for (const f of findings) console.error(`  - ${f}`)
  process.exit(1)
}
console.log('Workflow hardening passed.')
