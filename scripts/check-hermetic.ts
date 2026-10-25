/**
 * Hermetic-core gate.
 *
 * The deterministic packages must not reach the network, call a model, read
 * provider API keys, or use non-deterministic randomness. This is what lets the
 * security verdicts be reproduced offline and keeps an AI planner from quietly
 * becoming part of the trusted path.
 *
 * Escape hatch: add `hermetic-allow: <reason>` on the line.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = 'packages'

const FORBIDDEN_IMPORTS = [
  'node:http',
  'node:https',
  'node:net',
  'node:tls',
  'node:dns',
  'node:dgram',
  'node:http2',
  'node:child_process',
  'axios',
  'undici',
  'node-fetch',
  'openai',
  '@anthropic-ai',
  '@google/generative-ai',
  'langchain',
  'cohere-ai',
]

const FORBIDDEN_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\bfetch\s*\(/, reason: 'network call (fetch)' },
  { pattern: /\bMath\.random\s*\(/, reason: 'non-deterministic randomness' },
  { pattern: /\bWebSocket\s*\(/, reason: 'network socket' },
  { pattern: /\bprocess\.env\b/, reason: 'environment/secret access' },
]

interface Finding {
  file: string
  line: number
  reason: string
  text: string
}

function walk(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else if (full.endsWith('.ts') && !full.endsWith('.test.ts')) out.push(full)
  }
  return out
}

const findings: Finding[] = []

for (const file of walk(ROOT)) {
  const lines = readFileSync(file, 'utf8').split('\n')
  lines.forEach((text, index) => {
    if (text.includes('hermetic-allow:')) return
    const line = index + 1

    for (const specifier of FORBIDDEN_IMPORTS) {
      const importPattern = new RegExp(`from\\s+['"]${specifier.replace(/[/@]/g, m => `\\${m}`)}(/[^'"]*)?['"]`)
      if (importPattern.test(text)) {
        findings.push({ file: relative('.', file), line, reason: `forbidden import: ${specifier}`, text: text.trim() })
      }
    }

    for (const { pattern, reason } of FORBIDDEN_PATTERNS) {
      if (pattern.test(text)) {
        findings.push({ file: relative('.', file), line, reason, text: text.trim() })
      }
    }
  })
}

if (findings.length > 0) {
  console.error('Hermetic-core check failed:\n')
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}  ${f.reason}`)
    console.error(`    ${f.text}`)
  }
  console.error('\nThe deterministic core must stay offline and model-free.')
  process.exit(1)
}

console.log('Hermetic-core check passed: no network, model, secret, or random calls in packages/.')
