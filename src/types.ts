export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type Finding = {
  path: string
  category: string
  severity: Severity
  confidence: 'confirmed' | 'heuristic'
  preview: string
  fingerprint: string
}

export type Change = Omit<Finding, 'preview'> & { placeholder: string }

export type ScanResult = {
  valid: boolean
  entries: number
  findings: Finding[]
}

export type SanitizeResult = {
  har: unknown
  manifest: { version: 1; changes: Change[] }
}

export type Har = {
  log: {
    version: string
    creator: { name: string; version: string }
    entries: unknown[]
    [key: string]: unknown
  }
}
