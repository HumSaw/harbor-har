# HARbor

**Audit and sanitize HAR files locally before sharing them.**

HAR files routinely contain session cookies, authorization headers, tokens, request bodies, email addresses, IP addresses, and internal metadata. HARbor finds them without printing the original values, creates a structurally useful sanitized copy, and verifies the result offline.

```bash
npx github:HumSaw/harbor-har sanitize session.har --out session.safe.har
```

```text
Sanitized 12 values; 0 findings remain; wrote /work/session.safe.har
```

## Why HARbor

- Local-only: no account, telemetry, upload, or network request.
- Evidence-safe: reports JSON paths, categories, severity, confidence, length, and fingerprints—not raw values.
- Deterministic: repeated identifiers receive stable placeholders for debugging.
- Verifiable: `verify` fails when recognized sensitive content remains.
- Automation-friendly: JSON reports and documented exit codes.

## Commands

```bash
harbor-har scan session.har
harbor-har scan session.har --json
harbor-har sanitize session.har --out session.safe.har
harbor-har verify session.safe.har
harbor-har diff session.har session.safe.har
```

Until an npm release exists, install from GitHub:

```bash
npm install --global github:HumSaw/harbor-har
# or
npx github:HumSaw/harbor-har scan session.har
```

## Detector matrix

| Signal | Confidence | Default severity |
| --- | --- | --- |
| Authorization/cookie/token/password fields | Confirmed | High |
| Private-key, JWT, known token patterns | Confirmed | Critical–high |
| Email or explicitly named PII fields | Heuristic | Medium |
| IPv4 candidates | Heuristic | Low |

HARbor inspects HAR string fields and `name`/`value` collections used by headers, cookies, and query parameters. Sanitized placeholders preserve equality relationships without retaining source values. The manifest stores changed paths, categories, confidence, severity, placeholders, and truncated SHA-256 fingerprints.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean or successful |
| `1` | Findings remain |
| `2` | Invalid command or malformed HAR |
| `3` | Unsafe or failed file operation |

## Threat model

HARbor assumes the input is sensitive and untrusted. It does not execute HAR content, contact captured hosts, or print complete detected values. Output is written atomically with restrictive creation permissions; writing through an existing symlink and accidental input overwrite are rejected.

Review sanitized files before disclosure. Encoded, encrypted, compressed, proprietary, or context-dependent secrets can survive. Fingerprints can reveal equality across findings and should be handled as sensitive metadata. HARbor reduces disclosure risk; it does not prove a file is anonymous or safe for unrestricted publication.

## Programmatic API

```ts
import { parseHar, sanitizeHar, scanHar } from 'harbor-har'

const har = parseHar(source)
const report = scanHar(har)
const { har: sanitized, manifest } = sanitizeHar(har)
```

## Comparison

HARbor focuses on a reproducible terminal workflow: scan, deterministic sanitization, post-sanitize verification, safe reports, and structural diff. Browser extensions and hosted sanitizers may be more convenient for capture; HARbor intentionally avoids browser privileges and server-side uploads.

## Development

```bash
pnpm install --frozen-lockfile
pnpm check
pnpm pack --dry-run
```

All fixtures are synthetic. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).

## License

MIT
