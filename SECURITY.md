# Security policy

## Reporting

Use GitHub private vulnerability reporting for vulnerabilities in HARbor. Do not attach real HAR files, credentials, cookies, or personal data. Create a minimal synthetic fixture and explain the affected version and impact.

## Supported versions

The latest tagged release receives security fixes.

## Security boundaries

HARbor processes local, untrusted JSON and must not execute content or make network requests. A clean result means no configured detector matched; it is not proof that a HAR contains no sensitive information. Encoded, encrypted, compressed, proprietary, and context-dependent secrets may remain.
