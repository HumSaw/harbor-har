# Contributing

HARbor favors deterministic, offline behavior and a small audited surface.

1. Open an issue describing the detector or safety problem.
2. Use synthetic values only; never commit captured traffic, valid credentials, or personal data.
3. Add a failing test before changing behavior.
4. Run `pnpm check` and `pnpm pack --dry-run`.
5. Explain false-positive and false-negative tradeoffs in the pull request.

Detector changes must never expose raw matched values in console output, JSON output, thrown errors, snapshots, or manifests. Network access, telemetry, dynamic code execution, shell execution, and implicit input overwrite are out of scope.
