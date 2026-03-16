# Aegis Secret

Touch ID-gated wrapper for local developer CLIs and Keychain-backed secret workflows.

## Development Commands

```bash
./scripts/ci_local.sh      # Canonical local pre-push gate
swift test                 # Run the Swift package tests
```

## Code Style

- Keep raw-secret handling out of the MCP surface.
- Prefer wrapped-command policy changes over ad hoc command execution paths.
- Keep install and release flows reproducible from this repo alone.

## Push Policy

- Run `./scripts/ci_local.sh` before commit or push when the repo provides it.
- If `./scripts/ci_local.sh` fails, do not push unless `OLYMPUM_BYPASS_PRE_PUSH=1` is explicitly set for an emergency bypass.
- Prefer pull requests over direct `main` pushes when branch protection is enabled.
