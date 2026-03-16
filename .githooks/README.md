Enable tracked git hooks for this clone with:

```bash
git config core.hooksPath .githooks
```

The repo-owned `pre-push` hook runs `./scripts/ci_local.sh` and blocks the push if the local gate fails.
Use `OLYMPUM_BYPASS_PRE_PUSH=1` only for emergencies.
