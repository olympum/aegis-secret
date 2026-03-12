# Contributing to aegis-secret

Thank you for your interest in contributing.

## Code of Conduct

This project follows the Contributor Covenant. By participating, you agree to
uphold the standards in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Issues

- Check for existing issues before opening a new one.
- Include clear reproduction steps, expected behavior, and actual behavior.
- Include your macOS version, Swift toolchain version, and whether the issue is in the CLI, Keychain flow, or MCP server.

### Pull Requests

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/short-description`).
3. Keep changes focused and scoped to one concern.
4. Add or update tests and docs for behavior changes.
5. Run relevant local checks before opening the PR.
6. Commit with clear messages.
7. Push your branch and open a pull request.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```text
type(scope): description
```

Common types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `refactor`: Code change without behavior change
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

## Local Checks

Run the checks relevant to your changes before opening a PR:

```bash
swift build
swift test
```

If you change the install or MCP integration flow, also smoke test:

```bash
./scripts/install-user-mcp.sh
codex mcp get aegis-secret
claude mcp list
```

For install-flow changes, also verify the visible user-managed files:

```bash
ls ~/.config/aegis-secret
sed -n '1,120p' ~/.claude/CLAUDE.md
sed -n '1,120p' ~/.codex/AGENTS.md
```

The installer is expected to:

- refresh `~/.config/aegis-secret/commands.base.json`
- create `~/.config/aegis-secret/commands.local.json` if missing
- register user-scoped Claude and Codex MCP servers when those CLIs are installed
- update only the marked Aegis block inside `~/.claude/CLAUDE.md` and `~/.codex/AGENTS.md`

If the installer reports a missing provisioning profile, open `Aegis Secret.xcodeproj`
in Xcode, choose your paid team in Signing & Capabilities, build once, and rerun
the installer.

For local Xcode builds, set your team in `Config/Signing.local.xcconfig`.
That file is gitignored and should never be committed.

For release work, follow [RELEASING.md](RELEASING.md).

## Code Style

- Keep raw secret management CLI-only.
- Do not add MCP tools that return raw secret values.
- Keep the default agent path command-based rather than secret-text-based.
- Prefer wrapped-command mediation over shell execution or generic prompt conventions.
- Keep the visible config model simple: managed base plus user-local overlay.

## Commit Policy

- `Co-authored-by:` trailers are not allowed in this repository.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
