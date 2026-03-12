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

If the installer reports a missing provisioning profile, open `Aegis Secret.xcodeproj`
in Xcode, choose your paid team in Signing & Capabilities, build once, and rerun
the installer.

For local Xcode builds, set your team in `Config/Signing.local.xcconfig`.
That file is gitignored and should never be committed.

For release work, follow [RELEASING.md](RELEASING.md).

## Code Style

- Keep the default agent path policy-based rather than raw-secret-based.
- Do not add MCP tools that return raw secret values.
- Keep auth injection and policy enforcement in the local broker, not in prompts.
- Prefer small, explicit interfaces over generic secret execution surfaces.

## Commit Policy

- `Co-authored-by:` trailers are not allowed in this repository.

## License

By contributing, you agree that your contributions are licensed under the Apache License 2.0.
