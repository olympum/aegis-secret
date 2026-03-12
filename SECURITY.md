# Security Policy

## Supported Versions

Security fixes are applied on the `main` branch. Public releases will be listed
here once binary distribution starts.

## Reporting A Vulnerability

Please do not open public GitHub issues for security-sensitive reports.

Instead, report vulnerabilities privately to the maintainers with:

- a clear description of the issue
- affected version or commit
- reproduction steps or proof of concept
- impact assessment if known

If you already have a private contact path with the maintainers, use that.
Otherwise, open a GitHub security advisory draft or use the repository's private
security reporting flow once enabled.

We will acknowledge receipt as soon as practical, investigate the report, and
coordinate remediation and disclosure timing with the reporter.

## Scope

Security reports are especially helpful for:

- Keychain access control and storage behavior
- wrapped-command whitelist or deny-rule bypasses
- raw secret disclosure paths
- installation, signing, and notarization issues
- MCP tool abuse or sandbox escape concerns
