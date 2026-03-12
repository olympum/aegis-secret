# aegis-secret

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Aegis Secret lets agents use local commands with Touch ID approval on macOS.

Secrets stay in Keychain and are managed by humans through the CLI. Agents do
not get raw secret tools over MCP. Instead, MCP exposes a small wrapped-command
surface, and Aegis runs the real CLI directly after approval.

## Install

### Binary Release

1. Download `Aegis Secret-<version>-installer.pkg`.
2. Open the package and complete the installer.

The installer places `Aegis Secret.app` in `/Applications`, installs
`aegis-secret` and `aegis-secret-mcp` into `/usr/local/bin`, and makes a
best-effort attempt to register the user-scoped MCP server for Codex and
Claude.

If you need to repair the per-user MCP registration later, run:

```bash
aegis-secret install-user
```

### Build From Source

Store your Xcode development team ID once:

```bash
mkdir -p ~/.config/aegis-secret
cat > ~/.config/aegis-secret/install.env <<'EOF'
AEGIS_SECRET_TEAM_ID=YOURTEAMID
EOF
```

If you want Xcode.app builds to work without editing the project file, create
the repo-local override once:

```bash
cp Config/Signing.local.xcconfig.example Config/Signing.local.xcconfig
```

Then set your team ID in `Config/Signing.local.xcconfig`. That file is
gitignored.

Then run:

```bash
git clone https://github.com/olympum/aegis-secret.git
cd aegis-secret
./scripts/install-user-mcp.sh
```

## Use

### Store a secret

```bash
aegis-secret set OPENAI_API_KEY
```

### Check available wrapped commands

```bash
aegis-secret command list
aegis-secret command show gh
```

### Run a wrapped command yourself

```bash
aegis-secret run gh -- api /user
aegis-secret run aws -- sts get-caller-identity --output json
```

### Let the agent use MCP tools

The MCP server exposes:

- `list_commands`
- `run_command`

Typical agent flow:

1. Call `list_commands`
2. Pick a wrapped command such as `gh`
3. Call `run_command` with the wrapped command name and argv
4. Approve the request with Touch ID

The wrapped command name is the whitelist. If `kubectl` is not configured, MCP
cannot run `kubectl`.

## Wrapped Commands

A wrapped command is a named command Aegis is allowed to run for the agent.

Example:

- wrapped command name: `gh`
- real executable: `gh`
- allowed by default: arbitrary argv for `gh`
- built-in deny rules: obvious credential and auth-management paths like
  `gh auth ...`

This keeps adoption easy:

- add `gh`, `aws`, or `gcloud`
- let agents use the real CLI they already know
- tighten rules later only if you need to

## System Defaults And User Overrides

Aegis ships with a system command set and a separate user override file.

System defaults:

- live in the installed app bundle
- are updated when you install a new release
- include `gh`, `aws`, and `gcloud`

User overrides:

- live at `~/.config/aegis-secret/commands.json`
- can override shipped settings for a wrapped command
- can disable a shipped wrapped command
- can add new wrapped commands

Start from [`examples/commands.example.json`](examples/commands.example.json)
for a user override file:

```json
{
  "version": 1,
  "commands": [
    {
      "name": "gh",
      "approval_window_seconds": 0
    },
    {
      "name": "aws",
      "enabled": false
    },
    {
      "name": "kubectl",
      "command": "kubectl",
      "description": "Kubernetes CLI",
      "approval_window_seconds": 300,
      "timeout_seconds": 30,
      "max_output_bytes": 262144
    }
  ]
}
```

That example does three things:

- makes `gh` prompt every time
- disables the shipped `aws` wrapper
- adds a new `kubectl` wrapper

## CLI Reference

```bash
aegis-secret set <key> [--stdin]
aegis-secret get <key> --agent <agent-name>
aegis-secret delete <key>
aegis-secret list
aegis-secret install-user
aegis-secret command list
aegis-secret command show <name>
aegis-secret command validate [<name> | --file <path>]
aegis-secret command import <json-file>
aegis-secret run <name> -- <args...>
```

## Security Model

- Secrets are stored in the macOS Data Protection keychain.
- CLI secret reads are for explicit human use.
- MCP never exposes `get_secret`, `set_secret`, or `delete_secret`.
- Wrapped command names are the top-level whitelist.
- Wrapped commands are executed directly, never through a shell.
- Aegis closes stdin, applies timeouts and output caps, and prompts for Touch ID
  before execution.
- Default approval caching is five minutes per wrapped command, configurable in
  `commands.json`.
