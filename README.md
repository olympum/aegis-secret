# aegis-secret

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Capability-brokered local secrets for agent workflows on macOS.

Keep secrets in Keychain, expose only named capabilities to agents, and avoid
`.env` files as the default workflow.

## Install

```bash
git clone <repo-url>
cd aegis-secret
./scripts/install-user-mcp.sh
```

This installs:

- `~/.local/bin/aegis-secret`
- `~/.local/bin/aegis-secret-mcp`

and registers a user-scoped MCP server for Codex and Claude when those CLIs are present.

## Use

### 1. Store a secret

```bash
aegis-secret set OPENAI_API_KEY
```

### 2. Import a capability config

```bash
aegis-secret capability import ./examples/capabilities.example.json
```

### 3. Check what is available

```bash
aegis-secret capability list
aegis-secret capability show openai-api
```

### 4. Let the agent use MCP tools

The MCP server exposes:

- `list_capabilities`
- `probe_capability`
- `http_request`

The preferred path is that the agent uses a capability and never sees the raw secret text.

## Example Capability File

Start from [`examples/capabilities.example.json`](examples/capabilities.example.json):

```json
{
  "capabilities": [
    {
      "name": "openai-api",
      "description": "OpenAI API requests through the local broker",
      "secret_key": "OPENAI_API_KEY",
      "base_url": "https://api.openai.com",
      "allowed_methods": ["GET", "POST"],
      "auth_mode": "bearer",
      "allowed_path_prefixes": ["/v1"],
      "default_headers": {
        "Accept": "application/json"
      }
    }
  ]
}
```

Imported capability files are stored at `~/.config/aegis-secret/capabilities.json` by default.

## Commands

```bash
aegis-secret set <key>
aegis-secret get <key> --agent <agent-name>
aegis-secret delete <key>
aegis-secret list
aegis-secret capability list
aegis-secret capability show <name>
aegis-secret capability validate [<name> | --file <path>]
aegis-secret capability import <json-file>
```

## Development

```bash
swift build
swift test
```

If you want to run from source instead of installing first, use `swift run aegis-secret ...`.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
