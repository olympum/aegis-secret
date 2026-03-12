# aegis-secret

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Named-policy secret broker for agent workflows on macOS.

Keep secrets in Keychain, expose named policies to agents, and avoid
`.env` files as the default workflow.

Biometric-only secret access on macOS requires a signed install. Aegis Secret
targets the Data Protection keychain on macOS.

## What Is A Policy?

A secret is the raw credential, like `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.

A named policy is the agent-facing name for "this secret may be used in this specific way."

Think of it like this:

Without a policy:

- the agent needs the raw `OPENAI_API_KEY`
- the agent or subprocess decides where to send it
- the secret can leak into logs, prompts, shell history, or output

With a named policy:

- secret in Keychain: `OPENAI_API_KEY`
- policy name: `openai-api`
- allowed host: `https://api.openai.com`
- allowed methods: `GET`, `POST`
- allowed paths: `/v1/...`
- auth behavior: inject `Authorization: Bearer ...` locally

So when the agent wants to call OpenAI, it asks for policy `openai-api`, not for the raw key.

Concrete example:

- You store the secret once as `OPENAI_API_KEY`.
- You define a named policy called `openai-api`.
- The broker knows that policy `openai-api` means:
  - use `OPENAI_API_KEY`
  - only talk to `api.openai.com`
  - only hit `/v1/...`
  - attach the bearer token itself
- The agent calls `http_request` with policy `openai-api`.
- The raw `OPENAI_API_KEY` never needs to be returned to the agent.

That is why this repo talks about named policies, not just secrets.

## How The Agent Uses It

Once a named policy exists, the agent uses that name through MCP.

Example:

1. You store the secret:
   `OPENAI_API_KEY`
2. You define the named policy:
   `openai-api`
3. The agent sees that `openai-api` is available via `list_policies`.
4. The agent makes a request like:
   - tool: `http_request`
   - policy: `openai-api`
   - method: `POST`
   - path: `/v1/responses`
   - body: `{...}`
5. The local broker then:
   - reads `OPENAI_API_KEY` from Keychain
   - prompts for Touch ID
   - injects the auth header locally
   - sends the request to OpenAI
   - returns the API response

So the agent workflow is:

- discover policy names
- pick one by name
- call `http_request` with that name

Not:

- ask for the raw key
- put the key in an env var
- print the key into the transcript

## Install

### Binary Release

When GitHub release assets are available, install from a notarized binary instead
of building from source:

1. Download `Aegis Secret-<version>-macOS.dmg`.
2. Open the DMG.
3. Drag `Aegis Secret.app` into `Applications`.
4. Run:

```bash
/Applications/Aegis\ Secret.app/Contents/MacOS/aegis-secret install-user
```

That command creates `aegis-secret` and `aegis-secret-mcp` shims in
`~/.local/bin` and registers the user-scoped MCP server for Codex and Claude
when those CLIs are present.

### Build From Source

Store your Xcode development team ID once:

```bash
mkdir -p ~/.config/aegis-secret
cat > ~/.config/aegis-secret/install.env <<'EOF'
AEGIS_SECRET_TEAM_ID=YOURTEAMID
EOF
```

If you want Xcode.app builds to work without editing the project file, create the
repo-local override once:

```bash
cp Config/Signing.local.xcconfig.example Config/Signing.local.xcconfig
```

Then set your team ID in `Config/Signing.local.xcconfig`. That file is gitignored.

Then run the installer:

```bash
git clone https://github.com/olympum/aegis-secret.git
cd aegis-secret
./scripts/install-user-mcp.sh
```

You can also override it per-run with:

```bash
export AEGIS_SECRET_TEAM_ID="YOURTEAMID"
```

If the installer says it cannot find or create a provisioning profile, do this once:

1. Open `Aegis Secret.xcodeproj` in Xcode.
2. Select the `Aegis Secret` target.
3. In Signing & Capabilities, choose your paid Apple Developer team.
4. Build the app once in Xcode.
5. Rerun `./scripts/install-user-mcp.sh`.

This source-build path installs:

- `~/.local/bin/aegis-secret`
- `~/.local/bin/aegis-secret-mcp`
- `~/Applications/Aegis Secret.app`

and registers a user-scoped MCP server for Codex and Claude when those CLIs are present.

## Use

### 1. Store a secret

```bash
aegis-secret set OPENAI_API_KEY
```

### 2. Import a policy config

```bash
aegis-secret policy import ./examples/policies.example.json
```

This is where you define named policies: the name the agent can use, which secret backs it, and the rules for where that secret is allowed to go.

### 3. Check what is available

```bash
aegis-secret policy list
aegis-secret policy show openai-api
```

### 4. Let the agent use MCP tools

The MCP server exposes:

- `list_policies`
- `probe_policy`
- `http_request`

The preferred path is that the agent uses a named policy and never sees the raw secret text.

Typical agent flow:

1. Call `list_policies`
2. Call `probe_policy` for `openai-api`
3. Call `http_request` with policy `openai-api`

## Example Policy File

Start from [`examples/policies.example.json`](examples/policies.example.json):

```json
{
  "policies": [
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

Imported policy files are stored at `~/.config/aegis-secret/policies.json` by default.

## Commands

```bash
aegis-secret set <key>
aegis-secret get <key> --agent <agent-name>
aegis-secret delete <key>
aegis-secret list
aegis-secret policy list
aegis-secret policy show <name>
aegis-secret policy validate [<name> | --file <path>]
aegis-secret policy import <json-file>
```

## Development

```bash
swift build
swift test
```

Running from source is fine for development and tests, but the real biometric-only
workflow uses the signed app bundle created by `./scripts/install-user-mcp.sh`.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Security

Please use [SECURITY.md](SECURITY.md) for private security reporting guidance.
