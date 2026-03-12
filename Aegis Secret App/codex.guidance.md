## Aegis Secret

When a task involves local CLIs such as `gh`, `aws`, `gcloud`, `kubectl`, or similar tools, prefer the `aegis-secret` MCP server when it is available.

- Call `list_commands` first to discover which wrapped commands Aegis exposes.
- Use `run_command` for wrapped tools instead of invoking those CLIs directly through Bash.
- Treat Aegis as the default path for wrapped local tools, not as a fallback after shelling out.
- Use `aegis-secret command list` and `aegis-secret command show <NAME>` only as a local fallback when MCP is unavailable.
- Use `aegis-secret get <KEY> --agent Codex` only for explicit human-approved debugging or when the user specifically asks for the raw value.
