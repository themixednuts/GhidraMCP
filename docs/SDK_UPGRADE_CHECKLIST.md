# MCP Java SDK Upgrade Checklist

Use this checklist before and after changing `mcp.bom.version` in `pom.xml`.

## Pre-upgrade

1. Review release notes for:
   - `mcp-bom`
   - `mcp`
   - `mcp-core`
2. Confirm transport and protocol changes affecting stateless servers.
3. Check schema/model changes impacting:
   - `CallToolResult`
   - `Tool`/`JsonSchema`
   - completion/resource/prompt records

## Validation Matrix

Run all of the following:

1. `mvn -DskipTests clean compile`
2. `mvn test`
3. Start plugin in Ghidra and verify:
   - tool calls return `structuredContent`
   - resources/prompts/completions are discoverable
   - capability advertisement matches behavior
4. Execute smoke scenarios:
   - paginated tools with valid and invalid cursors
   - at least one prompt with completions
   - at least one resource template read

## Post-upgrade

1. Update docs/examples if cursor or schema contracts changed.
2. Record notable protocol/API behavior changes in changelog/PR notes.
3. Verify CI warning for MCP BOM drift is still operational.
