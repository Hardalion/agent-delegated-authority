# Conformance vectors

Language-independent fixtures for ADAP claim levels.

| File | Purpose |
| --- | --- |
| [mcp-vectors.json](./mcp-vectors.json) | Policy-only vs authority-enforcing MCP scenarios (synthetic, no side effects) |

Run the TypeScript reference checks with `pnpm test` (policy MCP tests) and `pnpm attacks` (authority path). Spec: [spec/mcp-binding.md](../../spec/mcp-binding.md), [spec/conformance.md](../../spec/conformance.md).
