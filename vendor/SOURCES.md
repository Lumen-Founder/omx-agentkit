# Vendored specs and schemas (read 2026-11-05)

| File | Source | License | Note |
|---|---|---|---|
| schemas/mcp-server.schema.2025-12-11.json | https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json | Apache-2.0 (MCP project, MIT for older contributions) | `$schema` used in all examples of modelcontextprotocol/registry docs/reference/server-json/generic-server-json.md (repo HEAD a48b6a733e808366d5e1fda65ab5fbfb5478e9fd) |
| schemas/openapi-3.1.schema.2022-10-07.json | https://spec.openapis.org/oas/3.1/schema/2022-10-07 | Apache-2.0 (OAI/OpenAPI-Specification) | Official OAS 3.1 schema (no schema-object validation) |
| specs/a2a.proto | https://raw.githubusercontent.com/a2aproject/A2A/main/specification/a2a.proto | Apache-2.0 (a2aproject/A2A) | A2A 1.0.0, repo HEAD 4735f4876449c6f381825d8a841b31b16c6ad0c4 |
| schemas/a2a-agent-card.derived-proto.schema.json | derived by hand from specs/a2a.proto | Apache-2.0 (derived from A2A) | A2A publishes no committed JSON Schema |
| specs/x402-specification-v2.md, specs/x402-bazaar.md | https://raw.githubusercontent.com/coinbase/x402/main/specs/ | Apache-2.0 (coinbase/x402) | repo HEAD 0e6e8c55d86b4f14234fb6e49a4052074fb93e57; no /.well-known/x402 in either |
| specs/draft-hawkins-x402-dns-discovery-02.txt | https://www.ietf.org/archive/id/draft-hawkins-x402-dns-discovery-02.txt | IETF Trust Legal Provisions (BCP 78), unmodified copy | Individual Internet-Draft (Informational), the only /.well-known/x402 definition found |
| schemas/x402-well-known.derived-draft-hawkins-02.schema.json | derived by hand from the draft above + x402 v2 section 5.1.2 | Apache-2.0 (derived) | |
