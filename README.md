<<<<<<< HEAD
# Cyber Clinic Mapper

## Short Description
Cyber Clinic Online provides accessible, practical tools for cyber analysts, starting with a CVE-to-CWE mapping and analysis engine. This prototype helps analysts quickly assess vulnerabilities, prioritize threats, and deliver cost-efficient recommendations ideally leveling the cybersecurity playing field.

## Project Plan
To develop the core diagnostic engine of a user-friendly cyber “clinic” which would be a tool that enables cyber analysts to quickly and efficiently map CVEs to CWEs, assess cybersecurity posture, and generate actionable reports. This first phase will deliver a cost-efficient, accessible solution that supports analysts in providing “clinic-style” recommendations, improving both speed and accessibility of cybersecurity assessments. 
=======
# MCP CVE→CWE→CIS Mapper

A minimal, offline MCP server that ingests CWE XML and CIS CSV (optionally CVE JSONs) into a local SQLite database and suggests high-quality CIS safeguards for specific CWEs.

## What it does
- Ingests CWE v4.18 XML into extended tables (attributes, relationships, platforms, modes, consequences, detection methods, mitigations, examples, observed examples, references, mapping notes, content history).
- Ingests CIS v8.x CSV into a unified structured `cis` table.
- Optionally ingests CVE JSON files (v5 and legacy v4 shapes) for search/mapping.
- Suggests CIS safeguards using IDF-weighted Jaccard scoring with sensible boosts.

## Requirements
- Python 3.12+
- Optional: `python-dotenv` if you want to use `.env` for `MAPPER_DB_PATH`.

## Running the server
Run via stdio with FastMCP:

```powershell
python c:\Users\thoma\Desktop\Academic\Cyber_Research\mcp_servers\MCPFramework-CVE-to-CWE_Mapper\CVE_CWE_Mapper_server.py
```

By default the DB is `mcp_servers\MCPFramework-CVE-to-CWE_Mapper\data\index.db`. To override:

```powershell
# Optional .env at repo root
"MAPPER_DB_PATH=C:\\path\\to\\index.db" | Out-File -Encoding utf8 -FilePath .env
```

## Core tools
- `cve_reset_db()`: Delete local DB file.
- `cve_ingest_cwe_xml(cwe_xml_path, replace=True)`: Ingest CWE XML v4.18 with extended metadata.
- `cve_ingest_cis(cis_csv_path, replace=False)`: Ingest CIS v8 structured CSV.
- `cve_build_index(source_dir=None, cwe_xml_path=None, cis_csv_path=None, reindex=False)`: Atomic rebuild; optional CVE ingest; validates input paths.
- `cve_index_stats()`, `cve_index_summary()`, `cve_environment_diagnostics()`, `cve_environment_summary()`.
- `cve_get_cwe_details(cwe_id)`: Aggregated extended CWE details.
- `cve_suggest_cis(cwe_id, top_n=10, prefer_functions="Protect,Detect", prefer_asset_classes="")`: Ranked CIS safeguards.
- `cve_suggest_cis_for_cwe(cwe_id)`: Convenience alias for `cve_suggest_cis`.
- `cve_ingest_file(file_path)`: Ingest a single CVE JSON (validated path and extension).
- `cve_search_cves(query)`, `cve_get_cve_sample(limit)`.
- `cve_debug_dry_run_dir(source_dir, max_files=200)`: Dry-run CVE ingestion without DB writes.

## Typical flow (PowerShell)
```powershell
# 1) Reset DB
python -c "import runpy; runpy.run_path('mcp_servers/MCPFramework-CVE-to-CWE_Mapper/CVE_CWE_Mapper_server.py')"; # starts MCP server (if needed)

# Using an MCP client, call tools in order:
# 2) cve_ingest_cwe_xml 'mcp-data-testing/cwe-cve-data/cwes/cwec_v4.18.xml'
# 3) cve_ingest_cis 'mcp-data-testing/cwe-cve-data/cis/CIS_Controls_Version_8.1.2___March_2025(Controls v8.1.csv'
# 4) cve_build_index (optional source_dir for CVEs)
# 5) cve_index_summary
# 6) cve_suggest_cis 'CWE-79'  # example
```

## Notes
- Inputs are path-validated with clear `{ok: False, error: ...}` responses.
- DB builds use WAL and atomic swap when `reindex=True`.
- Suggestions use IDF-weighted Jaccard with boosts (title/phrase, function, asset class, Control 16 heuristic).

## Troubleshooting
- `cwe_xml_path` / `cis_csv_path` invalid: ensure the path exists; the tools return a descriptive error.
- Empty index summary: ingest CWE and CIS first; CVE ingest is optional.
- To override DB location, set `MAPPER_DB_PATH` via `.env` or env var.

## License
Research-oriented; see top-level project license files when present.
>>>>>>> 3b778f0 (Mapper: add safe .env.example; data/.keep; finalize README/.gitignore; include server; remove legacy server.py)
