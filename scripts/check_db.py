"""
scripts/check_db.py  --  Database state inspector for the CVE-to-CWE Mapper
============================================================================
Run from the MCPFramework-CVE-to-CWE_Mapper directory:

    cd C:\\Users\\thoma\\Desktop\\Academic\\Cyber_Research\\mcp_servers\\MCPFramework-CVE-to-CWE_Mapper
    .venv\\Scripts\\activate
    python scripts\\check_db.py

No arguments needed.  Read-only -- nothing is written.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "index.db"


def check_db(path: Path, label: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  Path : {path}")
    if not path.exists():
        print("  [NOT FOUND]")
        return
    print(f"  Size : {path.stat().st_size / 1024 / 1024:.2f} MB")

    try:
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()]
        print(f"\n  Tables ({len(tables)}): {', '.join(tables) or '(none)'}")

        # Row counts for every known table
        KNOWN = [
            "cves", "cwes", "cis", "cis_controls",
            "cve_cwes", "cve_affected",
            "cwe_attributes", "cwe_relationships", "cwe_consequences",
            "cwe_mitigations", "cwe_detection_methods",
            "cwe_observed_examples", "cwe_platforms",
            "cwe_modes_of_introduction", "cwe_examples",
            "cwe_references", "cwe_mapping_notes", "cwe_content_history",
        ]
        print()
        for t in KNOWN:
            if t not in tables:
                continue
            n = cur.execute(f"SELECT COUNT(1) FROM {t}").fetchone()[0]
            print(f"    {t:<30} {n:>10,} rows")

        # CVE-specific checks
        if "cves" in tables:
            print()
            row = cur.execute("SELECT id, title FROM cves LIMIT 1").fetchone()
            if row:
                print(f"  Sample CVE  : {row[0]} | {(row[1] or '')[:60]}")
            else:
                print("  CVE table   : (empty)")

            total    = cur.execute("SELECT COUNT(1) FROM cves").fetchone()[0]
            with_cvss = cur.execute("SELECT COUNT(1) FROM cves WHERE cvss_score IS NOT NULL").fetchone()[0]
            with_kev  = cur.execute("SELECT COUNT(1) FROM cves WHERE is_kev = 1").fetchone()[0]
            with_cwe  = cur.execute("SELECT COUNT(1) FROM cves WHERE has_explicit_cwe = 1").fetchone()[0]
            print(f"  CVEs total  : {total:,}")
            print(f"  With CVSS   : {with_cvss:,}  ({100*with_cvss//max(1,total)}%)")
            print(f"  Is KEV      : {with_kev:,}")
            print(f"  Has CWE     : {with_cwe:,}  ({100*with_cwe//max(1,total)}%)")

            rows = cur.execute(
                "SELECT cvss_severity, COUNT(1) c FROM cves WHERE cvss_severity IS NOT NULL "
                "GROUP BY cvss_severity ORDER BY c DESC"
            ).fetchall()
            if rows:
                sev = ", ".join(f"{r[0]}={r[1]:,}" for r in rows)
                print(f"  Severity    : {sev}")

        # CWE check
        if "cwes" in tables:
            row = cur.execute("SELECT id, name FROM cwes LIMIT 1").fetchone()
            if row:
                print(f"\n  Sample CWE  : CWE-{row[0]} | {(row[1] or '')[:60]}")
            else:
                print("\n  CWE table   : (empty)")

        # CIS check
        if "cis" in tables:
            row = cur.execute("SELECT control, safeguard, title FROM cis LIMIT 1").fetchone()
            if row:
                print(f"  Sample CIS  : {row[0]}.{row[1]} | {(row[2] or '')[:50]}")
            else:
                print("  CIS table   : (empty)")

        # WAL warning
        wal = Path(str(path) + "-wal")
        if wal.exists():
            print(f"\n  [WARN] WAL file present ({wal.stat().st_size/1024:.0f} KB) -- DB may be open elsewhere")

        conn.close()

    except Exception as e:
        print(f"  [ERROR] {e}")


def main() -> None:
    print("\nDatabase State Inspector -- CVE-to-CWE Mapper")
    check_db(DB_PATH, "index.db  (live database)")
    tmp = DB_PATH.parent / "index.db.tmp"
    if tmp.exists():
        check_db(tmp, "index.db.tmp  (incomplete build?)")
    print()


if __name__ == "__main__":
    main()
