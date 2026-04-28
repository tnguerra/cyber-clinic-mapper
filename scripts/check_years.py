"""
scripts/check_years.py  --  Show CVE counts per year already in the database
Run from the scripts folder:
    python check_years.py
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "index.db"

if not DB_PATH.exists():
    print(f"[ERROR] DB not found: {DB_PATH}")
    raise SystemExit(1)

conn = sqlite3.connect(str(DB_PATH))
print("\nCVE counts by year in index.db")
print("-" * 35)

rows = conn.execute(
    "SELECT substr(id, 5, 4) AS yr, COUNT(1) AS c "
    "FROM cves "
    "GROUP BY yr "
    "ORDER BY yr"
).fetchall()

total = 0
for yr, c in rows:
    print(f"  {yr or '????'}:  {c:>8,}")
    total += c

print("-" * 35)
print(f"  Total: {total:>8,}\n")

# Also show what years exist on disk vs what's in DB
print("Years available on disk:")
print("-" * 35)
cve_dir = Path(__file__).parent.parent.parent.parent / "mcp-data-testing" / "cwe-cve-data" / "cves"
if cve_dir.exists():
    in_db = {yr for yr, _ in rows if yr}
    for year_dir in sorted(cve_dir.iterdir()):
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue
        yr = year_dir.name
        file_count = sum(1 for _ in year_dir.rglob("*.json"))
        status = "IN DB" if yr in in_db else "NOT INGESTED"
        print(f"  {yr}: {file_count:>8,} files   [{status}]")
else:
    print(f"  [NOT FOUND] {cve_dir}")
print()

conn.close()
