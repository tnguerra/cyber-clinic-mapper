"""Quick CIS data inspection -- run once and discard."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "index.db"
conn = sqlite3.connect(str(DB_PATH))
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print("\n=== All 153 CIS safeguards (control, safeguard, title) ===\n")
rows = cur.execute(
    "SELECT control, safeguard, title FROM cis ORDER BY CAST(control AS REAL), safeguard"
).fetchall()
for r in rows:
    print(f"  {r['control']}.{r['safeguard']:<8}  {r['title'][:80]}")

print("\n=== Sample description (first 3 rows) ===\n")
for r in cur.execute("SELECT control, safeguard, title, description FROM cis LIMIT 3").fetchall():
    print(f"  {r['control']}.{r['safeguard']} | {r['title']}")
    print(f"  DESC: {(r['description'] or '')[:200]}\n")

print("\n=== Keyword search tests ===")
for kw in ("application", "software", "secure", "input", "validat", "audit", "config"):
    n = cur.execute(
        "SELECT COUNT(1) FROM cis WHERE lower(title||' '||coalesce(description,'')) LIKE ?",
        (f"%{kw}%",)
    ).fetchone()[0]
    print(f"  '{kw}' matches: {n}")

conn.close()
