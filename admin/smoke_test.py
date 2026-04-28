"""
scripts/smoke_test.py  --  End-to-end pipeline smoke test
==========================================================
Tests the full CVE -> CWE -> CIS chain directly against index.db
without needing the MCP server to be running.

Run from the MCPFramework-CVE-to-CWE_Mapper directory:

    cd C:\\Users\\thoma\\Desktop\\Academic\\Cyber_Research\\mcp_servers\\MCPFramework-CVE-to-CWE_Mapper
    .venv\\Scripts\\activate
    python scripts\\smoke_test.py

Each test prints PASS / FAIL with details.
Final summary shows how many passed out of total.
"""

from __future__ import annotations
import sys
import re
import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
_MAPPER_DIR = Path(__file__).parent.parent
DB_PATH     = _MAPPER_DIR / "data" / "index.db"

def _import_mapper():
    srv = str(_MAPPER_DIR)
    if srv not in sys.path:
        sys.path.insert(0, srv)
    try:
        import CVE_CWE_Mapper_server as m
        return m
    except ImportError as e:
        print(f"[ERROR] Cannot import server: {e}")
        sys.exit(1)

mapper = _import_mapper()

PASS = 0
FAIL = 0
RESULTS: list[tuple[str, bool, str]] = []

def check(name: str, passed: bool, detail: str = "") -> None:
    global PASS, FAIL
    RESULTS.append((name, passed, detail))
    if passed:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")
        if detail:
            print(f"         --> {detail}")

# ---------------------------------------------------------------------------
# Open DB
# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("  Smoke Test -- CVE-to-CWE Mapper Pipeline")
print("=" * 60)

if not DB_PATH.exists():
    print(f"\n[ERROR] DB not found: {DB_PATH}")
    sys.exit(1)

conn = sqlite3.connect(str(DB_PATH))
conn.row_factory = sqlite3.Row
cur = conn.cursor()

print(f"\n  DB: {DB_PATH}")
print(f"  Size: {DB_PATH.stat().st_size / 1024 / 1024:.1f} MB\n")

# ---------------------------------------------------------------------------
# BLOCK 1: Schema integrity
# ---------------------------------------------------------------------------
print("--- Block 1: Schema Integrity ---")

REQUIRED_TABLES = [
    "cves", "cwes", "cis", "cis_controls",
    "cve_cwes", "cve_affected",
    "cwe_attributes", "cwe_relationships", "cwe_consequences",
    "cwe_mitigations", "cwe_detection_methods", "cwe_observed_examples",
]
tables = {r[0] for r in cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()}
for t in REQUIRED_TABLES:
    check(f"Table exists: {t}", t in tables)

REQUIRED_CVE_COLS = [
    "id", "title", "description", "state",
    "date_published", "cvss_score", "cvss_severity",
    "is_kev", "kev_date_added", "exploitation", "automatable",
    "has_explicit_cwe", "json",
]
cve_cols = {r[1] for r in cur.execute("PRAGMA table_info(cves)").fetchall()}
for col in REQUIRED_CVE_COLS:
    check(f"CVE column exists: {col}", col in cve_cols)

# ---------------------------------------------------------------------------
# BLOCK 2: Data volume sanity checks
# ---------------------------------------------------------------------------
print("\n--- Block 2: Data Volume ---")

n_cves = cur.execute("SELECT COUNT(1) FROM cves").fetchone()[0]
check("CVEs >= 300,000", n_cves >= 300_000, f"actual={n_cves:,}")

n_cwes = cur.execute("SELECT COUNT(1) FROM cwes").fetchone()[0]
check("CWEs >= 900", n_cwes >= 900, f"actual={n_cwes:,}")

n_cis = cur.execute("SELECT COUNT(1) FROM cis").fetchone()[0]
check("CIS safeguards >= 150", n_cis >= 150, f"actual={n_cis:,}")

n_cis_ctrl = cur.execute("SELECT COUNT(1) FROM cis_controls").fetchone()[0]
check("CIS top-level controls == 18", n_cis_ctrl == 18, f"actual={n_cis_ctrl}")

n_cve_cwes = cur.execute("SELECT COUNT(1) FROM cve_cwes").fetchone()[0]
check("CVE->CWE mappings >= 100,000", n_cve_cwes >= 100_000, f"actual={n_cve_cwes:,}")

n_affected = cur.execute("SELECT COUNT(1) FROM cve_affected").fetchone()[0]
check("CVE affected products >= 400,000", n_affected >= 400_000, f"actual={n_affected:,}")

n_kev = cur.execute("SELECT COUNT(1) FROM cves WHERE is_kev = 1").fetchone()[0]
check("KEV entries >= 1,000", n_kev >= 1_000, f"actual={n_kev:,}")

n_cvss = cur.execute("SELECT COUNT(1) FROM cves WHERE cvss_score IS NOT NULL").fetchone()[0]
pct = 100 * n_cvss // max(1, n_cves)
check("CVSS coverage >= 35%", pct >= 35, f"actual={pct}%  ({n_cvss:,} CVEs)")

# ---------------------------------------------------------------------------
# BLOCK 3: CVE lookup -- known high-profile CVEs
# ---------------------------------------------------------------------------
print("\n--- Block 3: Known CVE Lookups ---")

TEST_CVES = [
    # (CVE ID,               expected_severity,  should_have_cwe)
    ("CVE-2021-44228", "CRITICAL", True),   # Log4Shell
    ("CVE-2022-26134", "CRITICAL", True),   # Confluence OGNL injection
    ("CVE-2023-44487", None,       False),  # HTTP/2 Rapid Reset
    ("CVE-2024-21762", "CRITICAL", True),   # Fortinet OOB write
    ("CVE-2025-0282",  "CRITICAL", True),   # Ivanti Connect Secure
]

for cve_id, expected_sev, should_have_cwe in TEST_CVES:
    row = cur.execute(
        "SELECT id, title, cvss_score, cvss_severity, is_kev, has_explicit_cwe "
        "FROM cves WHERE id = ?", (cve_id,)
    ).fetchone()

    if row is None:
        check(f"CVE exists: {cve_id}", False, "not found in DB")
        continue

    check(f"CVE exists: {cve_id}", True,
          f"score={row['cvss_score']}  sev={row['cvss_severity']}  "
          f"kev={row['is_kev']}  has_cwe={row['has_explicit_cwe']}")

    if expected_sev:
        check(f"  {cve_id} severity={expected_sev}",
              (row["cvss_severity"] or "").upper() == expected_sev,
              f"actual={row['cvss_severity']}")

    if should_have_cwe:
        cwes = cur.execute(
            "SELECT cwe_id, source FROM cve_cwes WHERE cve_id = ?", (cve_id,)
        ).fetchall()
        check(f"  {cve_id} has CWE mapping",
              len(cwes) > 0,
              f"mapped={[r['cwe_id'] for r in cwes]}")

# ---------------------------------------------------------------------------
# BLOCK 4: CVE -> CWE chain (Log4Shell = CWE-502)
# ---------------------------------------------------------------------------
print("\n--- Block 4: CVE -> CWE Chain ---")

log4shell = cur.execute(
    "SELECT cwe_id, source FROM cve_cwes WHERE cve_id = 'CVE-2021-44228'"
).fetchall()
check("Log4Shell (CVE-2021-44228) has CWE mapping", len(log4shell) > 0,
      f"found={[r['cwe_id'] for r in log4shell]}")

if log4shell:
    cwe_id = log4shell[0]["cwe_id"]
    cwe_row = cur.execute(
        "SELECT id, name, description FROM cwes WHERE id = ?", (cwe_id,)
    ).fetchone()
    check(f"CWE-{cwe_id} exists in cwes table", cwe_row is not None,
          f"name={cwe_row['name'] if cwe_row else 'NOT FOUND'}")

    if cwe_row:
        attrs = cur.execute(
            "SELECT abstraction, status, likelihood FROM cwe_attributes WHERE cwe_id = ?",
            (cwe_id,)
        ).fetchone()
        check(f"CWE-{cwe_id} has extended attributes", attrs is not None)

        conseqs = cur.execute(
            "SELECT COUNT(1) FROM cwe_consequences WHERE cwe_id = ?", (cwe_id,)
        ).fetchone()[0]
        check(f"CWE-{cwe_id} has consequences", conseqs > 0, f"count={conseqs}")

        mitig = cur.execute(
            "SELECT COUNT(1) FROM cwe_mitigations WHERE cwe_id = ?", (cwe_id,)
        ).fetchone()[0]
        check(f"CWE-{cwe_id} has mitigations", mitig > 0, f"count={mitig}")

        rels = cur.execute(
            "SELECT nature, related_cwe_id FROM cwe_relationships WHERE cwe_id = ?",
            (cwe_id,)
        ).fetchall()
        check(f"CWE-{cwe_id} has relationships", len(rels) > 0,
              f"count={len(rels)}")

        print(f"\n  CWE-{cwe_id}: {cwe_row['name']}")
        print(f"  Abstraction  : {attrs['abstraction'] if attrs else 'N/A'}")
        print(f"  Status       : {attrs['status'] if attrs else 'N/A'}")
        print(f"  Consequences : {conseqs}   Mitigations: {mitig}   Relationships: {len(rels)}")

# ---------------------------------------------------------------------------
# BLOCK 5: CWE -> CIS suggestion chain
# ---------------------------------------------------------------------------
print("\n--- Block 5: CWE -> CIS Suggestion Chain ---")

# CIS v8.1 uses governance/process language, not vulnerability jargon.
# Verify meaningful terms are present that will score well for app-sec CWEs.
appsec_rows = cur.execute(
    "SELECT control, safeguard, title FROM cis "
    "WHERE lower(title || ' ' || coalesce(description,'')) LIKE '%application%' "
    "   OR lower(title || ' ' || coalesce(description,'')) LIKE '%software%' "
    "LIMIT 10"
).fetchall()
check("CIS has application/software security safeguards",
      len(appsec_rows) >= 5,
      f"found={len(appsec_rows)} rows")

secure_dev = cur.execute(
    "SELECT control, safeguard, title FROM cis "
    "WHERE lower(title) LIKE '%secure%' AND lower(title) LIKE '%development%' "
    "   OR lower(title) LIKE '%application security%'"
).fetchall()
check("CIS Control 16 (app dev security) safeguards present",
      len(secure_dev) > 0,
      f"found={[(r['control'], r['safeguard']) for r in secure_dev]}")

ig1_count = cur.execute("SELECT COUNT(1) FROM cis WHERE ig1 = 1").fetchone()[0]
check("CIS IG1 flags populated", ig1_count > 0, f"ig1_count={ig1_count}")

ctrl_ids = [r[0] for r in cur.execute(
    "SELECT control FROM cis_controls ORDER BY CAST(control AS INTEGER)"
).fetchall()]
check("CIS controls 1-18 all present",
      set(ctrl_ids) == {str(i) for i in range(1, 19)},
      f"found={ctrl_ids}")

# Test scorer: CWE-89 (SQL Injection) -> should rank Control 16 and 18 highly
print("\n  Testing scorer: CWE-89 (SQL Injection) -> CIS suggestions")
try:
    cwe89 = cur.execute("SELECT id, name FROM cwes WHERE id = '89'").fetchone()
    check("CWE-89 (SQL Injection) exists", cwe89 is not None)

    if cwe89:
        cis_rows = cur.execute(
            "SELECT control, safeguard, title, description FROM cis"
        ).fetchall()

        STOPWORDS = {
            "the","a","an","and","or","of","to","for","with","on","in","by",
            "be","is","are","as","at","from","can","may","should","also",
            "must","will","this","that","use","using","it","its","all",
            "their","they","them","your","into","each","any","more",
        }

        def _tok(t: str) -> set[str]:
            return {
                w.lower() for w in re.findall(r"[A-Za-z0-9]+", t or "")
                if w.lower() not in STOPWORDS and len(w) > 2
            }

        # Query terms drawn from CWE-89 name + description keywords
        query = (
            f"{cwe89['name']} sql injection database query "
            "application input validation software security"
        )
        qtok = _tok(query)

        scored = []
        for r in cis_rows:
            dtok = _tok(f"{r['title']} {r['description']}")
            inter = len(qtok & dtok)
            union = len(qtok | dtok)
            score = inter / union if union else 0.0
            if score > 0:
                scored.append((
                    r["control"], r["safeguard"], r["title"], score
                ))
        scored.sort(key=lambda x: x[3], reverse=True)

        check("Scorer returns results for CWE-89", len(scored) > 0)

        # Control 16 (Application Software Security) should appear in top 10
        top10_controls = {s[0] for s in scored[:10]}
        check("Control 16 (App Security) in top-10 CIS suggestions for CWE-89",
              "16" in top10_controls,
              f"top-10 controls={sorted(top10_controls)}")

        print(f"\n  Top 8 CIS suggestions for CWE-89 (SQL Injection):")
        for ctl, sg, title, sc in scored[:8]:
            print(f"    Control {ctl:>2}.{sg:<8}  score={sc:.3f}  {title[:55]}")

except Exception as e:
    check("Scorer runs without error", False, str(e))

# Test scorer: CWE-79 (XSS) -> should also hit Control 16
print("\n  Testing scorer: CWE-79 (Cross-Site Scripting) -> CIS suggestions")
try:
    cwe79 = cur.execute("SELECT id, name FROM cwes WHERE id = '79'").fetchone()
    check("CWE-79 (XSS) exists", cwe79 is not None)

    if cwe79:
        cis_rows = cur.execute(
            "SELECT control, safeguard, title, description FROM cis"
        ).fetchall()
        query79 = (
            f"{cwe79['name']} cross-site scripting web application "
            "browser output encoding software security"
        )
        qtok79 = _tok(query79)
        scored79 = []
        for r in cis_rows:
            dtok = _tok(f"{r['title']} {r['description']}")
            inter = len(qtok79 & dtok)
            union = len(qtok79 | dtok)
            score = inter / union if union else 0.0
            if score > 0:
                scored79.append((r["control"], r["safeguard"], r["title"], score))
        scored79.sort(key=lambda x: x[3], reverse=True)

        top10_79 = {s[0] for s in scored79[:10]}
        check("Control 16 (App Security) in top-10 for CWE-79 (XSS)",
              "16" in top10_79,
              f"top-10 controls={sorted(top10_79)}")

        print(f"\n  Top 5 CIS suggestions for CWE-79 (XSS):")
        for ctl, sg, title, sc in scored79[:5]:
            print(f"    Control {ctl:>2}.{sg:<8}  score={sc:.3f}  {title[:55]}")

except Exception as e:
    check("XSS scorer runs without error", False, str(e))

# ---------------------------------------------------------------------------
# BLOCK 6: KEV / CVSS triage queries
# ---------------------------------------------------------------------------
print("\n--- Block 6: Triage Query Tests ---")

# CRITICAL KEV CVEs from 2024
triage = cur.execute("""
    SELECT id, cvss_score, cvss_severity, exploitation, kev_date_added
    FROM cves
    WHERE is_kev = 1
      AND cvss_severity = 'CRITICAL'
      AND substr(id, 5, 4) = '2024'
    ORDER BY cvss_score DESC
    LIMIT 5
""").fetchall()
check("CRITICAL KEV CVEs from 2024 queryable", len(triage) > 0,
      f"found={len(triage)}")
if triage:
    print(f"\n  Sample CRITICAL KEV CVEs (2024):")
    for r in triage:
        print(f"    {r['id']}  score={r['cvss_score']}  "
              f"exploitation={r['exploitation']}  kev_added={r['kev_date_added']}")

# Product search
nginx_hits = cur.execute(
    "SELECT DISTINCT cve_id FROM cve_affected "
    "WHERE lower(product) LIKE '%nginx%' LIMIT 10"
).fetchall()
check("Product search (nginx) works", len(nginx_hits) > 0,
      f"found={len(nginx_hits)} CVEs")

ssh_hits = cur.execute(
    "SELECT DISTINCT cve_id FROM cve_affected "
    "WHERE lower(product) LIKE '%openssh%' LIMIT 10"
).fetchall()
check("Product search (openssh) works", len(ssh_hits) > 0,
      f"found={len(ssh_hits)} CVEs")

# Year distribution sanity
year_counts = cur.execute(
    "SELECT substr(id,5,4) yr, COUNT(1) c FROM cves "
    "GROUP BY yr ORDER BY yr"
).fetchall()
years_present = {r[0] for r in year_counts if r[0]}
check("All years 1999-2025 present in DB",
      {str(y) for y in range(1999, 2026)}.issubset(years_present),
      f"missing={sorted({str(y) for y in range(1999,2026)} - years_present)}")

# CWE observed_examples -> CVE reverse linkage
obs_ex_count = cur.execute("SELECT COUNT(1) FROM cwe_observed_examples").fetchone()[0]
check("CWE observed_examples populated", obs_ex_count >= 3000,
      f"count={obs_ex_count:,}")

# Spot-check: CVE-2023-44487 (HTTP/2 Rapid Reset) product data
http2_products = cur.execute(
    "SELECT vendor, product FROM cve_affected WHERE cve_id = 'CVE-2023-44487' LIMIT 5"
).fetchall()
check("CVE-2023-44487 has affected product entries",
      len(http2_products) > 0,
      f"found={[(r['vendor'], r['product']) for r in http2_products]}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
conn.close()

print("\n" + "=" * 60)
total = PASS + FAIL
print(f"  Results: {PASS} passed  /  {FAIL} failed  /  {total} total")
print("=" * 60)

if FAIL > 0:
    print("\n  FAILED tests:")
    for name, passed, detail in RESULTS:
        if not passed:
            print(f"    - {name}")
            if detail:
                print(f"      {detail}")
print()

sys.exit(0 if FAIL == 0 else 1)
