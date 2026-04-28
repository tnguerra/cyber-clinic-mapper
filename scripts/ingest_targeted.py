"""
scripts/ingest_targeted.py -- Targeted CVE/CWE/CIS ingestion for 2023-2025
===========================================================================
Ingests:
  1. CWE XML  (cwec_v4.18.xml)        ~1 min
  2. CIS CSV  (CIS Controls v8.1)     <5 sec
  3. CVE JSONs for selected years     ~15-30 min for 2023-2025

Usage -- run from the MCPFramework-CVE-to-CWE_Mapper directory
with the project venv active:

    cd C:\\Users\\thoma\\Desktop\\Academic\\Cyber_Research\\mcp_servers\\MCPFramework-CVE-to-CWE_Mapper
    .venv\\Scripts\\activate

    python scripts\\ingest_targeted.py --dry-run
    python scripts\\ingest_targeted.py --cwe-only
    python scripts\\ingest_targeted.py --cis-only
    python scripts\\ingest_targeted.py --cve-only --years 2023 2024 2025
    python scripts\\ingest_targeted.py --status
    python scripts\\ingest_targeted.py --reset   # delete DB then full ingest
"""

from __future__ import annotations

import sys
import os
import sqlite3
import json
import time
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (all relative to THIS file's location: scripts/ingest_targeted.py)
# ---------------------------------------------------------------------------
_MAPPER_DIR  = Path(__file__).parent.parent                         # MCPFramework-CVE-to-CWE_Mapper/
_DATA_ROOT   = _MAPPER_DIR.parent.parent / "mcp-data-testing" / "cwe-cve-data"
DB_PATH      = _MAPPER_DIR / "data" / "index.db"
CVE_DIR      = _DATA_ROOT / "cves"
CWE_XML_PATH = _DATA_ROOT / "cwes" / "cwec_v4.18.xml"
CIS_CSV_PATH = _DATA_ROOT / "cis" / "CIS_Controls_Version_8.1.2___March_2025(Controls v8.1.csv"

TARGET_YEARS = [2023, 2024, 2025]

# ---------------------------------------------------------------------------
# Import mapper helpers from the server module
# ---------------------------------------------------------------------------

def _import_mapper():
    srv = str(_MAPPER_DIR)
    if srv not in sys.path:
        sys.path.insert(0, srv)
    try:
        import CVE_CWE_Mapper_server as m
        return m
    except ImportError as e:
        print(f"\n[ERROR] Cannot import CVE_CWE_Mapper_server: {e}")
        print("Make sure the venv is activated:")
        print(r"  .venv\Scripts\activate")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Status helper
# ---------------------------------------------------------------------------

def show_status() -> None:
    print(f"\n  DB : {DB_PATH}")
    if not DB_PATH.exists():
        print("  [NOT FOUND] -- run ingestion first.\n")
        return
    print(f"  Size : {DB_PATH.stat().st_size / 1024 / 1024:.1f} MB")
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cur  = conn.cursor()
        for t in ["cves", "cwes", "cis", "cis_controls", "cve_cwes", "cve_affected"]:
            try:
                n = cur.execute(f"SELECT COUNT(1) FROM {t}").fetchone()[0]
                print(f"    {t:<25} {n:>10,} rows")
            except Exception:
                pass
        conn.close()
    except Exception as e:
        print(f"  [ERROR] {e}")
    print()

# ---------------------------------------------------------------------------
# Dry-run file counter
# ---------------------------------------------------------------------------

def dry_run(years: list[int]) -> None:
    print("\n  DRY RUN -- counting files only, nothing will be written.\n")
    total = 0
    for year in years:
        d = CVE_DIR / str(year)
        if not d.exists():
            print(f"  {year}: directory not found")
            continue
        count = sum(1 for _ in d.rglob("*.json"))
        print(f"  {year}: {count:>7,} JSON files")
        total += count
    print(f"\n  Total CVE files : {total:,}")
    print(f"  CWE XML  : {'EXISTS' if CWE_XML_PATH.exists() else 'NOT FOUND'}")
    print(f"  CIS CSV  : {'EXISTS' if CIS_CSV_PATH.exists() else 'NOT FOUND'}\n")

# ---------------------------------------------------------------------------
# CWE XML ingestion  (uses the mapper's existing helpers)
# ---------------------------------------------------------------------------

def ingest_cwe(mapper, conn: sqlite3.Connection, cur: sqlite3.Cursor) -> None:
    import xml.etree.ElementTree as ET

    if not CWE_XML_PATH.exists():
        print(f"  [SKIP] CWE XML not found: {CWE_XML_PATH}")
        return

    print(f"  Ingesting CWE XML : {CWE_XML_PATH.name}")
    t0 = time.time()

    # Clear existing CWE tables for a clean re-ingest
    for t in (
        "cwes", "cwe_attributes", "cwe_relationships", "cwe_platforms",
        "cwe_modes_of_introduction", "cwe_consequences", "cwe_detection_methods",
        "cwe_mitigations", "cwe_examples", "cwe_observed_examples",
        "cwe_references", "cwe_mapping_notes", "cwe_content_history",
    ):
        try:
            cur.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    conn.commit()

    def _local(elem):
        tag = elem.tag
        return tag.split("}", 1)[1] if isinstance(tag, str) and "}" in tag else tag

    tree = ET.parse(str(CWE_XML_PATH))
    root = tree.getroot()
    count = 0

    for weak in root.iter():
        if _local(weak).lower() != "weakness":
            continue
        wid  = weak.attrib.get("ID") or weak.attrib.get("Id") or weak.attrib.get("id")
        name = weak.attrib.get("Name") or weak.attrib.get("name")
        if not wid or not name:
            continue

        abstraction = weak.attrib.get("Abstraction")
        structure   = weak.attrib.get("Structure")
        status      = weak.attrib.get("Status")

        description = extended_desc = likelihood = None
        parent = None

        for child in weak:
            ln = _local(child).lower()
            if ln == "description":
                description = mapper._xml_text(child)
            elif ln == "extended_description":
                extended_desc = mapper._xml_text(child)
            elif ln == "likelihood_of_exploit":
                likelihood = mapper._xml_text(child)
            elif ln == "related_weaknesses":
                for rw in child:
                    if _local(rw).lower() != "related_weakness":
                        continue
                    nature = rw.attrib.get("Nature")
                    rcwe   = rw.attrib.get("CWE_ID")
                    vid    = rw.attrib.get("View_ID")
                    ordinal = rw.attrib.get("Ordinal")
                    if not parent and (nature or "").lower() == "childof" and rcwe:
                        parent = rcwe
                    cur.execute(
                        "INSERT INTO cwe_relationships (cwe_id,nature,related_cwe_id,view_id,ordinal) VALUES (?,?,?,?,?)",
                        (wid, nature, rcwe, vid, ordinal),
                    )
            elif ln == "applicable_platforms":
                for pe in child:
                    pln = _local(pe).lower()
                    if pln in ("language", "technology"):
                        cur.execute(
                            "INSERT INTO cwe_platforms (cwe_id,kind,class,prevalence) VALUES (?,?,?,?)",
                            (wid, "Language" if pln=="language" else "Technology",
                             pe.attrib.get("Class"), pe.attrib.get("Prevalence")),
                        )
            elif ln == "modes_of_introduction":
                for intro in child:
                    if _local(intro).lower() != "introduction":
                        continue
                    phase = None
                    for c2 in intro:
                        if _local(c2).lower() == "phase":
                            phase = mapper._xml_text(c2)
                    if wid and phase:
                        cur.execute("INSERT INTO cwe_modes_of_introduction (cwe_id,phase) VALUES (?,?)", (wid, phase))
            elif ln == "common_consequences":
                for cons in child:
                    if _local(cons).lower() != "consequence":
                        continue
                    scope = impact = note = None
                    for c2 in cons:
                        ln2 = _local(c2).lower()
                        if ln2 == "scope":   scope  = mapper._xml_text(c2)
                        elif ln2 == "impact": impact = mapper._xml_text(c2)
                        elif ln2 == "note":   note   = mapper._xml_text(c2)
                    cur.execute("INSERT INTO cwe_consequences (cwe_id,scope,impact,note) VALUES (?,?,?,?)", (wid,scope,impact,note))
            elif ln == "detection_methods":
                for dm in child:
                    if _local(dm).lower() != "detection_method":
                        continue
                    mid = dm.attrib.get("Detection_Method_ID")
                    method = desc_d = eff = None
                    for c2 in dm:
                        ln2 = _local(c2).lower()
                        if ln2 == "method":      method = mapper._xml_text(c2)
                        elif ln2 == "description": desc_d = mapper._xml_text(c2)
                        elif ln2 == "effectiveness": eff  = mapper._xml_text(c2)
                    cur.execute("INSERT INTO cwe_detection_methods (cwe_id,method_id,method,description,effectiveness) VALUES (?,?,?,?,?)", (wid,mid,method,desc_d,eff))
            elif ln == "potential_mitigations":
                for m in child:
                    if _local(m).lower() != "mitigation":
                        continue
                    phase = desc_m = eff = eff_notes = None
                    for c2 in m:
                        ln2 = _local(c2).lower()
                        if ln2 == "phase":          phase    = mapper._xml_text(c2)
                        elif ln2 == "description":  desc_m   = mapper._xml_text(c2)
                        elif ln2 == "effectiveness": eff     = mapper._xml_text(c2)
                        elif ln2 == "effectiveness_notes": eff_notes = mapper._xml_text(c2)
                    cur.execute("INSERT INTO cwe_mitigations (cwe_id,phase,description,effectiveness,effectiveness_notes) VALUES (?,?,?,?,?)", (wid,phase,desc_m,eff,eff_notes))
            elif ln == "demonstrative_examples":
                for ex in child:
                    if _local(ex).lower() != "demonstrative_example":
                        continue
                    intro_text = body_text = code_text = nature = language = None
                    for c2 in ex:
                        ln2 = _local(c2).lower()
                        if ln2 == "intro_text":   intro_text = mapper._xml_text(c2)
                        elif ln2 == "body_text":
                            t = mapper._xml_text(c2)
                            body_text = (body_text + "\n" + t) if body_text else t
                        elif ln2 == "example_code":
                            nature   = c2.attrib.get("Nature")
                            language = c2.attrib.get("Language")
                            code_text = mapper._xml_text(c2)
                    cur.execute("INSERT INTO cwe_examples (cwe_id,nature,language,intro_text,body_text,code_text) VALUES (?,?,?,?,?,?)", (wid,nature,language,intro_text,body_text,code_text))
            elif ln == "observed_examples":
                for ob in child:
                    if _local(ob).lower() != "observed_example":
                        continue
                    ref = desc_o = link = None
                    for c2 in ob:
                        ln2 = _local(c2).lower()
                        if ln2 == "reference":   ref    = mapper._xml_text(c2)
                        elif ln2 == "description": desc_o = mapper._xml_text(c2)
                        elif ln2 == "link":       link   = mapper._xml_text(c2)
                    cur.execute("INSERT INTO cwe_observed_examples (cwe_id,reference,description,link) VALUES (?,?,?,?)", (wid,ref,desc_o,link))
            elif ln == "references":
                for r in child:
                    if _local(r).lower() != "reference":
                        continue
                    ext_id = r.attrib.get("External_Reference_ID")
                    if ext_id:
                        cur.execute("INSERT INTO cwe_references (cwe_id,external_reference_id) VALUES (?,?)", (wid, ext_id))
            elif ln == "mapping_notes":
                usage = rationale = comments = reasons = None
                for c2 in child:
                    ln2 = _local(c2).lower()
                    if ln2 == "usage":      usage     = mapper._xml_text(c2)
                    elif ln2 == "rationale": rationale = mapper._xml_text(c2)
                    elif ln2 == "comments":  comments  = mapper._xml_text(c2)
                    elif ln2 == "reasons":
                        rs = []
                        for r3 in c2:
                            if _local(r3).lower() == "reason":
                                rs.append(r3.attrib.get("Type") or mapper._xml_text(r3))
                        reasons = "; ".join(r for r in rs if r)
                cur.execute("INSERT INTO cwe_mapping_notes (cwe_id,usage,rationale,comments,reasons) VALUES (?,?,?,?,?)", (wid,usage,rationale,comments,reasons))
            elif ln == "content_history":
                for ev in child:
                    evtype = _local(ev)
                    if evtype not in ("Submission", "Modification"):
                        continue
                    name_e = org_e = date_e = ver_e = rdate_e = comment_e = None
                    for c2 in ev:
                        ln2  = _local(c2)
                        text = mapper._xml_text(c2)
                        if ln2 in ("Submission_Name", "Modification_Name"):         name_e    = text
                        elif ln2 in ("Submission_Organization", "Modification_Organization"): org_e = text
                        elif ln2 in ("Submission_Date", "Modification_Date"):       date_e    = text
                        elif ln2 == "Submission_Version":    ver_e    = text
                        elif ln2 == "Submission_ReleaseDate": rdate_e  = text
                        elif ln2 == "Modification_Comment":  comment_e = text
                    cur.execute(
                        "INSERT INTO cwe_content_history (cwe_id,event_type,name,organization,date,version,release_date,comment) VALUES (?,?,?,?,?,?,?,?)",
                        (wid, evtype, name_e, org_e, date_e, ver_e, rdate_e, comment_e),
                    )

        cur.execute(
            "INSERT OR REPLACE INTO cwes (id,name,description,parent) VALUES (?,?,?,?)",
            (wid, name, description or "", parent),
        )
        cur.execute(
            "INSERT OR REPLACE INTO cwe_attributes (cwe_id,abstraction,structure,status,extended_description,likelihood) VALUES (?,?,?,?,?,?)",
            (wid, abstraction, structure, status, extended_desc or "", likelihood),
        )
        count += 1

    conn.commit()
    print(f"  CWE done : {count:,} weaknesses in {time.time()-t0:.1f}s\n")

# ---------------------------------------------------------------------------
# CIS CSV ingestion
# ---------------------------------------------------------------------------

def ingest_cis(mapper, conn: sqlite3.Connection, cur: sqlite3.Cursor) -> None:
    import csv as _csv

    if not CIS_CSV_PATH.exists():
        print(f"  [SKIP] CIS CSV not found: {CIS_CSV_PATH}")
        return

    print(f"  Ingesting CIS CSV : {CIS_CSV_PATH.name}")
    t0 = time.time()

    # Clear both CIS tables for a clean re-ingest
    for t in ("cis", "cis_controls"):
        try:
            cur.execute(f"DELETE FROM {t}")
        except Exception:
            pass
    conn.commit()

    inserted = skipped = 0
    with open(str(CIS_CSV_PATH), "r", encoding="utf-8", errors="replace") as fh:
        reader = _csv.reader(fh)
        for i, row in enumerate(reader):
            if i == 0:
                header = [c.strip().lower() for c in row]
                if not any("cis control" in h for h in header):
                    print(f"  [ERROR] Unexpected header: {row}")
                    return
                continue
            parsed = mapper._parse_cis_csv_row(row)
            if not parsed.get("control") and not parsed.get("title"):
                skipped += 1
                continue
            if parsed.get("is_summary"):
                cid = mapper._normalize_cis_control_id(parsed.get("control"))
                if cid and parsed.get("title"):
                    cur.execute(
                        "INSERT OR REPLACE INTO cis_controls (control,title,description) VALUES (?,?,?)",
                        (cid, parsed["title"], parsed.get("description")),
                    )
                skipped += 1
                continue
            cur.execute(
                "INSERT INTO cis (control,safeguard,asset_class,security_function,title,description,ig1,ig2,ig3) VALUES (?,?,?,?,?,?,?,?,?)",
                (parsed["control"], parsed["safeguard"], parsed["asset_class"],
                 parsed["security_function"], parsed["title"], parsed["description"],
                 parsed["ig1"], parsed["ig2"], parsed["ig3"]),
            )
            inserted += 1

    conn.commit()
    print(f"  CIS done : {inserted:,} safeguards, {skipped} skipped in {time.time()-t0:.1f}s\n")

# ---------------------------------------------------------------------------
# CVE JSON ingestion
# ---------------------------------------------------------------------------

def ingest_cves(mapper, conn: sqlite3.Connection, cur: sqlite3.Cursor, years: list[int]) -> None:
    for year in years:
        year_dir = CVE_DIR / str(year)
        if not year_dir.exists():
            print(f"  [SKIP] {year}: no directory at {year_dir}")
            continue

        files = sorted(year_dir.rglob("*.json"))
        print(f"  Ingesting {year}: {len(files):,} files ...")
        t0 = year_ok = year_err = 0
        t0 = time.time()

        for i, fpath in enumerate(files):
            try:
                mapper._ingest_file_into_db(str(fpath), conn, cur)
                year_ok += 1
            except Exception:
                year_err += 1

            if (i + 1) % 5000 == 0:
                elapsed = time.time() - t0
                rate    = (i + 1) / max(elapsed, 0.001)
                remain  = (len(files) - i - 1) / max(rate, 1)
                print(f"    {i+1:>7,}/{len(files):,}  |  {rate:.0f} files/sec  |  ~{remain:.0f}s left")

            if (i + 1) % 1000 == 0:
                conn.commit()

        conn.commit()
        print(f"  {year} done: {year_ok:,} ingested, {year_err} errors in {time.time()-t0:.1f}s\n")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Targeted CVE/CWE/CIS ingestion")
    parser.add_argument("--cwe-only",  action="store_true")
    parser.add_argument("--cis-only",  action="store_true")
    parser.add_argument("--cve-only",  action="store_true")
    parser.add_argument("--years",     nargs="+", type=int, default=TARGET_YEARS)
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--reset",     action="store_true", help="Delete existing DB first")
    parser.add_argument("--status",    action="store_true", help="Show DB stats and exit")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  Targeted Ingestion -- CVE-to-CWE Mapper")
    print("=" * 60)

    if args.status:
        show_status()
        return

    if args.dry_run:
        dry_run(args.years)
        return

    mapper = _import_mapper()

    if args.reset and DB_PATH.exists():
        print(f"  Deleting DB: {DB_PATH}")
        DB_PATH.unlink()
        for ext in ("-wal", "-shm"):
            p = Path(str(DB_PATH) + ext)
            if p.exists():
                p.unlink()
        print("  DB deleted.\n")

    DB_PATH.parent.mkdir(exist_ok=True)
    conn = mapper._get_mapper_conn()
    mapper._ensure_mapper_schema(conn)
    mapper._ensure_cis_schema(conn)
    mapper._ensure_cwe_extended_schema(conn)
    cur = conn.cursor()

    do_all = not (args.cwe_only or args.cis_only or args.cve_only)

    if do_all or args.cwe_only:
        ingest_cwe(mapper, conn, cur)

    if do_all or args.cis_only:
        ingest_cis(mapper, conn, cur)

    if do_all or args.cve_only:
        ingest_cves(mapper, conn, cur, args.years)

    conn.close()
    show_status()


if __name__ == "__main__":
    main()
