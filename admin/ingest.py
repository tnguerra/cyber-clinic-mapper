"""Data ingestion tools for the CVE-to-CWE mapper."""

from __future__ import annotations
from typing import Any, Optional, Dict
import os
import json
import csv
import asyncio
import sqlite3
from pathlib import Path


async def cve_ingest_file(file_path: str, get_mapper_conn, ensure_mapper_schema, ingest_file_into_db) -> dict:
    """Ingest a single CVE JSON file into the local index.
    
    Args:
        file_path: Path to CVE JSON file.
        get_mapper_conn: Function to get database connection.
        ensure_mapper_schema: Function to ensure schema exists.
        ingest_file_into_db: Function to ingest file into database.
    
    Returns:
        Dictionary with ingestion result: {ok, ingested, total_cves} or {ok, error}.
    """
    loop = asyncio.get_running_loop()

    def _worker() -> dict:
        # Basic validation to avoid machine-specific assumptions
        if not file_path or not os.path.isfile(file_path) or not file_path.lower().endswith(".json"):
            return {"ok": False, "error": f"file_path must be an existing .json file: {file_path}"}
        conn = get_mapper_conn()
        ensure_mapper_schema(conn)
        cur = conn.cursor()
        ingest_file_into_db(file_path, conn, cur)
        conn.commit()
        cur.execute("SELECT COUNT(1) c FROM cves")
        total = cur.fetchone()["c"]
        conn.close()
        return {"ok": True, "ingested": 1, "total_cves": total}

    return await loop.run_in_executor(None, _worker)


async def cve_ingest_cwe_xml(
    cwe_xml_path: str,
    replace: bool,
    get_mapper_conn,
    ingest_cwe_xml_into_db
) -> dict:
    """Ingest CWE XML (v4.18) into the extended CWE tables.

    If replace=True, clears existing CWE tables before ingesting.
    
    Args:
        cwe_xml_path: Path to CWE XML file (e.g., cwec_v4.18.xml).
        replace: If True, clear existing CWE tables before ingesting.
        get_mapper_conn: Function to get database connection.
        ingest_cwe_xml_into_db: Function to perform CWE XML ingestion.
    
    Returns:
        Dictionary with ingestion result: {ok, inserted, total_cwes} or {ok, error, inserted}.
    """
    if not cwe_xml_path or not os.path.exists(cwe_xml_path):
        return {"ok": False, "error": f"cwe_xml_path not found: {cwe_xml_path}"}
    loop = asyncio.get_running_loop()

    def _worker() -> dict:
        conn = get_mapper_conn()
        cur = conn.cursor()
        try:
            cwe_count = ingest_cwe_xml_into_db(conn, cwe_xml_path, replace=replace)
        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            return {"ok": False, "error": repr(e), "inserted": 0}

        total = None
        try:
            cur.execute("SELECT COUNT(1) FROM cwes")
            total = cur.fetchone()[0]
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        return {"ok": True, "inserted": cwe_count, "total_cwes": total}

    return await loop.run_in_executor(None, _worker)


async def cve_ingest_cis(
    cis_csv_path: str,
    replace: bool,
    get_mapper_conn,
    ensure_mapper_schema,
    ensure_cis_schema,
    parse_cis_csv_row,
    normalize_cis_control_id
) -> dict:
    """Ingest CIS CSV into unified structured 'cis' table.

    If replace=True, clears existing structured rows first.
    
    Args:
        cis_csv_path: Path to CIS CSV file.
        replace: If True, clear existing rows before ingesting.
        get_mapper_conn: Function to get database connection.
        ensure_mapper_schema: Function to ensure mapper schema.
        ensure_cis_schema: Function to ensure CIS schema.
        parse_cis_csv_row: Function to parse CIS CSV row.
        normalize_cis_control_id: Function to normalize CIS control ID.
    
    Returns:
        Dictionary with ingestion result or error information.
    """
    if not cis_csv_path or not os.path.exists(cis_csv_path):
        return {"ok": False, "error": f"cis_csv_path not found: {cis_csv_path}"}
    loop = asyncio.get_running_loop()

    def _worker() -> dict:
        conn = get_mapper_conn()
        ensure_mapper_schema(conn)
        ensure_cis_schema(conn)
        cur = conn.cursor()
        inserted = 0
        skipped = 0
        errors = 0
        if replace:
            try:
                cur.execute("DELETE FROM cis")
                conn.commit()
            except Exception:
                pass
        try:
            with open(cis_csv_path, "r", encoding="utf-8", errors="replace") as fh:
                r = csv.reader(fh)
                header = None
                for i, row in enumerate(r):
                    if i == 0:
                        header = [c.strip().lower() for c in row]
                        if not any("cis control" in h for h in header) or not any("title" in h for h in header):
                            return {"ok": False, "error": f"unexpected header: {row}"}
                        continue
                    try:
                        parsed = parse_cis_csv_row(row)
                        if not parsed.get("control") and not parsed.get("title"):
                            skipped += 1
                            continue
                        if parsed.get("is_summary"):
                            cid = normalize_cis_control_id(parsed.get("control"))
                            if cid and parsed.get("title"):
                                cur.execute(
                                    "INSERT OR REPLACE INTO cis_controls (control, title, description) VALUES (?, ?, ?)",
                                    (cid, parsed.get("title"), parsed.get("description")),
                                )
                            skipped += 1
                            continue
                        cur.execute(
                            """
                            INSERT INTO cis (
                                control, safeguard, asset_class, security_function,
                                title, description, ig1, ig2, ig3
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                parsed["control"], parsed["safeguard"], parsed["asset_class"], parsed["security_function"],
                                parsed["title"], parsed["description"], parsed["ig1"], parsed["ig2"], parsed["ig3"],
                            ),
                        )
                        inserted += 1
                    except Exception:
                        errors += 1
                conn.commit()
        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            return {"ok": False, "error": repr(e), "inserted": inserted, "skipped": skipped, "errors": errors}
        try:
            cur.execute("SELECT COUNT(1) FROM cis")
            total = cur.fetchone()[0]
        except Exception:
            total = None
        try:
            conn.close()
        except Exception:
            pass
        return {"ok": True, "inserted": inserted, "total_cis": total, "skipped": skipped, "errors": errors}

    return await loop.run_in_executor(None, _worker)


async def cve_build_index(
    source_dir: str | None,
    cwe_xml_path: str | None,
    cis_csv_path: str | None,
    reindex: bool,
    get_mapper_conn,
    ensure_mapper_schema,
    ensure_cis_schema,
    ingest_cwe_xml_into_db,
    ingest_file_into_db,
    parse_cis_csv_row,
    normalize_cis_control_id,
    prepare_thread_event_loop,
    mapper_db: Path,
    log_func=None,
    ctx=None
) -> dict:
    """Build the sqlite index from a directory of CVE JSONs (nested year/xxx) and optional CWE XML and CIS CSV.

    Args:
        source_dir: Path to directory containing nested CVE JSON files (optional).
        cwe_xml_path: Path to CWE XML file (optional).
        cis_csv_path: Path to CIS CSV file (optional).
        reindex: If True, remove existing DB first and rebuild atomically.
        get_mapper_conn: Function to get database connection.
        ensure_mapper_schema: Function to ensure mapper schema.
        ensure_cis_schema: Function to ensure CIS schema.
        ingest_cwe_xml_into_db: Function to ingest CWE XML.
        ingest_file_into_db: Function to ingest CVE JSON files.
        parse_cis_csv_row: Function to parse CIS CSV rows.
        normalize_cis_control_id: Function to normalize CIS control IDs.
        prepare_thread_event_loop: Function to prepare event loop in thread.
        mapper_db: Path to mapper database.
        log_func: Optional logging function.
        ctx: Optional MCP context for progress reporting.
    
    Returns:
        Dictionary with build result or error information.
    """
    loop = asyncio.get_running_loop()

    def _worker() -> dict:
        if prepare_thread_event_loop:
            prepare_thread_event_loop()

        # Early validation of optional paths for clearer portability
        if source_dir and not os.path.isdir(source_dir):
            return {"ok": False, "error": f"source_dir not found or not a directory: {source_dir}"}
        if cwe_xml_path and not os.path.isfile(cwe_xml_path):
            return {"ok": False, "error": f"cwe_xml_path not found: {cwe_xml_path}"}
        if cis_csv_path and not os.path.isfile(cis_csv_path):
            return {"ok": False, "error": f"cis_csv_path not found: {cis_csv_path}"}

        # If reindex requested, build the new index into a temporary DB file
        tmp_db_path = None
        if reindex:
            try:
                parent = str(mapper_db.parent)
            except Exception:
                parent = None
            tmp_db_path = str(mapper_db) + ".tmp"
            # ensure any stale tmp is removed
            try:
                if os.path.exists(tmp_db_path):
                    os.remove(tmp_db_path)
            except Exception:
                pass
            target_db_path = tmp_db_path
        else:
            target_db_path = None

        # Open the connection to the chosen target (tmp or live)
        conn = get_mapper_conn(db_path=target_db_path)
        ensure_mapper_schema(conn)
        cur = conn.cursor()

        cwe_count = 0
        if cwe_xml_path and os.path.exists(cwe_xml_path):
            try:
                cwe_count = ingest_cwe_xml_into_db(conn, cwe_xml_path, replace=False)
            except Exception as e:
                if log_func:
                    log_func(f"Failed to parse CWE XML: {e!r}")

        cis_count = 0
        if cis_csv_path and os.path.exists(cis_csv_path):
            try:
                # Ensure unified structured 'cis' table, then ingest via structured parser
                ensure_cis_schema(conn)
                cis_header_error = None
                with open(cis_csv_path, "r", encoding="utf-8", errors="replace") as fh:
                    r = csv.reader(fh)
                    header = None
                    for i, row in enumerate(r):
                        if i == 0:
                            header = [c.strip().lower() for c in row]
                            if not any("cis control" in h for h in header) or not any("title" in h for h in header):
                                cis_header_error = f"unexpected header: {row}"
                                if log_func:
                                    log_func(f"Failed to load CIS CSV: {cis_header_error}")
                                break
                            continue
                        parsed = parse_cis_csv_row(row)
                        if not parsed.get("control") and not parsed.get("title"):
                            continue
                        if parsed.get("is_summary"):
                            cid = normalize_cis_control_id(parsed.get("control"))
                            if cid and parsed.get("title"):
                                cur.execute(
                                    "INSERT OR REPLACE INTO cis_controls (control, title, description) VALUES (?, ?, ?)",
                                    (cid, parsed.get("title"), parsed.get("description")),
                                )
                            continue
                        cur.execute(
                            """
                            INSERT INTO cis (
                                control, safeguard, asset_class, security_function,
                                title, description, ig1, ig2, ig3
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                parsed["control"], parsed["safeguard"], parsed["asset_class"], parsed["security_function"],
                                parsed["title"], parsed["description"], parsed["ig1"], parsed["ig2"], parsed["ig3"],
                            ),
                        )
                        cis_count += 1
                conn.commit()
                if cis_header_error:
                    conn.close()
                    return {"ok": False, "error": cis_header_error, "cis_count": cis_count, "ingested_cves": 0, "errors": 0}
            except Exception as e:
                if log_func:
                    log_func(f"Failed to load CIS CSV: {e!r}")

        ingested = 0
        errors = 0
        # CVE ingestion is optional; skip if source_dir is None or does not exist.
        if source_dir and os.path.exists(source_dir):
            for root_dir, _, files in os.walk(source_dir):
                for fname in files:
                    if not fname.lower().endswith(".json"):
                        continue
                    path = os.path.join(root_dir, fname)
                    try:
                        ingest_file_into_db(path, conn, cur)
                        ingested += 1
                        if ctx and ingested % 200 == 0:
                            try:
                                # Use the event loop captured in the outer async function
                                asyncio.run_coroutine_threadsafe(
                                    ctx.report_progress(progress=min(1.0, ingested / 1000.0), total=1.0,
                                                        message=f"Ingested: {ingested}"), loop
                                )
                            except Exception:
                                pass
                    except Exception:
                        errors += 1
        else:
            if log_func:
                log_func("cve_build_index: skipping CVE ingestion (no source_dir provided or not found)")
        conn.commit()
        conn.close()

        # If we built into a temporary DB, atomically replace the live DB file.
        if reindex and tmp_db_path:
            try:
                live_path = str(mapper_db)
                backup_path = live_path + ".bak"
                # move existing live DB to backup (if exists) then replace
                try:
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                except Exception:
                    pass
                try:
                    if os.path.exists(live_path):
                        os.replace(live_path, backup_path)
                except Exception:
                    # if we can't move the existing live DB, try to remove it
                    try:
                        if os.path.exists(live_path):
                            os.remove(live_path)
                    except Exception:
                        pass
                # replace tmp into live location
                os.replace(tmp_db_path, live_path)
                # remove backup if all good
                try:
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                except Exception:
                    pass
            except Exception as e:
                if log_func:
                    log_func(f"Failed to atomically replace DB: {e!r}")
                # Attempt cleanup of tmp file
                try:
                    if os.path.exists(tmp_db_path):
                        os.remove(tmp_db_path)
                except Exception:
                    pass
                raise

        return {"ok": True, "cwe_count": cwe_count, "cis_count": cis_count, "ingested_cves": ingested, "errors": errors}

    result = await loop.run_in_executor(None, _worker)
    if ctx:
        try:
            await ctx.report_progress(progress=1.0, total=1.0, message="Index build complete")
        except Exception:
            pass
    return result
