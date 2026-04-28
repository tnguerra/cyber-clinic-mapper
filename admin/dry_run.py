"""Dry-run inspection and extraction helpers for the CVE-to-CWE mapper."""

from __future__ import annotations
from typing import Optional, Tuple, Any
import os
import json
import asyncio


def _extract_cve_info(item: dict) -> Tuple[Optional[str], Optional[str]]:
    """Extract a CVE id and a best-effort title from a CVE item without inserting.

    Returns (cve_id, title). May return (None, None) if nothing useful found.
    This mirrors the logic used by _store_cve_item so the dry-run/inspect tools
    can predict insertion behavior without writing to the DB.
    """
    cve_id: Optional[str] = None
    title: Optional[str] = None
    try:
        if isinstance(item, dict):
            cm = item.get("cveMetadata") or {}
            if isinstance(cm, dict):
                cve_id = cm.get("cveId") or cve_id

        try:
            cna = item.get("containers", {}).get("cna", {}) if isinstance(item.get("containers"), dict) else {}
            legacy = cna.get("x_legacyV4Record") if isinstance(cna, dict) else None
            if legacy and isinstance(legacy, dict):
                cve_id = legacy.get("CVE_data_meta", {}).get("ID") or cve_id
        except Exception:
            cna = {}

        if not cve_id and "cve" in item and isinstance(item["cve"], dict):
            cve_id = item["cve"].get("CVE_data_meta", {}).get("ID") or cve_id

        if not cve_id:
            cve_id = item.get("cveId") or item.get("id") or item.get("ID") or (item.get("CVE_data_meta") or {}).get("ID") or cve_id

        if isinstance(cna, dict):
            title = title or cna.get("title") or cna.get("summary") or title
            try:
                descs = cna.get("descriptions") if isinstance(cna.get("descriptions"), list) else None
                if descs:
                    parts = [d.get("value", "") for d in descs if isinstance(d, dict) and d.get("value")]
                    if parts:
                        if not title and parts:
                            title = parts[0][:200]
            except Exception:
                pass

        # fallback title sources
        if not title and isinstance(item, dict):
            title = item.get("summary") or item.get("title") or (item.get("cve", {}) or {}).get("CVE_data_meta", {}).get("title")
    except Exception:
        return (None, None)
    return (cve_id, title)


async def cve_debug_dry_run_dir(source_dir: str, max_files: int = 200, sample_skips: int = 10) -> dict:
    """Dry-run ingestion across a directory tree without writing to DB.

    Scans up to `max_files` JSON files and reports counts of items examined,
    how many had an extractable CVE id (would_insert), and a small sample of
    skipped item keys for debugging.
    
    Args:
        source_dir: Root directory to scan for CVE JSON files.
        max_files: Maximum number of JSON files to examine.
        sample_skips: Maximum number of skip samples to collect.
    
    Returns:
        Dictionary with dry-run statistics: {source_dir, files_examined, items_examined, would_insert, ...}.
    """
    loop = asyncio.get_running_loop()

    def _worker() -> dict:
        stats = {
            "source_dir": source_dir,
            "files_examined": 0,
            "files_skipped_nonjson": 0,
            "items_examined": 0,
            "would_insert": 0,
            "skipped_items": 0,
            "skipped_samples": [],
        }
        if not source_dir or not os.path.exists(source_dir):
            stats["error"] = "source_dir not found"
            return stats

        files_seen = 0
        for root_dir, _, files in os.walk(source_dir):
            for fname in files:
                if files_seen >= max_files:
                    break
                files_seen += 1
                if not fname.lower().endswith(".json"):
                    stats["files_skipped_nonjson"] += 1
                    continue
                path = os.path.join(root_dir, fname)
                stats["files_examined"] += 1
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        obj = json.load(fh)
                except Exception:
                    continue

                items = []
                if isinstance(obj, dict):
                    if "CVE_Items" in obj:
                        items = obj.get("CVE_Items", [])
                    elif "cve" in obj or "CVE_data_meta" in obj or "cveMetadata" in obj or obj.get("dataType") == "CVE_RECORD":
                        items = [obj]
                elif isinstance(obj, list):
                    items = obj

                for item in items:
                    stats["items_examined"] += 1
                    cid, _ = _extract_cve_info(item)
                    if cid:
                        stats["would_insert"] += 1
                    else:
                        stats["skipped_items"] += 1
                        if len(stats["skipped_samples"]) < int(sample_skips):
                            try:
                                stats["skipped_samples"].append({
                                    "file": path,
                                    "sample_keys": list(item.keys())[:20] if isinstance(item, dict) else [],
                                })
                            except Exception:
                                stats["skipped_samples"].append({"file": path, "sample_keys": []})

        return stats

    return await loop.run_in_executor(None, _worker)
