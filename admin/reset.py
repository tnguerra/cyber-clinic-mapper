"""Database maintenance tools for the CVE-to-CWE mapper."""

from __future__ import annotations
import os
from pathlib import Path


async def cve_reset_db(db_path: Path) -> dict:
    """Delete the local SQLite database file for a clean re-ingestion.
    
    Args:
        db_path: Path to the mapper database file.
    
    Returns:
        Dictionary with reset result: {ok, deleted, path} or {ok, error, path}.
    """
    try:
        db_path_str = str(db_path)
        if os.path.exists(db_path_str):
            os.remove(db_path_str)
            return {"ok": True, "deleted": True, "path": db_path_str}
        return {"ok": True, "deleted": False, "path": db_path_str}
    except Exception as e:
        return {"ok": False, "error": repr(e), "path": str(db_path)}
