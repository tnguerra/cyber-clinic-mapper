"""System and environment diagnostics for the CVE-to-CWE mapper."""

from __future__ import annotations
import sys as _sys
import os
import platform
import sqlite3
import shutil
import multiprocessing
import time
from pathlib import Path


def system_diagnostics(db_path: Path) -> dict:
    """Return system-level diagnostics useful for debugging the mapper.

    Includes OS/platform, Python and SQLite versions, DB path/size, disk usage,
    CPU count, and optional psutil memory/boot info if psutil is available.
    
    Args:
        db_path: Path to the mapper database file.
    
    Returns:
        Dictionary with comprehensive system and environment information.
    """
    out: dict = {}
    try:
        out["platform"] = platform.platform()
    except Exception:
        out["platform"] = None
    try:
        out["python_version"] = _sys.version
    except Exception:
        out["python_version"] = None
    try:
        out["sqlite_version"] = sqlite3.sqlite_version
    except Exception:
        out["sqlite_version"] = None

    try:
        out["db_path"] = str(db_path)
        out["db_exists"] = db_path.exists()
        out["db_size_bytes"] = db_path.stat().st_size if db_path.exists() else None
    except Exception:
        out["db_path"] = None
        out["db_exists"] = False
        out["db_size_bytes"] = None

    # Get data directory from db_path parent
    data_dir = db_path.parent if db_path else Path(".")
    try:
        du = shutil.disk_usage(str(data_dir))
        out.update({"disk_total": du.total, "disk_used": du.used, "disk_free": du.free})
    except Exception:
        out.update({"disk_total": None, "disk_used": None, "disk_free": None})

    try:
        out["cpu_count"] = multiprocessing.cpu_count()
    except Exception:
        out["cpu_count"] = None

    out["timestamp"] = time.time()

    # Optional deeper system info if psutil is available
    try:
        import psutil  # type: ignore

        vm = psutil.virtual_memory()._asdict()
        sw = psutil.swap_memory()._asdict()
        out["psutil"] = {"virtual_memory": vm, "swap_memory": sw, "boot_time": psutil.boot_time()}
    except Exception:
        pass

    return out
