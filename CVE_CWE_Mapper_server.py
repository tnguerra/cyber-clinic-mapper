"""
Minimal Python MCP server for Claude Desktop (stdio transport).

Tools provided:
- echo(text): echoes the text
- add(a, b): adds two numbers
- get_time(tz): returns ISO timestamp in local time or UTC

Also exposes:
- Resource: greeting://{name}
- Prompt: Friendly Greeting

Run directly (stdio):
    python server.py

Dev with MCP Inspector (after installing mcp[cli]):
    mcp dev server.py

Install into Claude Desktop automatically:
    mcp install server.py --name "MCPFramework-Pyshark"
"""

from __future__ import annotations

import datetime as _dt
from collections import Counter
from typing import TypedDict, Any, List, Optional, Dict, Tuple
import asyncio as _asyncio

# CVE/CWE mapper dependencies
import os
import re
import json
import sqlite3
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
import unicodedata

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
import sys as _sys
import shutil as _shutil


# Create the FastMCP server instance
mcp = FastMCP(
    name="MCPFramework-Pyshark",
    instructions=(
        "A tiny demo MCP server written in Python. It has a few example tools, "
        "a resource, and a prompt."
    ),
)
def _log(msg: str) -> None:
    try:
        print(f"[mcppython] {msg}", file=_sys.stderr)
    except Exception:
        pass

_log("Starting server module load")


def _prepare_thread_event_loop() -> None:
    """Ensure a usable asyncio event loop in the current (worker) thread.

    On Windows in some host environments (e.g. Claude Desktop sandbox) threads spawned via
    asyncio.to_thread may not have a default loop, and some libraries (pyshark / asyncio
    utilities they indirectly use) call get_event_loop(). This helper creates and sets a
    new loop if absent. It is a no-op if a loop already exists.
    """
    try:
        import asyncio
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except Exception:
        pass








# Removed non-essential greeting resource/prompt to keep server minimal for mapper testing


# ---------------- Mapper globals & helpers (restored after accidental truncation) ----------------
# Optional: load .env for local development; safe no-op if missing
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

_ENV_DB = os.environ.get("MAPPER_DB_PATH")
_DEFAULT_LOCAL_DATA_DIR = Path(__file__).parent / "data"
try:
    _DEFAULT_LOCAL_DATA_DIR.mkdir(exist_ok=True)
except Exception:
    pass
_MAPPER_DB = Path(_ENV_DB) if _ENV_DB else _DEFAULT_LOCAL_DATA_DIR / "index.db"


def _get_mapper_conn(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open a sqlite connection with defensive PRAGMA settings.

    db_path: optional override path (used for atomic rebuilds).
    Returns a connection with row_factory=sqlite3.Row.
    """
    target = Path(db_path) if db_path else _MAPPER_DB
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=FULL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA temp_store=MEMORY")
    except Exception:
        pass
    return conn


def _ensure_mapper_schema(conn: sqlite3.Connection) -> None:
    """Create base tables (cves, cwes). Legacy raw cis table creation removed; structured handled separately."""
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            json TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwes (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            parent TEXT
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_title ON cves(title)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cves_desc ON cves(description)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwes_name ON cwes(name)")
    conn.commit()


def _ensure_cis_schema(conn: sqlite3.Connection) -> None:
    """Ensure unified structured CIS table 'cis'. Migrate from legacy tables if present.

    Actions:
      - If existing 'cis' has only a 'raw' column (legacy), rename to 'cis_raw_legacy'.
      - Create structured 'cis' table if absent.
      - If 'cis_structured' exists, copy rows into new 'cis' then drop 'cis_structured'.
    """
    cur = conn.cursor()
    # Detect existing cis schema
    legacy_raw = False
    try:
        cur.execute("PRAGMA table_info(cis)")
        cols = [r[1] for r in cur.fetchall()]  # second col is name
        if cols == ["raw"]:
            legacy_raw = True
    except Exception:
        pass
    if legacy_raw:
        try:
            cur.execute("ALTER TABLE cis RENAME TO cis_raw_legacy")
        except Exception:
            pass
    # Create structured cis table if not exists
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            control TEXT,
            safeguard TEXT,
            asset_class TEXT,
            security_function TEXT,
            title TEXT,
            description TEXT,
            ig1 INTEGER,
            ig2 INTEGER,
            ig3 INTEGER
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cis_control ON cis(control)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cis_safeguard ON cis(safeguard)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cis_title_desc ON cis(title, description)")
    # Migrate from cis_structured if present
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cis_structured'")
        if cur.fetchone():
            try:
                cur.execute("INSERT INTO cis (control, safeguard, asset_class, security_function, title, description, ig1, ig2, ig3) SELECT control, safeguard, asset_class, security_function, title, description, ig1, ig2, ig3 FROM cis_structured")
            except Exception:
                pass
            try:
                cur.execute("DROP TABLE cis_structured")
            except Exception:
                pass
    except Exception:
        pass
    conn.commit()


def _ensure_cwe_extended_schema(conn: sqlite3.Connection) -> None:
    """Create extended CWE tables capturing richer metadata if absent."""
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_attributes (
            cwe_id TEXT PRIMARY KEY,
            abstraction TEXT,
            structure TEXT,
            status TEXT,
            extended_description TEXT,
            likelihood TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_relationships (
            cwe_id TEXT,
            nature TEXT,
            related_cwe_id TEXT,
            view_id TEXT,
            ordinal TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_platforms (
            cwe_id TEXT,
            kind TEXT,
            class TEXT,
            prevalence TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_modes_of_introduction (
            cwe_id TEXT,
            phase TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_consequences (
            cwe_id TEXT,
            scope TEXT,
            impact TEXT,
            note TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_detection_methods (
            cwe_id TEXT,
            method_id TEXT,
            method TEXT,
            description TEXT,
            effectiveness TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_mitigations (
            cwe_id TEXT,
            phase TEXT,
            description TEXT,
            effectiveness TEXT,
            effectiveness_notes TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_examples (
            cwe_id TEXT,
            nature TEXT,
            language TEXT,
            intro_text TEXT,
            body_text TEXT,
            code_text TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_observed_examples (
            cwe_id TEXT,
            reference TEXT,
            description TEXT,
            link TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_references (
            cwe_id TEXT,
            external_reference_id TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_mapping_notes (
            cwe_id TEXT,
            usage TEXT,
            rationale TEXT,
            comments TEXT,
            reasons TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cwe_content_history (
            cwe_id TEXT,
            event_type TEXT,
            name TEXT,
            organization TEXT,
            date TEXT,
            version TEXT,
            release_date TEXT,
            comment TEXT
        )
        """
    )
    # Indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_rel_cwe ON cwe_relationships(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_platforms_cwe ON cwe_platforms(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_modes_cwe ON cwe_modes_of_introduction(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_conseq_cwe ON cwe_consequences(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_detect_cwe ON cwe_detection_methods(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_mitig_cwe ON cwe_mitigations(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_examples_cwe ON cwe_examples(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_obs_ex_cwe ON cwe_observed_examples(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_refs_cwe ON cwe_references(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_map_notes_cwe ON cwe_mapping_notes(cwe_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cwe_history_cwe ON cwe_content_history(cwe_id)")
    conn.commit()


def _xml_text(elem) -> str:
    try:
        return ET.tostring(elem, encoding="unicode", method="text").strip()
    except Exception:
        return (elem.text or "").strip() if getattr(elem, "text", None) else ""


_WORD_RE = re.compile(r"[A-Za-z0-9]+")


def _tokenize(text: str) -> List[str]:
    if not text:
        return []
    return [t.lower() for t in _WORD_RE.findall(text)]


def _score_overlap(query_tokens: List[str], doc_tokens: List[str]) -> float:
    """Bounded overlap score using Jaccard similarity over token sets."""
    if not query_tokens or not doc_tokens:
        return 0.0
    qa = set(query_tokens)
    da = set(doc_tokens)
    inter = len(qa & da)
    union = len(qa | da)
    if union == 0:
        return 0.0
    return inter / union


STOPWORDS = {
    "the","a","an","and","or","of","to","for","with","on","in","by","be","is","are","as","at","from","can","may","should","also","must","will","this","that","use","using","it","their","they","them","your","into"
}


def _filter_tokens(tokens: List[str]) -> List[str]:
    return [t for t in tokens if t not in STOPWORDS and len(t) > 2]


def _store_cve_item(item: dict, cur: sqlite3.Cursor) -> None:
    """Extract core CVE fields and insert into cves table.

    Attempts multiple layout patterns (v5, legacy v4, bundles). Skips when no id found.
    """
    cve_id: Optional[str] = None
    title: Optional[str] = None
    desc: Optional[str] = None
    legacy: Optional[dict] = None
    cna: Optional[dict] = None
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
                        if not title:
                            title = parts[0][:200]
                        desc = " ".join(parts)
            except Exception:
                pass
        if not desc and legacy and isinstance(legacy, dict):
            try:
                ddata = legacy.get("description", {}).get("description_data") or legacy.get("description_data")
                if ddata:
                    desc = " ".join([d.get("value", "") for d in ddata if isinstance(d, dict)])
            except Exception:
                pass
        if not desc:
            if isinstance(item.get("description"), str):
                desc = item.get("description")
            elif isinstance(item.get("description"), dict):
                try:
                    ddata = item["description"].get("description_data", [])
                    if ddata:
                        desc = " ".join([d.get("value", "") for d in ddata if isinstance(d, dict)])
                except Exception:
                    pass
        title = title or item.get("summary") or item.get("title") or ""
        desc = desc or ""
    except Exception as e:
        _log(f"_store_cve_item: extraction error: {e!r}")
    if not cve_id:
        try:
            keys = list(item.keys())[:12] if isinstance(item, dict) else []
            _log(f"Skipping item (no CVE id found). Sample keys: {keys}")
        except Exception:
            _log("Skipping item (no CVE id found).")
        return
    try:
        cur.execute(
            "INSERT OR REPLACE INTO cves (id, title, description, json) VALUES (?, ?, ?, ?)",
            (cve_id, title or "", desc or "", json.dumps(item)),
        )
    except Exception as e:
        _log(f"Failed to insert CVE {cve_id}: {e!r}")


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

def _ingest_file_into_db(path: str, conn: sqlite3.Connection, cur: sqlite3.Cursor) -> None:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        obj = json.load(fh)
    # Recognize multiple common CVE file shapes:
    # - NVD bundle with "CVE_Items"
    # - CVE v5 single record with top-level "cveMetadata" or dataType == "CVE_RECORD"
    # - Legacy NVD/v4 style with "cve" / "CVE_data_meta"
    if isinstance(obj, dict):
        if "CVE_Items" in obj:
            for item in obj.get("CVE_Items", []):
                _store_cve_item(item, cur)
        elif "cve" in obj or "CVE_data_meta" in obj or "cveMetadata" in obj or obj.get("dataType") == "CVE_RECORD":
            _store_cve_item(obj, cur)
    elif isinstance(obj, list):
        for item in obj:
            try:
                _store_cve_item(item, cur)
            except Exception:
                pass
    conn.commit()


@mcp.tool()
async def cve_build_index(
    source_dir: str | None = None,
    cwe_xml_path: str | None = None,
    cis_csv_path: str | None = None,
    reindex: bool = False,
    ctx: Context[ServerSession, None] | None = None,
) -> dict:
    """Build the sqlite index from a directory of CVE JSONs (nested year/xxx) and optional CWE XML and CIS CSV.

    source_dir: path to directory containing nested CVE JSON files
    cwe_xml_path: optional path to cwec_v4.18.xml
    cis_csv_path: optional path to CIS CSV
    reindex: if True, remove existing DB first
    """
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        _prepare_thread_event_loop()

        # Early validation of optional paths for clearer portability
        if source_dir and not os.path.isdir(source_dir):
            return {"ok": False, "error": f"source_dir not found or not a directory: {source_dir}"}
        if cwe_xml_path and not os.path.isfile(cwe_xml_path):
            return {"ok": False, "error": f"cwe_xml_path not found: {cwe_xml_path}"}
        if cis_csv_path and not os.path.isfile(cis_csv_path):
            return {"ok": False, "error": f"cis_csv_path not found: {cis_csv_path}"}

        # If reindex requested, build the new index into a temporary DB file in
        # the same directory and atomically replace the live DB on success.
        tmp_db_path = None
        if reindex:
            try:
                parent = str(_MAPPER_DB.parent)
            except Exception:
                parent = None
            tmp_db_path = str(_MAPPER_DB) + ".tmp"
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
        conn = _get_mapper_conn(db_path=target_db_path)
        _ensure_mapper_schema(conn)
        cur = conn.cursor()

        cwe_count = 0
        if cwe_xml_path and os.path.exists(cwe_xml_path):
            try:
                tree = ET.parse(cwe_xml_path)
                root = tree.getroot()

                def _local_name(elem):
                    # Element tags may include namespace like '{uri}TagName'
                    tag = elem.tag
                    if isinstance(tag, str) and "}" in tag:
                        return tag.split("}", 1)[1]
                    return tag

                _ensure_cwe_extended_schema(conn)

                for weak in root.iter():
                    if _local_name(weak).lower() != "weakness":
                        continue

                    # Core attributes
                    wid = weak.attrib.get("ID") or weak.attrib.get("Id") or weak.attrib.get("id")
                    name = weak.attrib.get("Name") or weak.attrib.get("name")
                    abstraction = weak.attrib.get("Abstraction")
                    structure = weak.attrib.get("Structure")
                    status = weak.attrib.get("Status")

                    # Texts
                    description = None
                    extended_desc = None
                    for child in weak:
                        ln = _local_name(child).lower()
                        if ln == "description":
                            description = _xml_text(child)
                        elif ln == "extended_description":
                            extended_desc = _xml_text(child)

                    # Relationships (capture parent from first ChildOf)
                    parent = None
                    for rels in weak:
                        if _local_name(rels).lower() != "related_weaknesses":
                            continue
                        for rw in rels:
                            if _local_name(rw).lower() != "related_weakness":
                                continue
                            nature = rw.attrib.get("Nature")
                            rcwe = rw.attrib.get("CWE_ID")
                            view_id = rw.attrib.get("View_ID")
                            ordinal = rw.attrib.get("Ordinal")
                            if not parent and (nature or "").lower() == "childof" and rcwe:
                                parent = rcwe
                            cur.execute(
                                "INSERT INTO cwe_relationships (cwe_id, nature, related_cwe_id, view_id, ordinal) VALUES (?, ?, ?, ?, ?)",
                                (wid, nature, rcwe, view_id, ordinal),
                            )

                    # Platforms
                    for plats in weak:
                        if _local_name(plats).lower() != "applicable_platforms":
                            continue
                        for pe in plats:
                            ln = _local_name(pe).lower()
                            if ln in ("language", "technology"):
                                kind = "Language" if ln == "language" else "Technology"
                                klass = pe.attrib.get("Class")
                                prevalence = pe.attrib.get("Prevalence")
                                cur.execute(
                                    "INSERT INTO cwe_platforms (cwe_id, kind, class, prevalence) VALUES (?, ?, ?, ?)",
                                    (wid, kind, klass, prevalence),
                                )

                    # Modes of Introduction
                    for moi in weak:
                        if _local_name(moi).lower() != "modes_of_introduction":
                            continue
                        for intro in moi:
                            if _local_name(intro).lower() != "introduction":
                                continue
                            phase = None
                            for c2 in intro:
                                if _local_name(c2).lower() == "phase":
                                    phase = _xml_text(c2)
                            if wid and phase:
                                cur.execute(
                                    "INSERT INTO cwe_modes_of_introduction (cwe_id, phase) VALUES (?, ?)",
                                    (wid, phase),
                                )

                    # Likelihood
                    likelihood = None
                    for child in weak:
                        if _local_name(child).lower() == "likelihood_of_exploit":
                            likelihood = _xml_text(child)

                    # Consequences
                    for cc in weak:
                        if _local_name(cc).lower() != "common_consequences":
                            continue
                        for cons in cc:
                            if _local_name(cons).lower() != "consequence":
                                continue
                            scope = impact = note = None
                            for c2 in cons:
                                ln2 = _local_name(c2).lower()
                                if ln2 == "scope":
                                    scope = _xml_text(c2)
                                elif ln2 == "impact":
                                    impact = _xml_text(c2)
                                elif ln2 == "note":
                                    note = _xml_text(c2)
                            cur.execute(
                                "INSERT INTO cwe_consequences (cwe_id, scope, impact, note) VALUES (?, ?, ?, ?)",
                                (wid, scope, impact, note),
                            )

                    # Detection methods
                    for dm in weak:
                        if _local_name(dm).lower() != "detection_methods":
                            continue
                        for d in dm:
                            if _local_name(d).lower() != "detection_method":
                                continue
                            mid = d.attrib.get("Detection_Method_ID")
                            method = description_d = effectiveness = None
                            for c2 in d:
                                ln2 = _local_name(c2).lower()
                                if ln2 == "method":
                                    method = _xml_text(c2)
                                elif ln2 == "description":
                                    description_d = _xml_text(c2)
                                elif ln2 == "effectiveness":
                                    effectiveness = _xml_text(c2)
                            cur.execute(
                                "INSERT INTO cwe_detection_methods (cwe_id, method_id, method, description, effectiveness) VALUES (?, ?, ?, ?, ?)",
                                (wid, mid, method, description_d, effectiveness),
                            )

                    # Mitigations
                    for pm in weak:
                        if _local_name(pm).lower() != "potential_mitigations":
                            continue
                        for m in pm:
                            if _local_name(m).lower() != "mitigation":
                                continue
                            phase = desc_m = eff = eff_notes = None
                            for c2 in m:
                                ln2 = _local_name(c2).lower()
                                if ln2 == "phase":
                                    phase = _xml_text(c2)
                                elif ln2 == "description":
                                    desc_m = _xml_text(c2)
                                elif ln2 == "effectiveness":
                                    eff = _xml_text(c2)
                                elif ln2 == "effectiveness_notes":
                                    eff_notes = _xml_text(c2)
                            cur.execute(
                                "INSERT INTO cwe_mitigations (cwe_id, phase, description, effectiveness, effectiveness_notes) VALUES (?, ?, ?, ?, ?)",
                                (wid, phase, desc_m, eff, eff_notes),
                            )

                    # Demonstrative examples
                    for de in weak:
                        if _local_name(de).lower() != "demonstrative_examples":
                            continue
                        for ex in de:
                            if _local_name(ex).lower() != "demonstrative_example":
                                continue
                            intro_text = body_text = code_text = nature = language = None
                            for c2 in ex:
                                ln2 = _local_name(c2).lower()
                                if ln2 == "intro_text":
                                    intro_text = _xml_text(c2)
                                elif ln2 == "body_text":
                                    t = _xml_text(c2)
                                    body_text = (body_text + "\n" + t) if body_text else t
                                elif ln2 == "example_code":
                                    nature = c2.attrib.get("Nature")
                                    language = c2.attrib.get("Language")
                                    code_text = _xml_text(c2)
                            cur.execute(
                                "INSERT INTO cwe_examples (cwe_id, nature, language, intro_text, body_text, code_text) VALUES (?, ?, ?, ?, ?, ?)",
                                (wid, nature, language, intro_text, body_text, code_text),
                            )

                    # Observed examples
                    for oe in weak:
                        if _local_name(oe).lower() != "observed_examples":
                            continue
                        for ob in oe:
                            if _local_name(ob).lower() != "observed_example":
                                continue
                            ref = desc_o = link = None
                            for c2 in ob:
                                ln2 = _local_name(c2).lower()
                                if ln2 == "reference":
                                    ref = _xml_text(c2)
                                elif ln2 == "description":
                                    desc_o = _xml_text(c2)
                                elif ln2 == "link":
                                    link = _xml_text(c2)
                            cur.execute(
                                "INSERT INTO cwe_observed_examples (cwe_id, reference, description, link) VALUES (?, ?, ?, ?)",
                                (wid, ref, desc_o, link),
                            )

                    # References
                    for refs in weak:
                        if _local_name(refs).lower() != "references":
                            continue
                        for r in refs:
                            if _local_name(r).lower() != "reference":
                                continue
                            ext_id = r.attrib.get("External_Reference_ID")
                            if ext_id:
                                cur.execute(
                                    "INSERT INTO cwe_references (cwe_id, external_reference_id) VALUES (?, ?)",
                                    (wid, ext_id),
                                )

                    # Mapping notes
                    usage = rationale = comments = reasons = None
                    for mn in weak:
                        if _local_name(mn).lower() != "mapping_notes":
                            continue
                        for c2 in mn:
                            ln2 = _local_name(c2).lower()
                            if ln2 == "usage":
                                usage = _xml_text(c2)
                            elif ln2 == "rationale":
                                rationale = _xml_text(c2)
                            elif ln2 == "comments":
                                comments = _xml_text(c2)
                            elif ln2 == "reasons":
                                rs = []
                                for r3 in c2:
                                    if _local_name(r3).lower() == "reason":
                                        rs.append(r3.attrib.get("Type") or _xml_text(r3))
                                reasons = "; ".join([r for r in rs if r])
                        cur.execute(
                            "INSERT INTO cwe_mapping_notes (cwe_id, usage, rationale, comments, reasons) VALUES (?, ?, ?, ?, ?)",
                            (wid, usage, rationale, comments, reasons),
                        )

                    # Content history
                    for ch in weak:
                        if _local_name(ch).lower() != "content_history":
                            continue
                        for ev in ch:
                            evtype = _local_name(ev)
                            if evtype not in ("Submission", "Modification"):
                                continue
                            name_e = org_e = date_e = ver_e = rdate_e = comment_e = None
                            for c2 in ev:
                                ln2 = _local_name(c2)
                                text = _xml_text(c2)
                                if ln2 == "Submission_Name" or ln2 == "Modification_Name":
                                    name_e = text
                                elif ln2 == "Submission_Organization" or ln2 == "Modification_Organization":
                                    org_e = text
                                elif ln2 == "Submission_Date" or ln2 == "Modification_Date":
                                    date_e = text
                                elif ln2 == "Submission_Version":
                                    ver_e = text
                                elif ln2 == "Submission_ReleaseDate":
                                    rdate_e = text
                                elif ln2 == "Modification_Comment":
                                    comment_e = text
                            cur.execute(
                                "INSERT INTO cwe_content_history (cwe_id, event_type, name, organization, date, version, release_date, comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (wid, evtype, name_e, org_e, date_e, ver_e, rdate_e, comment_e),
                            )

                    if wid and name:
                        try:
                            cur.execute(
                                "INSERT OR REPLACE INTO cwes (id, name, description, parent) VALUES (?, ?, ?, ?)",
                                (wid, name, description or "", parent),
                            )
                            cur.execute(
                                "INSERT OR REPLACE INTO cwe_attributes (cwe_id, abstraction, structure, status, extended_description, likelihood) VALUES (?, ?, ?, ?, ?, ?)",
                                (wid, abstraction, structure, status, extended_desc or "", likelihood),
                            )
                            cwe_count += 1
                        except Exception as e:
                            _log(f"Failed to insert CWE {wid!r}: {e!r}")
                conn.commit()
            except Exception as e:
                _log(f"Failed to parse CWE XML: {e!r}")

        cis_count = 0
        if cis_csv_path and os.path.exists(cis_csv_path):
            try:
                # Ensure unified structured 'cis' table, then ingest via structured parser
                _ensure_cis_schema(conn)
                # Use the same parser as cve_ingest_cis_structured for a single pass
                with open(cis_csv_path, "r", encoding="utf-8", errors="replace") as fh:
                    r = csv.reader(fh)
                    header = None
                    for i, row in enumerate(r):
                        if i == 0:
                            header = [c.strip().lower() for c in row]
                            if not any("cis control" in h for h in header) or not any("title" in h for h in header):
                                break
                            continue
                        parsed = _parse_cis_csv_row(row)
                        if not parsed.get("control") and not parsed.get("title"):
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
            except Exception as e:
                _log(f"Failed to load CIS CSV: {e!r}")

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
                        _ingest_file_into_db(path, conn, cur)
                        ingested += 1
                        if ctx and ingested % 200 == 0:
                            try:
                                # Use the event loop captured in the outer async function
                                _asyncio.run_coroutine_threadsafe(
                                    ctx.report_progress(progress=min(1.0, ingested / 1000.0), total=1.0,
                                                        message=f"Ingested: {ingested}"), loop
                                )
                            except Exception:
                                pass
                    except Exception:
                        errors += 1
        else:
            _log("cve_build_index: skipping CVE ingestion (no source_dir provided or not found)")
        conn.commit()
        conn.close()

        # If we built into a temporary DB, atomically replace the live DB file.
        if reindex and tmp_db_path:
            try:
                live_path = str(_MAPPER_DB)
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
                _log(f"Failed to atomically replace DB: {e!r}")
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


@mcp.tool()
async def cve_ingest_file(file_path: str) -> dict:
    """Ingest a single CVE JSON file into the local index."""
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        # Basic validation to avoid machine-specific assumptions
        if not file_path or not os.path.isfile(file_path) or not file_path.lower().endswith(".json"):
            return {"ok": False, "error": f"file_path must be an existing .json file: {file_path}"}
        conn = _get_mapper_conn()
        _ensure_mapper_schema(conn)
        cur = conn.cursor()
        _ingest_file_into_db(file_path, conn, cur)
        conn.commit()
        cur.execute("SELECT COUNT(1) c FROM cves")
        total = cur.fetchone()["c"]
        conn.close()
        return {"ok": True, "ingested": 1, "total_cves": total}

    return await loop.run_in_executor(None, _worker)


@mcp.tool()
async def cve_search_cves(query: str, limit: int = 20) -> dict:
    """Basic text search across CVE title and description.

    Returns an object wrapper to avoid client list-flattening issues:
    {"count": n, "items": [{id,title,snippet}, ...]}
    """
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        q = f"%{query}%"
        # prefer exact id match first, and also allow id/title/description LIKE matches
        cur.execute(
            "SELECT id, title, description FROM cves WHERE id = ? OR id LIKE ? OR title LIKE ? OR description LIKE ? LIMIT ?",
            (query, q, q, q, limit),
        )
        rows = cur.fetchall()
        items = []
        for r in rows:
            snippet = (r["description"] or "")[:300]
            items.append({"id": r["id"], "title": r["title"], "snippet": snippet})
        conn.close()
        return {"count": len(items), "items": items}

    return await loop.run_in_executor(None, _worker)


@mcp.tool()
async def cve_map_cve_to_cwe(cve_id: str, top_n: int = 5) -> dict:
    """Map a CVE to candidate CWEs.

    Returns an object wrapper: {"count": n, "items": [{cwe_id, cwe_name, confidence, evidence}, ...]}
    cwe_id is normalized to "CWE-<num>" and cwe_name is looked up when possible.
    """
    loop = _asyncio.get_running_loop()
    def _worker() -> dict:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, title, description, json FROM cves WHERE id = ?", (cve_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return {"count": 0, "items": []}

        try:
            stored = json.loads(row["json"])
        except Exception:
            stored = None

        # Collect explicit CWE mentions with JSON paths/evidence
        explicit: dict[str, list[dict]] = {}

        def _scan(obj, path: list):
            # path is list of keys/indices
            if isinstance(obj, dict):
                # check keys that commonly hold CWE ids
                for k, v in obj.items():
                    lk = k.lower()
                    if lk in ("cweid", "cwe_id", "cwe-id", "cwe"):
                        # normalize numeric or string CWE values
                        if isinstance(v, (int,)):
                            cid = f"CWE-{v}"
                        elif isinstance(v, str):
                            # numeric-only -> CWE-<n>
                            if v.isdigit():
                                cid = f"CWE-{v}"
                            else:
                                # try to find CWE-123 patterns inside
                                m = re.search(r"CWE[-\s]?(\d+)", v, flags=re.I)
                                cid = f"CWE-{m.group(1)}" if m else None
                        else:
                            cid = None
                        if cid:
                            explicit.setdefault(cid, []).append({"path": ".".join(map(str, path + [k])), "snippet": str(v)})
                    # recurse only into dicts/lists to avoid duplicating primitive string matches
                    if isinstance(v, (dict, list)):
                        _scan(v, path + [k])
            elif isinstance(obj, list):
                for i, e in enumerate(obj):
                    _scan(e, path + [i])
            elif isinstance(obj, str):
                # find textual CWE mentions like 'CWE-319' or 'CWE 319'
                for m in re.findall(r"CWE[-\s]?(\d+)", obj, flags=re.I):
                    cid = f"CWE-{m}"
                    explicit.setdefault(cid, []).append({"path": ".".join(map(str, path)), "snippet": obj[:200]})

        if stored is not None:
            try:
                _scan(stored, [])
            except Exception:
                # defensive: if scan fails keep going to fallback
                pass

        # If we found explicit CWEs, return them with evidence
        def _normalize_cwe_id(cid: str) -> tuple[str, str]:
            # returns (pretty, numeric)
            m = re.search(r"(\d+)", cid or "")
            num = m.group(1) if m else (cid if cid and cid.isdigit() else "")
            pretty = f"CWE-{num}" if num else (cid or "")
            return pretty, num

        # helper to enrich with CWE name
        def _enrich_items(items_in: list[dict]) -> list[dict]:
            enriched: list[dict] = []
            for it in items_in:
                cid = it.get("cwe_id")
                pretty, num = _normalize_cwe_id(str(cid) if cid is not None else "")
                name = None
                try:
                    if num:
                        cur.execute("SELECT name FROM cwes WHERE id = ?", (num,))
                        rname = cur.fetchone()
                        name = rname["name"] if rname else None
                except Exception:
                    name = None
                enriched.append({
                    "cwe_id": pretty,
                    "cwe_name": name,
                    "confidence": it.get("confidence", 0.0),
                    "evidence": it.get("evidence"),
                })
            return enriched

        if explicit:
            out_list = []
            for cid, evidences in explicit.items():
                out_list.append({"cwe_id": cid, "confidence": 1.0, "evidence": evidences})
            items = _enrich_items(out_list)
            conn.close()
            return {"count": len(items), "items": items}

        # Fallback: token-overlap scoring, with vendor/product token boosting
        base_text = (row["title"] or "") + " " + (row["description"] or "")
        tokens = _tokenize(base_text)

        # collect vendor/product strings from the stored JSON to boost scoring
        vp_tokens: list[str] = []

        def _collect_vp(obj):
            if isinstance(obj, dict):
                # common affected structure: containers -> cna -> affected -> [{"vendor":..., "product":...}]
                if "vendor" in obj or "product" in obj:
                    v = obj.get("vendor")
                    p = obj.get("product")
                    if isinstance(v, str):
                        vp_tokens.extend(_tokenize(v))
                    if isinstance(p, str):
                        vp_tokens.extend(_tokenize(p))
                for v in obj.values():
                    _collect_vp(v)
            elif isinstance(obj, list):
                for e in obj:
                    _collect_vp(e)

        if stored is not None:
            try:
                _collect_vp(stored)
            except Exception:
                pass

        # Boost vendor/product tokens by duplicating them (simple weighting)
        if vp_tokens:
            tokens_for_scoring = tokens + vp_tokens * 2
        else:
            tokens_for_scoring = tokens

        candidates: List[tuple[str, float]] = []
        cur.execute("SELECT id, name, description FROM cwes")
        for c in cur.fetchall():
            cwe_tokens = _tokenize((c["name"] or "") + " " + (c["description"] or ""))
            score = _score_overlap(tokens_for_scoring, cwe_tokens)
            if score > 0.0:
                candidates.append((c["id"], score))

        candidates.sort(key=lambda x: x[1], reverse=True)
        out = []
        max_score = candidates[0][1] if candidates else 0.0
        for cwe_id_val, score in candidates[:top_n]:
            norm = (score / max_score) if max_score > 0 else 0.0
            evidence = {"method": "keyword_overlap", "score": round(float(score), 3)}
            out.append({"cwe_id": cwe_id_val, "confidence": round(float(norm), 3), "evidence": evidence})

        items = _enrich_items(out)
        conn.close()
        return {"count": len(items), "items": items}

    return await loop.run_in_executor(None, _worker)


  # (Removed old raw-only implementation; unified suggester wrapper retained later.)


@mcp.tool()
async def cve_environment_diagnostics() -> dict:
    """Return small diagnostics for the mapping environment: DB path, python/sqlite versions."""
    return {
        "db_path": str(_MAPPER_DB),
        "db_exists": _MAPPER_DB.exists(),
        "db_from_env": bool(_ENV_DB),
        "python_version": _sys.version,
        "sqlite_version": sqlite3.sqlite_version,
        "note": "No default external source root is used; supply explicit source_dir to cve_build_index",
    }



# PCAP/pyshark legacy tooling references removed – keeping file lean for mapper testing.

    # -----------------------
    # In-server self-test tool
    # -----------------------
@mcp.tool()
async def cve_self_test() -> dict:
    """Run a quick in-server self-test (sample, mapping, id-search, DB sanity).

    This runs inside the MCP server process so callers (like Ollama) can
    validate tool behavior and the exact environment the server uses.
    Returns a dict containing the raw outputs and a boolean `ok` flag.
    """
    out: dict = {"ok": False}
    try:
        # sample
        out["sample"] = await cve_get_cve_sample(limit=5)

        # mapping for a known sample CVE (if present)
        try:
            out["mapping"] = await cve_map_cve_to_cwe(cve_id="CVE-2025-62643", top_n=10)
        except Exception as e:
            out["mapping_error"] = repr(e)

        # search by id
        try:
            out["search"] = await cve_search_cves(query="CVE-2025-62643", limit=5)
        except Exception as e:
            out["search_error"] = repr(e)

        # environment diagnostics
        try:
            out["env"] = await cve_environment_diagnostics()
        except Exception as e:
            out["env_error"] = repr(e)

        # quick DB sanity: count cves
        try:
            conn = _get_mapper_conn()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(1) FROM cves")
            out["cves_count"] = cur.fetchone()[0]
            conn.close()
        except Exception as e:
            out["db_count_error"] = repr(e)

        out["ok"] = True
    except Exception as e:
        out["error"] = repr(e)
    return out


@mcp.tool()
async def cve_index_stats() -> dict:
    """Return counts for mapper DB tables (cves, cwes, cis unified structured, extended CWE presence)."""
    try:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(1) FROM cves"); cves = int(cur.fetchone()[0])
        except Exception:
            cves = None
        try:
            cur.execute("SELECT COUNT(1) FROM cwes"); cwes = int(cur.fetchone()[0])
        except Exception:
            cwes = None
        try:
            cur.execute("SELECT COUNT(1) FROM cis"); cis = int(cur.fetchone()[0])
        except Exception:
            cis = None
        # extended CWE indicator
        extended = False
        try:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cwe_attributes'")
            extended = bool(cur.fetchone())
        except Exception:
            extended = False
        conn.close()
        return {"cves": cves, "cwes": cwes, "cis": cis, "cwe_extended": extended}
    except Exception as e:
        return {"error": repr(e)}


@mcp.tool()
async def cve_get_cve_sample(limit: int = 5) -> dict:
    """Return up to `limit` CVE rows as {count, items:[{id,title,snippet}, ...]}.

    Uses inline LIMIT to avoid any odd client parameter-binding behavior.
    """
    if limit <= 0:
        limit = 5
    try:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        lim = int(limit)
        cur.execute(f"SELECT id, title, description FROM cves LIMIT {lim}")
        rows = cur.fetchall()
        items = []
        for r in rows:
            items.append({"id": r[0], "title": r[1], "snippet": (r[2] or "")[:400]})
        try:
            conn.close()
        except Exception:
            pass
        return {"count": len(items), "items": items}
    except Exception as e:
        return {"error": repr(e), "count": 0, "items": []}


# ---------------- Additional tools: CIS-only ingest & improved sample wrapper ---------------

@mcp.tool()
async def cve_ingest_cis(cis_csv_path: str, replace: bool = False) -> dict:
    """Ingest CIS CSV into unified structured 'cis' table.

    If replace=True, clears existing structured rows first.
    Returns: {ok, inserted, total_cis, skipped, errors|error}
    """
    if not cis_csv_path or not os.path.exists(cis_csv_path):
        return {"ok": False, "error": f"cis_csv_path not found: {cis_csv_path}"}
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        conn = _get_mapper_conn()
        _ensure_mapper_schema(conn)
        _ensure_cis_schema(conn)
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
                        parsed = _parse_cis_csv_row(row)
                        if not parsed.get("control") and not parsed.get("title"):
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


@mcp.tool()
async def cve_ingest_cwe_xml(cwe_xml_path: str, replace: bool = True) -> dict:
    """Ingest CWE XML (v4.18) into the extended CWE tables.

    If replace=True, clears existing CWE tables before ingesting.
    Returns: {ok, inserted, total_cwes, error?}
    """
    if not cwe_xml_path or not os.path.exists(cwe_xml_path):
        return {"ok": False, "error": f"cwe_xml_path not found: {cwe_xml_path}"}
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        conn = _get_mapper_conn()
        _ensure_mapper_schema(conn)
        _ensure_cwe_extended_schema(conn)
        cur = conn.cursor()
        if replace:
            # Clear all related tables for a clean ingest
            for t in (
                "cwes",
                "cwe_attributes",
                "cwe_relationships",
                "cwe_platforms",
                "cwe_modes_of_introduction",
                "cwe_consequences",
                "cwe_detection_methods",
                "cwe_mitigations",
                "cwe_examples",
                "cwe_observed_examples",
                "cwe_references",
                "cwe_mapping_notes",
                "cwe_content_history",
            ):
                try:
                    cur.execute(f"DELETE FROM {t}")
                except Exception:
                    pass
            conn.commit()
        try:
            tree = ET.parse(cwe_xml_path)
            root = tree.getroot()

            def _local_name(elem):
                tag = elem.tag
                if isinstance(tag, str) and "}" in tag:
                    return tag.split("}", 1)[1]
                return tag

            cwe_count = 0
            for weak in root.iter():
                if _local_name(weak).lower() != "weakness":
                    continue

                wid = weak.attrib.get("ID") or weak.attrib.get("Id") or weak.attrib.get("id")
                name = weak.attrib.get("Name") or weak.attrib.get("name")
                abstraction = weak.attrib.get("Abstraction")
                structure = weak.attrib.get("Structure")
                status = weak.attrib.get("Status")

                description = None
                extended_desc = None
                for child in weak:
                    ln = _local_name(child).lower()
                    if ln == "description":
                        description = _xml_text(child)
                    elif ln == "extended_description":
                        extended_desc = _xml_text(child)

                parent = None
                for rels in weak:
                    if _local_name(rels).lower() != "related_weaknesses":
                        continue
                    for rw in rels:
                        if _local_name(rw).lower() != "related_weakness":
                            continue
                        nature = rw.attrib.get("Nature")
                        rcwe = rw.attrib.get("CWE_ID")
                        view_id = rw.attrib.get("View_ID")
                        ordinal = rw.attrib.get("Ordinal")
                        if not parent and (nature or "").lower() == "childof" and rcwe:
                            parent = rcwe
                        cur.execute(
                            "INSERT INTO cwe_relationships (cwe_id, nature, related_cwe_id, view_id, ordinal) VALUES (?, ?, ?, ?, ?)",
                            (wid, nature, rcwe, view_id, ordinal),
                        )

                for plats in weak:
                    if _local_name(plats).lower() != "applicable_platforms":
                        continue
                    for pe in plats:
                        ln = _local_name(pe).lower()
                        if ln in ("language", "technology"):
                            kind = "Language" if ln == "language" else "Technology"
                            klass = pe.attrib.get("Class")
                            prevalence = pe.attrib.get("Prevalence")
                            cur.execute(
                                "INSERT INTO cwe_platforms (cwe_id, kind, class, prevalence) VALUES (?, ?, ?, ?)",
                                (wid, kind, klass, prevalence),
                            )

                for moi in weak:
                    if _local_name(moi).lower() != "modes_of_introduction":
                        continue
                    for intro in moi:
                        if _local_name(intro).lower() != "introduction":
                            continue
                        phase = None
                        for c2 in intro:
                            if _local_name(c2).lower() == "phase":
                                phase = _xml_text(c2)
                        if wid and phase:
                            cur.execute(
                                "INSERT INTO cwe_modes_of_introduction (cwe_id, phase) VALUES (?, ?)",
                                (wid, phase),
                            )

                likelihood = None
                for child in weak:
                    if _local_name(child).lower() == "likelihood_of_exploit":
                        likelihood = _xml_text(child)

                for cc in weak:
                    if _local_name(cc).lower() != "common_consequences":
                        continue
                    for cons in cc:
                        if _local_name(cons).lower() != "consequence":
                            continue
                        scope = impact = note = None
                        for c2 in cons:
                            ln2 = _local_name(c2).lower()
                            if ln2 == "scope":
                                scope = _xml_text(c2)
                            elif ln2 == "impact":
                                impact = _xml_text(c2)
                            elif ln2 == "note":
                                note = _xml_text(c2)
                        cur.execute(
                            "INSERT INTO cwe_consequences (cwe_id, scope, impact, note) VALUES (?, ?, ?, ?)",
                            (wid, scope, impact, note),
                        )

                for dm in weak:
                    if _local_name(dm).lower() != "detection_methods":
                        continue
                    for d in dm:
                        if _local_name(d).lower() != "detection_method":
                            continue
                        mid = d.attrib.get("Detection_Method_ID")
                        method = description_d = effectiveness = None
                        for c2 in d:
                            ln2 = _local_name(c2).lower()
                            if ln2 == "method":
                                method = _xml_text(c2)
                            elif ln2 == "description":
                                description_d = _xml_text(c2)
                            elif ln2 == "effectiveness":
                                effectiveness = _xml_text(c2)
                        cur.execute(
                            "INSERT INTO cwe_detection_methods (cwe_id, method_id, method, description, effectiveness) VALUES (?, ?, ?, ?, ?)",
                            (wid, mid, method, description_d, effectiveness),
                        )

                for pm in weak:
                    if _local_name(pm).lower() != "potential_mitigations":
                        continue
                    for m in pm:
                        if _local_name(m).lower() != "mitigation":
                            continue
                        phase = desc_m = eff = eff_notes = None
                        for c2 in m:
                            ln2 = _local_name(c2).lower()
                            if ln2 == "phase":
                                phase = _xml_text(c2)
                            elif ln2 == "description":
                                desc_m = _xml_text(c2)
                            elif ln2 == "effectiveness":
                                eff = _xml_text(c2)
                            elif ln2 == "effectiveness_notes":
                                eff_notes = _xml_text(c2)
                        cur.execute(
                            "INSERT INTO cwe_mitigations (cwe_id, phase, description, effectiveness, effectiveness_notes) VALUES (?, ?, ?, ?, ?)",
                            (wid, phase, desc_m, eff, eff_notes),
                        )

                for de in weak:
                    if _local_name(de).lower() != "demonstrative_examples":
                        continue
                    for ex in de:
                        if _local_name(ex).lower() != "demonstrative_example":
                            continue
                        intro_text = body_text = code_text = nature = language = None
                        for c2 in ex:
                            ln2 = _local_name(c2).lower()
                            if ln2 == "intro_text":
                                intro_text = _xml_text(c2)
                            elif ln2 == "body_text":
                                t = _xml_text(c2)
                                body_text = (body_text + "\n" + t) if body_text else t
                            elif ln2 == "example_code":
                                nature = c2.attrib.get("Nature")
                                language = c2.attrib.get("Language")
                                code_text = _xml_text(c2)
                        cur.execute(
                            "INSERT INTO cwe_examples (cwe_id, nature, language, intro_text, body_text, code_text) VALUES (?, ?, ?, ?, ?, ?)",
                            (wid, nature, language, intro_text, body_text, code_text),
                        )

                for oe in weak:
                    if _local_name(oe).lower() != "observed_examples":
                        continue
                    for ob in oe:
                        if _local_name(ob).lower() != "observed_example":
                            continue
                        ref = desc_o = link = None
                        for c2 in ob:
                            ln2 = _local_name(c2).lower()
                            if ln2 == "reference":
                                ref = _xml_text(c2)
                            elif ln2 == "description":
                                desc_o = _xml_text(c2)
                            elif ln2 == "link":
                                link = _xml_text(c2)
                        cur.execute(
                            "INSERT INTO cwe_observed_examples (cwe_id, reference, description, link) VALUES (?, ?, ?, ?)",
                            (wid, ref, desc_o, link),
                        )

                for refs in weak:
                    if _local_name(refs).lower() != "references":
                        continue
                    for r in refs:
                        if _local_name(r).lower() != "reference":
                            continue
                        ext_id = r.attrib.get("External_Reference_ID")
                        if ext_id:
                            cur.execute(
                                "INSERT INTO cwe_references (cwe_id, external_reference_id) VALUES (?, ?)",
                                (wid, ext_id),
                            )

                usage = rationale = comments = reasons = None
                for mn in weak:
                    if _local_name(mn).lower() != "mapping_notes":
                        continue
                    for c2 in mn:
                        ln2 = _local_name(c2).lower()
                        if ln2 == "usage":
                            usage = _xml_text(c2)
                        elif ln2 == "rationale":
                            rationale = _xml_text(c2)
                        elif ln2 == "comments":
                            comments = _xml_text(c2)
                        elif ln2 == "reasons":
                            rs = []
                            for r3 in c2:
                                if _local_name(r3).lower() == "reason":
                                    rs.append(r3.attrib.get("Type") or _xml_text(r3))
                            reasons = "; ".join([r for r in rs if r])
                    cur.execute(
                        "INSERT INTO cwe_mapping_notes (cwe_id, usage, rationale, comments, reasons) VALUES (?, ?, ?, ?, ?)",
                        (wid, usage, rationale, comments, reasons),
                    )

                for ch in weak:
                    if _local_name(ch).lower() != "content_history":
                        continue
                    for ev in ch:
                        evtype = _local_name(ev)
                        if evtype not in ("Submission", "Modification"):
                            continue
                        name_e = org_e = date_e = ver_e = rdate_e = comment_e = None
                        for c2 in ev:
                            ln2 = _local_name(c2)
                            text = _xml_text(c2)
                            if ln2 == "Submission_Name" or ln2 == "Modification_Name":
                                name_e = text
                            elif ln2 == "Submission_Organization" or ln2 == "Modification_Organization":
                                org_e = text
                            elif ln2 == "Submission_Date" or ln2 == "Modification_Date":
                                date_e = text
                            elif ln2 == "Submission_Version":
                                ver_e = text
                            elif ln2 == "Submission_ReleaseDate":
                                rdate_e = text
                            elif ln2 == "Modification_Comment":
                                comment_e = text
                        cur.execute(
                            "INSERT INTO cwe_content_history (cwe_id, event_type, name, organization, date, version, release_date, comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (wid, evtype, name_e, org_e, date_e, ver_e, rdate_e, comment_e),
                        )

                if wid and name:
                    try:
                        cur.execute(
                            "INSERT OR REPLACE INTO cwes (id, name, description, parent) VALUES (?, ?, ?, ?)",
                            (wid, name, description or "", parent),
                        )
                        cur.execute(
                            "INSERT OR REPLACE INTO cwe_attributes (cwe_id, abstraction, structure, status, extended_description, likelihood) VALUES (?, ?, ?, ?, ?, ?)",
                            (wid, abstraction, structure, status, extended_desc or "", likelihood),
                        )
                        cwe_count += 1
                    except Exception:
                        pass
            conn.commit()
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


@mcp.tool()
async def cve_reset_db() -> dict:
    """Delete the local SQLite database file for a clean re-ingestion."""
    try:
        db_path = str(_MAPPER_DB)
        if os.path.exists(db_path):
            os.remove(db_path)
            return {"ok": True, "deleted": True, "path": db_path}
        return {"ok": True, "deleted": False, "path": db_path}
    except Exception as e:
        return {"ok": False, "error": repr(e), "path": str(_MAPPER_DB)}


@mcp.tool()
async def cve_get_cve_sample_v2(limit: int = 5) -> dict:
    """Return up to `limit` CVE rows as an object {count: n, items: [...]}.

    Uses inline LIMIT (no parameter binding) to avoid client/bridge issues where
    only the first row was surfaced. Each item contains id, title, snippet.
    """
    if limit <= 0:
        limit = 5
    try:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        lim = int(limit)
        # Inline LIMIT to bypass parameter binding anomalies some bridges exhibit
        cur.execute(f"SELECT id, title, description FROM cves LIMIT {lim}")
        rows = cur.fetchall()
        items: list[dict] = []
        for r in rows:
            items.append({
                "id": r[0],
                "title": r[1],
                "snippet": (r[2] or "")[:400]
            })
        try:
            conn.close()
        except Exception:
            pass
        return {"count": len(items), "items": items}
    except Exception as e:
        return {"error": repr(e), "count": 0, "items": []}

# ---------------- Unified CIS structured helpers ----------------


def _normalize_cell(val: Optional[str]) -> str:
    if not val:
        return ""
    v = val.strip().strip('"').strip("'")
    v = unicodedata.normalize("NFKC", v)
    return v


def _flag(val: Optional[str]) -> int:
    return 1 if (val or "").strip().lower() == "x" else 0


def _parse_cis_csv_row(row: List[str]) -> Dict[str, Any]:
    # Expected header columns (9): CIS Control, CIS Safeguard, Asset Class, Security Function, Title, Description, IG1, IG2, IG3
    cells = [_normalize_cell(c) for c in row]
    while len(cells) < 9:
        cells.append("")
    control, safeguard, asset_class, sec_fn, title, desc, ig1_raw, ig2_raw, ig3_raw = cells[:9]
    control = control.replace("\u00a0", "").strip()
    safeguard = safeguard.replace("\u00a0", "").strip()
    return {
        "control": control or None,
        "safeguard": safeguard or None,
        "asset_class": asset_class or None,
        "security_function": sec_fn or None,
        "title": title or None,
        "description": desc or None,
        "ig1": _flag(ig1_raw),
        "ig2": _flag(ig2_raw),
        "ig3": _flag(ig3_raw),
        "is_summary": (safeguard == "" or safeguard is None),
    }


# (Structured ingestion now handled by cve_ingest_cis)


# (Legacy migration function removed; unified schema handles any needed transition automatically)


# Removed deprecated stub definition of cve_suggest_cis; only enhanced version retained below.


@mcp.tool()
async def cve_validate_cwe_xml(cwe_xml_path: str) -> dict:
    """Quickly validate a CWE XML file and report a count of weakness entries."""
    if not cwe_xml_path or not os.path.exists(cwe_xml_path):
        return {"ok": False, "error": "Path not found"}
    try:
        tree = ET.parse(cwe_xml_path)
        root = tree.getroot()
        count = sum(1 for _ in root.iter())
        return {"ok": True, "elements": count}
    except Exception as e:
        return {"ok": False, "error": repr(e)}


@mcp.tool()
async def cve_environment_summary() -> str:
    """Return a one-line human-friendly summary of the mapper environment.

    This is meant for quick assistant responses so the model receives a short
    text summary instead of nested JSON.
    """
    try:
        diag = await cve_environment_diagnostics()
        path = diag.get("db_path", str(_MAPPER_DB))
        exists = diag.get("db_exists", False)
        src_note = "DB from env" if diag.get("db_from_env") else "DB local"
        pyver = (diag.get("python_version") or "").split()[0]
        sqlite_ver = diag.get("sqlite_version", sqlite3.sqlite_version)
        return f"DB: {path} (exists={exists}, {src_note}); Python={pyver}; SQLite={sqlite_ver}"
    except Exception:
        return f"DB: {str(_MAPPER_DB)} (exists={_MAPPER_DB.exists()}); Python={_sys.version.split()[0]}; SQLite={sqlite3.sqlite_version}"


@mcp.tool()
async def cve_index_summary() -> str:
    """Return a one-line summary reflecting unified CIS and extended CWE presence."""
    try:
        s = await cve_index_stats()
        if not s or s.get("cves") is None:
            return "Index: unavailable"
        ext = " +extendedCWE" if s.get("cwe_extended") else ""
        return f"Index: {s['cves']} CVEs, {s['cwes']} CWEs, {s['cis']} CIS{ext}"
    except Exception:
        return "Index: error while fetching stats"


@mcp.tool()
async def cve_get_cwe_details(cwe_id: str) -> dict:
    """Return a detailed view of a CWE (aggregates extended tables)."""
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        m = re.search(r"(\d+)", cwe_id or "")
        cid = m.group(1) if m else cwe_id
        out: Dict[str, Any] = {"cwe_id": f"CWE-{cid}" if isinstance(cid, str) and cid and str(cid).isdigit() else str(cwe_id)}
        try:
            cur.execute("SELECT id, name, description, parent FROM cwes WHERE id = ?", (cid,))
            r = cur.fetchone()
            if not r:
                conn.close()
                return {"ok": False, "error": "CWE not found", "cwe_id": out["cwe_id"]}
            out.update({"id": r["id"], "name": r["name"], "description": r["description"], "parent": r["parent"]})
            # attrs
            try:
                cur.execute("SELECT abstraction, structure, status, extended_description, likelihood FROM cwe_attributes WHERE cwe_id = ?", (cid,))
                a = cur.fetchone()
                if a:
                    out["attributes"] = {
                        "abstraction": a["abstraction"],
                        "structure": a["structure"],
                        "status": a["status"],
                        "extended_description": a["extended_description"],
                        "likelihood": a["likelihood"],
                    }
            except Exception:
                pass
            # simple collectors
            def fetch_list(sql: str, params=()):
                try:
                    cur.execute(sql, params)
                    cols = [c[0] for c in cur.description]
                    return [dict(zip(cols, row)) for row in cur.fetchall()]
                except Exception:
                    return []
            out["relationships"] = fetch_list("SELECT nature, related_cwe_id, view_id, ordinal FROM cwe_relationships WHERE cwe_id = ?", (cid,))
            out["platforms"] = fetch_list("SELECT kind, class, prevalence FROM cwe_platforms WHERE cwe_id = ?", (cid,))
            out["modes_of_introduction"] = fetch_list("SELECT phase FROM cwe_modes_of_introduction WHERE cwe_id = ?", (cid,))
            out["consequences"] = fetch_list("SELECT scope, impact, note FROM cwe_consequences WHERE cwe_id = ?", (cid,))
            out["detection_methods"] = fetch_list("SELECT method_id, method, description, effectiveness FROM cwe_detection_methods WHERE cwe_id = ?", (cid,))
            out["mitigations"] = fetch_list("SELECT phase, description, effectiveness, effectiveness_notes FROM cwe_mitigations WHERE cwe_id = ?", (cid,))
            out["examples"] = fetch_list("SELECT nature, language, intro_text, body_text, code_text FROM cwe_examples WHERE cwe_id = ?", (cid,))
            out["observed_examples"] = fetch_list("SELECT reference, description, link FROM cwe_observed_examples WHERE cwe_id = ?", (cid,))
            out["references"] = fetch_list("SELECT external_reference_id FROM cwe_references WHERE cwe_id = ?", (cid,))
            out["mapping_notes"] = fetch_list("SELECT usage, rationale, comments, reasons FROM cwe_mapping_notes WHERE cwe_id = ?", (cid,))
            out["content_history"] = fetch_list("SELECT event_type, name, organization, date, version, release_date, comment FROM cwe_content_history WHERE cwe_id = ?", (cid,))
            conn.close()
            out["ok"] = True
            return out
        except Exception as e:
            try:
                conn.close()
            except Exception:
                pass
            return {"ok": False, "error": repr(e), "cwe_id": out.get("cwe_id", str(cwe_id))}

    return await loop.run_in_executor(None, _worker)


@mcp.tool()
async def cve_suggest_cis(
    cwe_id: str,
    top_n: int = 10,
    prefer_functions: str = "Protect,Detect",
    prefer_asset_classes: str = "",
) -> dict:
    """Suggest CIS safeguards for a CWE using structured CIS data when available.

    Enhancements vs prior version:
      - IDF-weighted Jaccard on structured composite token sets (title *3, desc *2, fn, asset_class)
      - Dynamic query token filtering (drops tokens appearing in >=25% of CIS rows)
      - Stronger phrase boosts for format-string patterns (1.50x)
      - Title-match bonus (1.08x) when any matched token occurs in title
      - Optional boosts: preferred security functions (1.15x), asset classes (1.20x)
      - Code-centric CWE detection: boosts Control 16 (Application Software Security) by 1.15x
    """
    loop = _asyncio.get_running_loop()
    pf_set = {p.strip().lower() for p in (prefer_functions or "").split(",") if p.strip()}
    pa_set = {p.strip().lower() for p in (prefer_asset_classes or "").split(",") if p.strip()}

    def _worker() -> dict:
        import math
        conn = _get_mapper_conn()
        cur = conn.cursor()
        m = re.search(r"(\d+)", cwe_id or "")
        cwe_num = m.group(1) if m else None
        cwe_name = None
        cwe_desc = None
        if cwe_num:
            try:
                cur.execute("SELECT name, description FROM cwes WHERE id = ?", (cwe_num,))
                rr = cur.fetchone()
                if rr:
                    cwe_name, cwe_desc = rr["name"], rr["description"]
            except Exception:
                pass

        # Build query tokens & enrich for certain CWE patterns
        raw_q_tokens: List[str] = []
        for p in [cwe_id, cwe_num, cwe_name, cwe_desc]:
            if p:
                raw_q_tokens.extend(_tokenize(p))
        ln = (cwe_name or "").lower()
        ld = (cwe_desc or "").lower()
        if "format string" in ln or "format string" in ld:
            raw_q_tokens.extend(_tokenize("format string printf specifier uncontrolled format vprintf snprintf input validation static analysis code review secure coding application security"))
        if ("hard-coded" in ln or "hardcoded" in ln or "hard-coded" in ld or "hardcoded" in ld):
            raw_q_tokens.extend(_tokenize("hardcoded credential password secret application security code review"))
        q_tokens = _filter_tokens(raw_q_tokens)
        if not q_tokens:
            conn.close()
            return {"query": {"cwe_id": cwe_id, "cwe_numeric": cwe_num, "cwe_name": cwe_name}, "count": 0, "items": []}

        # Code-centric heuristic (format/injection/buffer/etc.)
        codey = any(k in ln or k in ld for k in [
            "format string","buffer","overflow","underflow","injection","xss","sql","memory","validation","sanitize","serialization","deserialization","type confusion"
        ])

        # Ensure unified CIS schema presence (safe no-op if already)
        try:
            _ensure_cis_schema(conn)
        except Exception:
            pass

        items: List[Dict[str, Any]] = []
        try:
            cur.execute("SELECT control, safeguard, asset_class, security_function, title, description, ig1, ig2, ig3 FROM cis")
            rows = cur.fetchall()
            if not rows:
                conn.close()
                return {"query": {"cwe_id": cwe_id, "cwe_numeric": cwe_num, "cwe_name": cwe_name}, "count": 0, "items": []}

            # Build document frequency over composite tokens
            df: Counter[str] = Counter()
            composites: List[Dict[str, Any]] = []
            for r in rows:
                title_tokens = _filter_tokens(_tokenize(r[4] or ""))
                desc_tokens  = _filter_tokens(_tokenize(r[5] or ""))
                fn_tokens    = _filter_tokens(_tokenize(r[3] or ""))
                ac_tokens    = _filter_tokens(_tokenize(r[2] or ""))
                comp_set = set(title_tokens) | set(desc_tokens) | set(fn_tokens) | set(ac_tokens)
                if not comp_set:
                    continue
                df.update(comp_set)
                composites.append({
                    "control": r[0], "safeguard": r[1], "asset_class": r[2], "functions": r[3],
                    "title": r[4], "description": r[5], "title_set": set(title_tokens),
                    "comp_set": comp_set, "ig": {"ig1": r[6], "ig2": r[7], "ig3": r[8]}
                })
            N = max(1, len(composites))
            idf = {t: (math.log((N + 1) / (df_t + 1)) + 1.0) for t, df_t in df.items()}

            # Dynamic query token filtering (remove ubiquitous tokens)
            q_tokens2 = [t for t in q_tokens if df.get(t, 0) / N < 0.25]
            if not q_tokens2:
                q_tokens2 = q_tokens
            qset = set(q_tokens2)

            def weighted_jaccard(qs: set[str], ds: set[str]) -> float:
                if not qs or not ds:
                    return 0.0
                inter = qs & ds
                if not inter:
                    return 0.0
                union = qs | ds
                num = sum(idf.get(t, 1.0) for t in inter)
                den = sum(idf.get(t, 1.0) for t in union)
                if den <= 0:
                    return 0.0
                return num / den

            scored: List[Tuple[str, str, str, float, List[str], str, int, int, int]] = []
            for c in composites:
                base_score = weighted_jaccard(qset, c["comp_set"])
                if base_score <= 0:
                    continue
                text_lc = f"{(c['title'] or '').lower()} {(c['description'] or '').lower()}"
                if ("format string" in text_lc) or ("printf" in text_lc) or ("format specifier" in text_lc):
                    base_score *= 1.50
                matched_set = qset & c["comp_set"]
                if matched_set and any(t in c["title_set"] for t in matched_set):
                    base_score *= 1.08
                fn_lower = (c["functions"] or "").lower().strip()
                if fn_lower and fn_lower in pf_set:
                    base_score *= 1.15
                ac_lower = (c["asset_class"] or "").lower().strip()
                if ac_lower and ac_lower in pa_set:
                    base_score *= 1.20
                if codey and (c["control"] or "").strip() == "16":
                    base_score *= 1.15
                matched = sorted(list(matched_set))[:12]
                scored.append((c["control"], c["safeguard"], c["title"], float(base_score), matched, c["functions"], c["ig"]["ig1"], c["ig"]["ig2"], c["ig"]["ig3"]))
            scored.sort(key=lambda x: x[3], reverse=True)
            for s in scored[: max(1, int(top_n))]:
                items.append({
                    "control": s[0], "safeguard": s[1], "title": s[2], "score": round(s[3], 3),
                    "matched": s[4], "functions": s[5], "ig": {"ig1": s[6], "ig2": s[7], "ig3": s[8]},
                })
        except Exception:
            pass
        conn.close()
        return {"query": {"cwe_id": cwe_id, "cwe_numeric": cwe_num, "cwe_name": cwe_name}, "count": len(items), "items": items}

    return await loop.run_in_executor(None, _worker)

# Legacy wrapper retained for backward compatibility; delegates to new structured-aware tool.
@mcp.tool()
async def cve_suggest_cis_for_cwe(cwe_id: str, top_n: int = 10) -> dict:
    return await cve_suggest_cis(cwe_id=cwe_id, top_n=top_n)
@mcp.tool()
async def cve_debug_dry_run_dir(source_dir: str, max_files: int = 200, sample_skips: int = 10) -> dict:
    """Dry-run ingestion across a directory tree without writing to DB.

    Scans up to `max_files` JSON files and reports counts of items examined,
    how many had an extractable CVE id (would_insert), and a small sample of
    skipped item keys for debugging.
    """
    loop = _asyncio.get_running_loop()

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


def main() -> None:
    """Run the server using stdio (works with Claude Desktop)."""
    # Keep main minimal for mapper-only server (no tshark/pyshark checks)

    # Defaults to stdio transport when executed directly
    try:
        _log("Invoking mcp.run() (stdio)")
        mcp.run()
    except Exception as e:
        _log(f"Server crashed: {e!r}")
        raise


if __name__ == "__main__":
    main()

# ---------------- Windows / general environment diagnostics ----------------

@mcp.tool()
async def environment_diagnostics() -> dict[str, Any]:
    """Return a minimal environment diagnostic relevant to the CVE->CWE mapper.

    This intentionally avoids importing or referencing pyshark/tshark to keep the
    mapper file free of PCAP dependencies.
    """
    return {
        "db_path": str(_MAPPER_DB),
        "db_exists": _MAPPER_DB.exists(),
        "python_version": _sys.version.split()[0],
        "sqlite_version": sqlite3.sqlite_version,
    }


@mcp.tool()
async def system_diagnostics() -> dict:
    """Return system-level diagnostics useful for debugging the mapper.

    Includes OS/platform, Python and SQLite versions, DB path/size, disk usage,
    CPU count, and optional psutil memory/boot info if psutil is available.
    """
    import platform
    import shutil
    import multiprocessing
    import time

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
        out["db_path"] = str(_MAPPER_DB)
        out["db_exists"] = _MAPPER_DB.exists()
        out["db_size_bytes"] = _MAPPER_DB.stat().st_size if _MAPPER_DB.exists() else None
    except Exception:
        out["db_path"] = None
        out["db_exists"] = False
        out["db_size_bytes"] = None

    try:
        du = shutil.disk_usage(str(_DEFAULT_LOCAL_DATA_DIR))
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

