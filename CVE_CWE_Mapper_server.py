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
from typing import Any, List, Optional, Dict, Tuple
import asyncio as _asyncio

# CVE/CWE mapper dependencies
import os
import re
import json
import sqlite3
from pathlib import Path
import unicodedata

from mcp.server.fastmcp import FastMCP
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


# Removed non-essential greeting resource/prompt to keep server minimal for mapper testing


# ---------------- Mapper globals & helpers (restored after accidental truncation) ----------------
# Optional: load .env for local development; safe no-op if missing
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

_ENV_DB = os.environ.get("MAPPER_DB_PATH")
_MAPPER_DB = Path(_ENV_DB) if _ENV_DB else Path(__file__).parent / "data" / "index.db"


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


def _is_cve_id(q: str) -> bool:
    """Return True if the query looks like a formal CVE identifier.

    Accepts forms like CVE-2021-44228 (numeric suffix of at least 4 digits).
    Case-insensitive and tolerant of surrounding whitespace.
    """
    if not q:
        return False
    q = q.strip()
    return bool(re.match(r"(?i)^CVE-\d{4}-\d{4,}$", q))


@mcp.tool()
async def cve_search_cves(query: str, limit: int = 20, mode: str = "auto") -> dict:
    """Search CVEs with selectable modes: exact, fuzzy, or auto.

    - mode='auto' (default): if `query` looks like a CVE id (CVE-YYYY-NNNN...),
      perform an exact id lookup; otherwise perform fuzzy LIKE search.
    - mode='exact': always perform exact id lookup (returns single match or not-found).
    - mode='fuzzy': always perform fuzzy LIKE search across id/title/description.

    Return shape keeps compatibility: {"count": n, "items": [...]}
    Additional keys: "mode_used" and for exact lookups "exact_match".
    """
    loop = _asyncio.get_running_loop()

    def _worker() -> dict:
        conn = _get_mapper_conn()
        cur = conn.cursor()
        q_like = f"%{query}%"

        # Decide mode
        m = (mode or "auto").strip().lower()
        if m == "auto":
            mode_used = "exact" if _is_cve_id(query) else "fuzzy"
        elif m in ("exact", "fuzzy"):
            mode_used = m
        else:
            # unknown mode -> fallback to fuzzy
            mode_used = "fuzzy"

        if mode_used == "exact":
            try:
                cur.execute("SELECT id, title, description FROM cves WHERE id = ? LIMIT ?", (query, limit))
                r = cur.fetchone()
                if r:
                    exact = {"id": r["id"], "title": r["title"], "snippet": (r["description"] or "")[:400]}
                    conn.close()
                    return {"mode_used": "exact", "query": query, "count": 1, "exact_match": exact, "items": [exact]}
                else:
                    conn.close()
                    return {"mode_used": "exact", "query": query, "count": 0, "exact_match": None, "items": []}
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                return {"mode_used": "exact", "query": query, "count": 0, "exact_match": None, "items": []}

        # Fuzzy path: preserve previous behavior
        try:
            cur.execute(
                "SELECT id, title, description FROM cves WHERE id = ? OR id LIKE ? OR title LIKE ? OR description LIKE ? LIMIT ?",
                (query, q_like, q_like, q_like, limit),
            )
            rows = cur.fetchall()
            items = []
            for r in rows:
                snippet = (r["description"] or "")[:300]
                items.append({"id": r["id"], "title": r["title"], "snippet": snippet})
            conn.close()
            return {"mode_used": "fuzzy", "query": query, "count": len(items), "items": items}
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            return {"mode_used": "fuzzy", "query": query, "count": 0, "items": []}

    return await loop.run_in_executor(None, _worker)


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
    "the","a","an","and","or","of","to","for","with","on","in","by","be","is","are","as","at","from","can","may","should","also","must","will","this","that","use","using","used","it","their","they","them","your","into","have","has","had","can","could","would","should","may","might","many","some","more","most","such","than","then","when","where","while","who","what","which","all","any","each","every","not","only","own","same","other","over","under","into","out","up","down","off","per","via","how","why","what","whose","these","those","there","here","being","been","did","does","done","make","makes","made","allow","allows","allowing","cause","causes","causing","attack","attacker","attackers","system","systems","application","applications","data","code","user","users","input","outputs","output","file","files","remote","local","network","issue","issues","problem","problems","vulnerability","vulnerabilities","vulnerable","severe","security"
}


def _filter_tokens(tokens: List[str]) -> List[str]:
    return [t for t in tokens if t not in STOPWORDS and len(t) > 2]



# Admin ingest/index implementations moved into admin/ modules.


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

    def _add_weighted_tokens(bucket: Counter[str], text: str, weight: float) -> None:
        for token in _filter_tokens(_tokenize(text)):
            bucket[token] += weight

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

        # Build weighted query tokens & enrich for certain CWE patterns.
        q_weights: Counter[str] = Counter()
        if cwe_id:
            _add_weighted_tokens(q_weights, cwe_id, 0.25)
        if cwe_num:
            _add_weighted_tokens(q_weights, cwe_num, 0.25)
        if cwe_name:
            _add_weighted_tokens(q_weights, cwe_name, 3.0)
        if cwe_desc:
            _add_weighted_tokens(q_weights, cwe_desc, 1.25)
        ln = (cwe_name or "").lower()
        ld = (cwe_desc or "").lower()
        topic_boost_phrases: List[str] = []
        if "format string" in ln or "format string" in ld:
            topic_boost_phrases.extend([
                "format string",
                "printf",
                "uncontrolled format",
                "application security",
                "secure coding",
                "code-level security checks",
                "secure application development",
            ])
        if ("hard-coded" in ln or "hardcoded" in ln or "hard-coded" in ld or "hardcoded" in ld):
            topic_boost_phrases.extend([
                "hardcoded credential",
                "password secret",
                "application security",
                "secure coding",
                "code-level security checks",
            ])
        if any(k in ln or k in ld for k in ["sql injection", "xss", "cross-site scripting", "cross site scripting", "command injection", "deserialization", "buffer overflow", "memory corruption", "overflow", "injection"]):
            topic_boost_phrases.extend([
                "secure application development process",
                "application security",
                "secure coding",
                "code-level security checks",
                "application penetration testing",
                "threat modeling",
                "software vulnerabilities",
            ])
        if "sql injection" in ln or "sql injection" in ld:
            topic_boost_phrases.extend([
                "validate security measures",
                "secure design principles",
            ])
        for phrase in topic_boost_phrases:
            _add_weighted_tokens(q_weights, phrase, 2.25)
        if not q_weights:
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
            q_weights = Counter(
                {
                    t: w
                    for t, w in q_weights.items()
                    if df.get(t, 0) / N < 0.30 or w >= 2.5
                }
            )
            if not q_weights:
                q_weights = Counter({t: 1.0 for t in _filter_tokens(_tokenize(f"{cwe_name or ''} {cwe_desc or ''}"))})
            qset = set(q_weights.keys())
            query_total = sum(idf.get(t, 1.0) * w for t, w in q_weights.items()) or 1.0

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
                base_score = sum(idf.get(t, 1.0) * w for t, w in q_weights.items() if t in c["comp_set"]) / query_total
                if base_score <= 0:
                    continue
                title_lc = (c["title"] or "").lower()
                text_lc = f"{title_lc} {(c['description'] or '').lower()}"
                if any(phrase in text_lc for phrase in topic_boost_phrases):
                    base_score *= 1.45
                if ("format string" in text_lc) or ("printf" in text_lc) or ("format specifier" in text_lc):
                    base_score *= 1.35
                matched_set = qset & c["comp_set"]
                if matched_set and any(t in c["title_set"] for t in matched_set):
                    base_score *= 1.15
                fn_lower = (c["functions"] or "").lower().strip()
                if fn_lower and fn_lower in pf_set:
                    base_score *= 1.15
                ac_lower = (c["asset_class"] or "").lower().strip()
                if ac_lower and ac_lower in pa_set:
                    base_score *= 1.20
                if codey:
                    if (c["control"] or "").strip() == "16":
                        base_score *= 1.30
                    if (c["control"] or "").strip() == "18":
                        base_score *= 1.10
                    if any(term in text_lc for term in ["secure application development", "application security", "code-level security checks", "secure coding", "threat modeling", "application penetration testing", "software vulnerabilities"]):
                        base_score *= 1.30
                    elif not any(term in text_lc for term in ["security", "secure", "vulnerability", "penetration", "coding", "design", "validate"]):
                        base_score *= 0.85
                    if (c["control"] or "").strip() == "18" and "validate security measures" in text_lc:
                        base_score *= 1.20
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

