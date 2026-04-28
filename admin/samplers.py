"""Sample retrieval tools for the CVE-to-CWE mapper."""

from __future__ import annotations
import sqlite3


async def cve_get_cve_sample_v2(limit: int, get_mapper_conn) -> dict:
    """Return up to `limit` CVE rows as an object {count: n, items: [...]}.

    Uses inline LIMIT (no parameter binding) to avoid client/bridge issues where
    only the first row was surfaced. Each item contains id, title, snippet.
    
    Args:
        limit: Maximum number of samples to retrieve.
        get_mapper_conn: Function to get a database connection.
    
    Returns:
        Dictionary with sample CVE records: {count, items} or {error, count, items}.
    """
    if limit <= 0:
        limit = 5
    try:
        conn = get_mapper_conn()
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
