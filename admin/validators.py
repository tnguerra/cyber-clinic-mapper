"""XML and data validation tools for the CVE-to-CWE mapper."""

from __future__ import annotations
import os
import xml.etree.ElementTree as ET


async def cve_validate_cwe_xml(cwe_xml_path: str) -> dict:
    """Quickly validate a CWE XML file and report a count of weakness entries.
    
    Args:
        cwe_xml_path: Path to CWE XML file (e.g., cwec_v4.18.xml).
    
    Returns:
        Dictionary with validation result: {ok, elements} or {ok, error}.
    """
    if not cwe_xml_path or not os.path.exists(cwe_xml_path):
        return {"ok": False, "error": "Path not found"}
    try:
        tree = ET.parse(cwe_xml_path)
        root = tree.getroot()
        count = sum(1 for _ in root.iter())
        return {"ok": True, "elements": count}
    except Exception as e:
        return {"ok": False, "error": repr(e)}
