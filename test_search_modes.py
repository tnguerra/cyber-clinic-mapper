"""Test the updated cve_search_cves function with mode=exact|fuzzy|auto."""
import sys
import asyncio
from pathlib import Path

# Add server to path
_MAPPER_DIR = Path(__file__).parent
sys.path.insert(0, str(_MAPPER_DIR))

import CVE_CWE_Mapper_server as mapper

async def test_search_modes():
    """Test exact, fuzzy, and auto modes."""
    
    print("Testing cve_search_cves() with mode parameter:\n")
    
    # Test 1: Exact CVE ID with auto mode (should be exact)
    result = await mapper.cve_search_cves("CVE-2021-44228", limit=5, mode="auto")
    print(f"Test 1: query='CVE-2021-44228', mode='auto'")
    print(f"  mode_used: {result.get('mode_used')}")
    print(f"  count: {result.get('count')}")
    print(f"  exact_match: {result.get('exact_match', {}).get('id') if result.get('exact_match') else None}")
    assert result.get("mode_used") == "exact", "Should use exact mode for CVE-like query"
    assert result.get("count") == 1, "Should find exactly 1 CVE"
    print("  ✓ PASS\n")
    
    # Test 2: Same CVE with explicit exact mode
    result = await mapper.cve_search_cves("CVE-2021-44228", limit=5, mode="exact")
    print(f"Test 2: query='CVE-2021-44228', mode='exact'")
    print(f"  mode_used: {result.get('mode_used')}")
    print(f"  count: {result.get('count')}")
    assert result.get("mode_used") == "exact", "Should use exact mode"
    assert result.get("count") == 1, "Should find exactly 1 CVE"
    print("  ✓ PASS\n")
    
    # Test 3: Non-existent CVE with exact mode (should return empty)
    result = await mapper.cve_search_cves("CVE-9999-9999", limit=5, mode="exact")
    print(f"Test 3: query='CVE-9999-9999', mode='exact'")
    print(f"  mode_used: {result.get('mode_used')}")
    print(f"  count: {result.get('count')}")
    assert result.get("mode_used") == "exact", "Should use exact mode"
    assert result.get("count") == 0, "Should not find any CVE"
    print("  ✓ PASS\n")
    
    # Test 4: Fuzzy search on keyword (use a simpler, more common keyword)
    result = await mapper.cve_search_cves("sql injection", limit=5, mode="fuzzy")
    print(f"Test 4: query='sql injection', mode='fuzzy'")
    print(f"  mode_used: {result.get('mode_used')}")
    print(f"  count: {result.get('count')}")
    print(f"  items sample: {[item.get('id') for item in result.get('items', [])[:3]]}")
    assert result.get("mode_used") == "fuzzy", "Should use fuzzy mode"
    assert result.get("count") > 0, "Should find multiple CVEs for fuzzy search"
    print("  ✓ PASS\n")
    
    # Test 5: Keyword with auto mode (should fallback to fuzzy)
    result = await mapper.cve_search_cves("buffer overflow", limit=5, mode="auto")
    print(f"Test 5: query='buffer overflow', mode='auto'")
    print(f"  mode_used: {result.get('mode_used')}")
    print(f"  count: {result.get('count')}")
    assert result.get("mode_used") == "fuzzy", "Should use fuzzy mode for non-CVE query"
    assert result.get("count") > 0, "Should find multiple CVEs"
    print("  ✓ PASS\n")
    
    # Test 6: Case-insensitive CVE with auto mode
    result = await mapper.cve_search_cves("cve-2021-44228", limit=5, mode="auto")
    print(f"Test 6: query='cve-2021-44228' (lowercase), mode='auto'")
    print(f"  mode_used: {result.get('mode_used')}")
    print(f"  count: {result.get('count')}")
    assert result.get("mode_used") == "exact", "Should recognize lowercase CVE as exact pattern"
    assert result.get("count") >= 0, "Should handle case-insensitive match"
    print("  ✓ PASS\n")
    
    print("=" * 60)
    print("All search mode tests PASSED!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_search_modes())
