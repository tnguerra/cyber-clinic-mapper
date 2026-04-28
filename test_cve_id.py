import re

def _is_cve_id(q: str) -> bool:
    """Return True if the query looks like a formal CVE identifier."""
    if not q:
        return False
    q = q.strip()
    return bool(re.match(r"(?i)^CVE-\d{4}-\d{4,}$", q))

# Test cases
test_cases = [
    ("CVE-2021-44228", True),
    ("CVE-2025-0282", True),
    ("cve-2021-44228", True),  # case-insensitive
    ("CVE-2025-123", False),   # too few trailing digits
    ("CVE-2025", False),       # missing trailing number
    ("2021-44228", False),     # missing CVE prefix
    ("log4j remote code", False),  # non-CVE text
    ("", False),               # empty
    ("  CVE-2021-44228  ", True),  # with whitespace
]

print("Testing _is_cve_id():")
for query, expected in test_cases:
    result = _is_cve_id(query)
    status = "PASS" if result == expected else "FAIL"
    print(f"  {status:4}  _is_cve_id({repr(query):30}) = {result:5} (expected {expected})")

all_pass = all(_is_cve_id(q) == e for q, e in test_cases)
print(f"\nOverall: {'All tests passed' if all_pass else 'Some tests failed'}")
