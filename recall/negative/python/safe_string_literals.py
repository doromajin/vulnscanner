"""Negative test: pattern keywords inside Python string literals should not fire.

These are documentation strings, not executable code — the patterns appear only
as text describing vulnerable functions, not as actual calls with user-tainted data.
"""

# PY-DESER-001 guard: yaml.load() in a description string, not a real call
DESER_MSG = (
    "Avoid yaml.load() without SafeLoader — use yaml.safe_load() instead. "
    "pickle.loads() and marshal.loads() are equally dangerous."
)

# PY-EXEC-001 guard: exec() in a docstring example, not real code
def documented_danger():
    """
    Vulnerable example (DO NOT USE):
        exec(user_input)
        eval(user_input)
    Always use subprocess with a fixed command list instead.
    """
    return "safe"


# re.search() pattern: should not trigger LDAP-001
import re

def find_uid(text: str) -> str | None:
    m = re.search(r"uid=(\d+)", text)
    return m.group(1) if m else None


def parse_all(raw: str) -> dict:
    result = {}
    m_all = re.search(r"All (\d+) checks passed", raw)
    if m_all:
        result["passed"] = int(m_all.group(1))
    m_fail = re.search(r"(\d+) check\(s\) FAILED", raw)
    if m_fail:
        result["failed"] = int(m_fail.group(1))
    return result
