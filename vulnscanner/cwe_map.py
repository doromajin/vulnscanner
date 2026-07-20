"""Maps VulnScanner rule IDs to CWE numbers for compliance reporting."""
from __future__ import annotations
from typing import Optional

# Specific rule overrides (checked before prefix lookup)
_SPECIFIC: dict[str, int] = {
    "WCRYPTO-008": 338,  # Use of Cryptographically Weak Pseudo-Random Number Generator
    "SEC-005": 312,       # Cleartext Storage of Sensitive Information (private keys)
}

# Prefix → CWE mapping (longest prefix wins; "AST-" stripped before lookup)
_PREFIX: dict[str, int] = {
    "SQL":      89,    # CWE-89:   Improper Neutralization of SQL Commands
    "XSS":      79,    # CWE-79:   Cross-Site Scripting
    "CMD":      78,    # CWE-78:   OS Command Injection
    "PATH":     22,    # CWE-22:   Path Traversal
    "DESER":    502,   # CWE-502:  Deserialization of Untrusted Data
    "SSRF":     918,   # CWE-918:  Server-Side Request Forgery
    "REDIR":    601,   # CWE-601:  URL Redirection to Untrusted Site
    "SSTI":     94,    # CWE-94:   Code Injection
    "PP":       1321,  # CWE-1321: Prototype Pollution
    "SEC":      798,   # CWE-798:  Use of Hard-coded Credentials
    "XXE":      611,   # CWE-611:  Improper Restriction of XML External Entity Reference
    "LDAP":     90,    # CWE-90:   LDAP Injection
    "WCRYPTO":  326,   # CWE-326:  Inadequate Encryption Strength
    "CSRF":     352,   # CWE-352:  Cross-Site Request Forgery
    "NOSQL":    943,   # CWE-943:  Improper Neutralization of Special Elements in Data Query
    "IAC-TF":   284,   # CWE-284:  Improper Access Control (IaC misconfig)
    "IAC-K8S":  250,   # CWE-250:  Execution with Unnecessary Privileges
    "LOG":      117,   # CWE-117:  Improper Output Neutralization for Logs
    "TBV":      501,   # CWE-501:  Trust Boundary Violation
    "SSL":      295,   # CWE-295:  Improper Certificate Validation
    "RACE":     362,   # CWE-362:  Race Condition (TOCTOU)
    "MISS":     306,   # CWE-306:  Missing Authentication for Critical Function
    "DEBUG":    489,   # CWE-489:  Active Debug Code
}


import re as _re

_AST_PREFIX_RE = _re.compile(
    r'^(?:AST|JAST|JSAST|TSAST|GOAST|RBAST|PHAST)-'
)


def get_cwe_id(rule_id: str) -> Optional[int]:
    """Return the CWE ID for *rule_id*, or None if unknown."""
    if rule_id in _SPECIFIC:
        return _SPECIFIC[rule_id]
    # Strip language-specific AST prefixes: AST-SQL-001, PHAST-CMD-001, etc.
    lookup = _AST_PREFIX_RE.sub('', rule_id)
    for prefix, cwe in _PREFIX.items():
        if lookup.startswith(prefix):
            return cwe
    return None
