"""Fix suggestions and CWE mappings for each vulnerability type.

Each entry provides:
  cwe    — CWE identifier (int)
  text   — plain-text fix guidance for CLI --detail output
  markdown — GitHub-flavored markdown for SARIF help.markdown
             (shown in GitHub Code Scanning sidebar and VS Code SARIF viewer)
"""
from __future__ import annotations

from vulnscanner.models import VulnType

# ── Fix suggestion database ───────────────────────────────────────────────────

_DB: dict[VulnType, dict] = {

    VulnType.SQL_INJECTION: {
        "cwe": 89,
        "text": (
            "Use parameterized queries (prepared statements) — never concatenate "
            "user input into SQL strings. Pass user data as bind parameters so the "
            "database driver handles escaping automatically."
        ),
        "markdown": (
            "## Fix: SQL Injection (CWE-89)\n\n"
            "Use **parameterized queries** — never concatenate user input into SQL.\n\n"
            "```python\n"
            "# ❌ Vulnerable\ncursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
            "# ✅ Safe\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
            "```\n\n"
            "**PHP (PDO):** `$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); "
            "$stmt->execute([$id]);`\n\n"
            "**Java (JDBC):** `PreparedStatement ps = conn.prepareStatement(...); "
            "ps.setString(1, id);`\n\n"
            "**References:** "
            "[OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)"
        ),
    },

    VulnType.XSS: {
        "cwe": 79,
        "text": (
            "HTML-encode all user-controlled values before rendering them in a page. "
            "Use your framework's auto-escaping (Jinja2 autoescape, React JSX, "
            "htmlspecialchars() in PHP). Set a Content-Security-Policy header."
        ),
        "markdown": (
            "## Fix: Cross-Site Scripting (CWE-79)\n\n"
            "**HTML-encode output** before inserting user data into the page.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nreturn f\"<p>Hello {name}</p>\"\n\n"
            "# ✅ Safe (Jinja2 with autoescape)\nreturn render_template(\"hello.html\", name=name)\n"
            "# hello.html: <p>Hello {{ name }}</p>  ← auto-escaped\n"
            "```\n\n"
            "**PHP:** `echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');`\n\n"
            "**Node.js:** Use `he.encode(str)` or framework auto-escaping.\n\n"
            "Also set `Content-Security-Policy: default-src 'self'` response header.\n\n"
            "**References:** "
            "[OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)"
        ),
    },

    VulnType.COMMAND_INJECTION: {
        "cwe": 78,
        "text": (
            "Never pass user input to shell commands. Use library functions with "
            "argument arrays instead of shell strings. If shell execution is truly "
            "necessary, validate against a strict allowlist and never use shell=True."
        ),
        "markdown": (
            "## Fix: Command Injection (CWE-78)\n\n"
            "**Avoid shell=True** and string interpolation. Use array-form subprocess calls.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nsubprocess.run(f\"convert {filename}\", shell=True)\n\n"
            "# ✅ Safe — array form, no shell interpretation\n"
            "subprocess.run([\"convert\", filename], shell=False)\n"
            "```\n\n"
            "**PHP:** Use `escapeshellarg()` / `escapeshellcmd()` — or better, use "
            "PHP library equivalents that don't invoke a shell.\n\n"
            "**Ruby:** Use `system('cmd', arg)` array form instead of `system(\"cmd #{arg}\")`.\n\n"
            "**References:** "
            "[OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)"
        ),
    },

    VulnType.PATH_TRAVERSAL: {
        "cwe": 22,
        "text": (
            "Validate and sanitize file paths before use. Use os.path.realpath() to "
            "resolve the canonical path, then assert it starts with the expected "
            "base directory. Reject any path containing '..', null bytes, or "
            "absolute path prefixes from user input."
        ),
        "markdown": (
            "## Fix: Path Traversal (CWE-22)\n\n"
            "Canonicalize the path and assert it's within the allowed base directory.\n\n"
            "```python\n"
            "import os\n\n"
            "BASE = '/var/www/files'\n\n"
            "# ❌ Vulnerable\npath = os.path.join(BASE, user_input)\n\n"
            "# ✅ Safe\npath = os.path.realpath(os.path.join(BASE, user_input))\n"
            "if not path.startswith(BASE + os.sep):\n"
            "    raise ValueError('Invalid path')\n"
            "```\n\n"
            "**PHP:** `realpath()` + `str_starts_with($resolved, $base)`\n\n"
            "**References:** "
            "[OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)"
        ),
    },

    VulnType.SSRF: {
        "cwe": 918,
        "text": (
            "Validate URLs against an allowlist of permitted hosts/schemes before "
            "making outbound requests. Block requests to private IP ranges (127.x, "
            "10.x, 172.16-31.x, 169.254.x). Use a dedicated HTTP proxy that "
            "enforces network-level restrictions."
        ),
        "markdown": (
            "## Fix: Server-Side Request Forgery (CWE-918)\n\n"
            "Validate the target URL against an allowlist before fetching.\n\n"
            "```python\n"
            "from urllib.parse import urlparse\n\n"
            "ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}\n\n"
            "def safe_fetch(url: str) -> bytes:\n"
            "    host = urlparse(url).hostname\n"
            "    if host not in ALLOWED_HOSTS:\n"
            "        raise ValueError(f'Host {host!r} is not allowed')\n"
            "    return requests.get(url, timeout=10).content\n"
            "```\n\n"
            "Also block: `file://`, `gopher://`, `dict://` schemes and "
            "private IPv4/IPv6 ranges.\n\n"
            "**References:** "
            "[OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)"
        ),
    },

    VulnType.OPEN_REDIRECT: {
        "cwe": 601,
        "text": (
            "Validate redirect URLs against an allowlist of permitted destinations. "
            "Prefer relative paths over absolute URLs for redirects. If an absolute "
            "URL is needed, parse it and verify the hostname matches your domain."
        ),
        "markdown": (
            "## Fix: Open Redirect (CWE-601)\n\n"
            "Validate the redirect target before redirecting.\n\n"
            "```python\n"
            "from urllib.parse import urlparse\n\n"
            "ALLOWED_HOSTS = {'example.com', 'www.example.com'}\n\n"
            "def safe_redirect(url: str) -> str:\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.scheme and parsed.netloc not in ALLOWED_HOSTS:\n"
            "        return '/'\n"
            "    return url\n"
            "```\n\n"
            "Prefer returning a relative path (e.g. `/dashboard`) rather than "
            "echoing the user-supplied URL.\n\n"
            "**References:** "
            "[OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)"
        ),
    },

    VulnType.HARDCODED_SECRET: {
        "cwe": 798,
        "text": (
            "Move secrets to environment variables or a secrets manager (HashiCorp "
            "Vault, AWS Secrets Manager, GCP Secret Manager). Never commit credentials "
            "to version control. Rotate any exposed secrets immediately."
        ),
        "markdown": (
            "## Fix: Hardcoded Secret (CWE-798)\n\n"
            "Load secrets from environment variables or a secrets manager — never "
            "hardcode them in source.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nSECRET_KEY = 'my-hardcoded-secret'\n\n"
            "# ✅ Safe\nimport os\nSECRET_KEY = os.environ['SECRET_KEY']\n"
            "```\n\n"
            "Use `.env` files locally (gitignored) with `python-dotenv`. "
            "In CI/CD, inject secrets via the platform's secret store.\n\n"
            "**If this secret was ever committed**, rotate it immediately — "
            "git history is public even after deletion.\n\n"
            "**References:** "
            "[OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)"
        ),
    },

    VulnType.INSECURE_DESERIALIZATION: {
        "cwe": 502,
        "text": (
            "Avoid deserializing untrusted data with pickle, marshal, or yaml.load(). "
            "Use safe alternatives: json.loads() for data exchange, yaml.safe_load() "
            "for YAML, or signed/encrypted tokens (JWT) for state passing."
        ),
        "markdown": (
            "## Fix: Insecure Deserialization (CWE-502)\n\n"
            "**Never deserialize untrusted data** with `pickle`, `marshal`, or "
            "`yaml.load()`. Use safe alternatives.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nobj = pickle.loads(user_data)\n\n"
            "# ✅ Safe — use JSON for data exchange\nimport json\nobj = json.loads(user_data)\n"
            "```\n\n"
            "For YAML: `yaml.safe_load(data)` instead of `yaml.load(data)`.\n\n"
            "If you must deserialize binary objects, sign the payload with HMAC "
            "and verify before deserializing.\n\n"
            "**References:** "
            "[OWASP Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)"
        ),
    },

    VulnType.SSTI: {
        "cwe": 1336,
        "text": (
            "Never pass user input directly to template engine render functions. "
            "Use template files with auto-escaping enabled and pass data as context "
            "variables. If dynamic templates are needed, use a sandboxed environment."
        ),
        "markdown": (
            "## Fix: Server-Side Template Injection (CWE-1336)\n\n"
            "Pass data as **template context variables**, not as part of the template string.\n\n"
            "```python\n"
            "# ❌ Vulnerable\ntemplate = Template(user_input)  # user can inject {{ config }}\n\n"
            "# ✅ Safe\n# Use a static template file; pass user data as context\nreturn render_template('hello.html', name=user_input)\n"
            "```\n\n"
            "For Jinja2: enable `autoescape=True` and use `Environment` with "
            "`SandboxedEnvironment` if templates must be dynamic.\n\n"
            "**References:** "
            "[PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)"
        ),
    },

    VulnType.WEAK_CRYPTOGRAPHY: {
        "cwe": 327,
        "text": (
            "Replace MD5/SHA1/DES/RC4 with current standards: SHA-256/SHA-3 for "
            "hashing, AES-256-GCM for encryption, bcrypt/Argon2 for password "
            "hashing. Use the 'cryptography' library instead of 'hashlib' for "
            "encryption primitives."
        ),
        "markdown": (
            "## Fix: Weak Cryptography (CWE-327)\n\n"
            "Replace deprecated algorithms with modern equivalents.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nimport hashlib\nhashlib.md5(data).hexdigest()\n\n"
            "# ✅ Safe — integrity hash\nhashlib.sha256(data).hexdigest()\n\n"
            "# ✅ Safe — password hashing\nimport bcrypt\nhashed = bcrypt.hashpw(password, bcrypt.gensalt())\n"
            "```\n\n"
            "**Encryption:** AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`\n\n"
            "**TLS:** Minimum TLS 1.2; prefer TLS 1.3.\n\n"
            "**References:** "
            "[OWASP Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)"
        ),
    },

    VulnType.CSRF: {
        "cwe": 352,
        "text": (
            "Add CSRF tokens to all state-changing forms and verify them server-side. "
            "Use SameSite=Strict or SameSite=Lax cookie attribute. Modern frameworks "
            "(Django, Rails, Spring Security) include CSRF middleware — ensure it's enabled. "
            "Remove any decorators that bypass CSRF protection on sensitive views."
        ),
        "markdown": (
            "## Fix: Cross-Site Request Forgery (CWE-352)\n\n"
            "Use CSRF tokens and `SameSite` cookie attribute.\n\n"
            "```html\n<!-- Include CSRF token in every state-changing form -->\n"
            "<form method=\"POST\">\n"
            "  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">\n"
            "</form>\n"
            "```\n\n"
            "**Django:** `CsrfViewMiddleware` is enabled by default in `MIDDLEWARE`. "
            "Remove any decorator that bypasses CSRF protection on views handling POST/PUT/DELETE.\n\n"
            "**Cookie:** `Set-Cookie: session=...; SameSite=Strict; Secure; HttpOnly`\n\n"
            "**References:** "
            "[OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)"
        ),
    },

    VulnType.LDAP_INJECTION: {
        "cwe": 90,
        "text": (
            "Escape special LDAP characters in user input before including it in "
            "search filters. Use ldap3's escape_filter_chars() or an equivalent "
            "library function. Prefer allow-listed attribute names."
        ),
        "markdown": (
            "## Fix: LDAP Injection (CWE-90)\n\n"
            "Escape user input in LDAP filter strings.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nfilter_str = f'(uid={username})'\n\n"
            "# ✅ Safe (ldap3)\nfrom ldap3.utils.conv import escape_filter_chars\n"
            "safe = escape_filter_chars(username)\nfilter_str = f'(uid={safe})'\n"
            "```\n\n"
            "**References:** "
            "[OWASP LDAP Injection](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)"
        ),
    },

    VulnType.PROTOTYPE_POLLUTION: {
        "cwe": 1321,
        "text": (
            "Use Object.create(null) for merge targets to avoid prototype chain. "
            "Validate object keys before merging — reject '__proto__', 'constructor', "
            "and 'prototype'. Use structured-clone() or JSON.parse(JSON.stringify()) "
            "for deep cloning instead of recursive merge."
        ),
        "markdown": (
            "## Fix: Prototype Pollution (CWE-1321)\n\n"
            "Block dangerous property names in object merges.\n\n"
            "```js\n"
            "// ❌ Vulnerable\nfunction merge(dst, src) {\n"
            "  for (const key in src) dst[key] = src[key];\n}\n\n"
            "// ✅ Safe\nfunction merge(dst, src) {\n"
            "  for (const key of Object.keys(src)) {\n"
            "    if (key === '__proto__' || key === 'constructor') continue;\n"
            "    dst[key] = src[key];\n  }\n}\n"
            "```\n\n"
            "Or use `Object.assign(Object.create(null), src)` for the target.\n\n"
            "**References:** "
            "[Prototype Pollution Prevention](https://github.com/nicolo-ribaudo/tc39-proposal-sanitizer)"
        ),
    },

    VulnType.NOSQL_INJECTION: {
        "cwe": 943,
        "text": (
            "Never interpolate user input directly into NoSQL queries. For MongoDB, "
            "use typed driver queries with explicit field types. Validate that numeric "
            "fields are actually numbers (int()/float()) before querying."
        ),
        "markdown": (
            "## Fix: NoSQL Injection (CWE-943)\n\n"
            "Use typed, parameterized queries — never string interpolation.\n\n"
            "```python\n"
            "# ❌ Vulnerable\ncol.find({'user': request.args.get('user')})\n\n"
            "# ✅ Safe — validate and cast types\nusername = str(request.args['user'])\n"
            "if not re.match(r'^[a-zA-Z0-9_]+$', username):\n    abort(400)\n"
            "col.find({'user': username})\n"
            "```\n\n"
            "For MongoDB: never allow operator injection (`$where`, `$regex`) "
            "from user input.\n\n"
            "**References:** "
            "[OWASP NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/)"
        ),
    },

    VulnType.VULNERABLE_DEPENDENCY: {
        "cwe": 1395,
        "text": (
            "Upgrade to the patched version listed in the CVE advisory. Pin "
            "dependency versions in requirements.txt / package.json and run "
            "'pip audit' or 'npm audit' in CI to catch future vulnerabilities."
        ),
        "markdown": (
            "## Fix: Vulnerable Dependency (CWE-1395)\n\n"
            "Upgrade to the patched version from the CVE advisory.\n\n"
            "```bash\n# Python\npip install --upgrade <package>\npip audit\n\n"
            "# Node.js\nnpm audit fix\n```\n\n"
            "Pin versions in `requirements.txt` / `package-lock.json` and run "
            "dependency audits in CI (`pip-audit`, `npm audit`, `trivy`).\n\n"
            "**References:** [OSV.dev](https://osv.dev)"
        ),
    },

    VulnType.EMAIL_INJECTION: {
        "cwe": 93,
        "text": (
            "Strip or reject newline characters (\\r, \\n) from all email header "
            "values before use. Never concatenate user input directly into header "
            "strings. Use a mail library that handles header encoding automatically."
        ),
        "markdown": (
            "## Fix: Email Header Injection (CWE-93)\n\n"
            "Strip newline characters from user-controlled email header values.\n\n"
            "```python\n"
            "# ❌ Vulnerable\nsend_mail(to=user_email, subject=user_subject)\n\n"
            "# ✅ Safe\ndef sanitize_header(value: str) -> str:\n"
            "    return re.sub(r'[\\r\\n]', '', value)\n"
            "send_mail(to=sanitize_header(user_email), subject=sanitize_header(user_subject))\n"
            "```\n\n"
            "**References:** "
            "[CWE-93](https://cwe.mitre.org/data/definitions/93.html)"
        ),
    },

    VulnType.MISSING_AUTHORIZATION: {
        "cwe": 862,
        "text": (
            "Add authorization checks before every sensitive action. Use your "
            "framework's permission decorators (@login_required, @permission_required). "
            "Apply the principle of least privilege — deny by default."
        ),
        "markdown": (
            "## Fix: Missing Authorization (CWE-862)\n\n"
            "Check permissions before executing sensitive operations.\n\n"
            "```python\n"
            "# ❌ Vulnerable — no auth check\ndef delete_user(request, user_id):\n"
            "    User.objects.filter(id=user_id).delete()\n\n"
            "# ✅ Safe\nfrom django.contrib.auth.decorators import permission_required\n\n"
            "@permission_required('auth.delete_user', raise_exception=True)\n"
            "def delete_user(request, user_id):\n    User.objects.filter(id=user_id).delete()\n"
            "```\n\n"
            "**References:** "
            "[OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)"
        ),
    },

    VulnType.IAC_MISCONFIGURATION: {
        "cwe": 16,
        "text": (
            "Review and harden IaC configurations: disable public access, enforce "
            "encryption at rest and in transit, restrict security group ingress to "
            "specific IP ranges, and enable logging/monitoring."
        ),
        "markdown": (
            "## Fix: IaC Misconfiguration (CWE-16)\n\n"
            "Apply security hardening to your infrastructure configuration.\n\n"
            "```hcl\n# ❌ Vulnerable — public S3 bucket\nresource \"aws_s3_bucket\" \"data\" {\n"
            "  bucket = \"my-bucket\"\n}\n\n"
            "# ✅ Safe\nresource \"aws_s3_bucket_public_access_block\" \"data\" {\n"
            "  bucket                  = aws_s3_bucket.data.id\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n}\n"
            "```\n\n"
            "Run `tfsec`, `checkov`, or `terrascan` in CI to catch misconfigurations.\n\n"
            "**References:** "
            "[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)"
        ),
    },
}

# ── Public helpers ────────────────────────────────────────────────────────────

_FALLBACK: dict = {
    "cwe": None,
    "text": "Review the flagged code and ensure user-controlled input is validated, "
            "sanitized, or escaped before use in sensitive operations.",
    "markdown": (
        "## Fix\n\n"
        "Validate, sanitize, or escape all user-controlled input before use in "
        "this context. Consult the OWASP Cheat Sheet Series for language-specific guidance."
    ),
}


def get_fix(vuln_type: VulnType) -> dict:
    """Return the fix entry for *vuln_type* (falls back to a generic entry)."""
    return _DB.get(vuln_type, _FALLBACK)


def get_cwe(vuln_type: VulnType) -> int | None:
    """Return the CWE identifier for *vuln_type*, or None."""
    return _DB.get(vuln_type, {}).get("cwe")
