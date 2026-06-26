import sys
sys.path.insert(0, ".")
from vulnscanner.knowledge.store import KnowledgeStore

store = KnowledgeStore()

fps = [
    ("bludit", "dbjson.class.php", 32, "DESER-004",
     "$this->unserialize() is a private method calling json_decode(), not PHP built-in unserialize(). "
     "Regex matches method name but $this->methodName() pattern is NOT PHP's unserialize()."),
    ("bludit", "dbjson.class.php", 100, "DESER-004",
     "Private method definition of unserialize() — same file, not a call to PHP built-in."),
    ("Lychee", "CommandExecutor.php", 23, "CMD-004",
     "Testability wrapper around exec(). Callers (GitPull, ComposerCall) pass hardcoded git/composer commands, not user input."),
    ("kimai", "AbstractTwigRenderer.php", 73, "SSTI-003",
     "Template is basename($document->getFilename()) from @invoice/ dir — file path, not user string. "
     "Twig SandboxExtension is enabled with StrictPolicy (lines 66-71)."),
    ("kimai", "UserTest.php", 657, "DESER-004",
     "In test file — deserialization of controlled test fixtures, not real user input."),
    ("InvoicePlane", "Loader.php", 488, "CMD-004",
     "CodeIgniter framework MX/Loader short_open_tag rewriter. eval() processes local PHP view files "
     "from $_ci_path (framework-controlled path), not user input."),
]

for repo, file_, line, rule_id, reason in fps:
    key = store.add_false_positive(repo, file_, line, rule_id, reason=reason)
    print(f"  FP {key}: {rule_id} {repo}/{file_}:{line}")

key = store.add_confirmed(
    "Attendize",
    "public/assets/javascript/app.js",
    105,
    "CMD-004",
    code_snippet="eval(data.runThis)",
    notes="eval(data.runThis) — AJAX response from server executed directly as JavaScript. "
          "If server-side has XSS/injection vulnerability affecting runThis field, attacker gains "
          "client-side RCE. Anti-pattern: server should never return executable JS. CSP would mitigate.",
)
print(f"\n  Confirmed: {key} -- Attendize eval(data.runThis)")

store.add_rule_improvement(
    "DESER-004",
    "Exclude method-call patterns ($this->unserialize() / $obj->unserialize()) — these are user-defined methods, "
    "not PHP built-in unserialize(). Add negative lookbehind for '->' before 'unserialize'. "
    "Confirmed FP: bludit dbjson.class.php wraps json_decode() in private method named unserialize().",
    "FP-0019 (bludit), FP-0020 (bludit)",
)
print("  Rule improvement: DESER-004 method-call exclusion")

stats = store.get_stats()
print(f"\nStats: {stats['confirmed_count']} confirmed, {stats['fp_count']} FPs, precision {stats['precision_pct']}%")
