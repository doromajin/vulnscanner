from pathlib import Path

from vulnscanner.analyzers import missing_auth
from vulnscanner.analyzers.missing_auth import MissingAuthAnalyzer

_CTRL = (
    "package app;\n"
    "@RestController\n"
    "public class C {\n"
    "    @PostMapping(\"/items\")\n"
    "    public String create(@RequestBody String b) { return b; }\n"
    "}\n"
)


def _sev(tmp_path: Path, cfg: str | None) -> set[str]:
    missing_auth._spring_project_requires_auth.cache_clear()
    java = tmp_path / "src" / "main" / "java" / "app"
    java.mkdir(parents=True)
    ctrl = java / "C.java"
    ctrl.write_text(_CTRL, encoding="utf-8")
    if cfg is not None:
        (java / "WebSecurityConfig.java").write_text(cfg, encoding="utf-8")
    return {f.severity.name for f in MissingAuthAnalyzer().analyze(str(ctrl), _CTRL)}


def _cfg(chain: str) -> str:
    return ("@EnableWebSecurity\npublic class WebSecurityConfig {\n"
            "  void configure(HttpSecurity http) throws Exception {\n    http.authorizeRequests()\n" + chain + ";\n  }\n}\n")


def test_no_security_config_keeps_high(tmp_path):
    assert _sev(tmp_path, None) == {"HIGH"}


def test_anyrequest_authenticated_lowers_to_low(tmp_path):
    cfg = _cfg("      .antMatchers(\"/login\").permitAll()\n      .anyRequest().authenticated()")
    assert _sev(tmp_path, cfg) == {"LOW"}


def test_anyrequest_permitall_keeps_high(tmp_path):
    assert _sev(tmp_path, _cfg("      .anyRequest().permitAll()")) == {"HIGH"}
