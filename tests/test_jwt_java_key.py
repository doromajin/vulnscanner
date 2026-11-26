"""Java JWT hard-coded signing key (JWT-008): TP / FP / FN."""
from vulnscanner.analyzers.jwt_analyzer import JWTAnalyzer


def _ids(src: str) -> set:
    src = "import com.auth0.jwt.algorithms.Algorithm;" + chr(10) + src
    return {f.rule_id for f in JWTAnalyzer().analyze("A.java", src)}


def test_jwt_hardcoded_key_tp():
    assert "JWT-008" in _ids('class A { String s = io.jsonwebtoken.Jwts.builder().signWith(SignatureAlgorithm.HS256, "k3y").compact(); }')
    assert "JWT-008" in _ids('class A { Object a = Algorithm.HMAC256("literal"); }')
    assert "JWT-008" in _ids('class A { private static final String SECRET = "abc";\n Object a = Algorithm.HMAC256(SECRET); }')
    assert "JWT-008" in _ids('class A { private static final String SECRET = "abc";\n'
                             ' private static final String B = java.util.Base64.getEncoder().encodeToString(SECRET.getBytes());\n'
                             ' Object a = io.jsonwebtoken.Jwts.parser().setSigningKey(B); }')


def test_jwt_hardcoded_key_fp():
    assert "JWT-008" not in _ids('class A { Object a = Algorithm.HMAC256(System.getenv("K")); }')
    assert "JWT-008" not in _ids('class A { private static final String SECRET = System.getenv("K");\n Object a = Algorithm.HMAC256(SECRET); }')
    assert "JWT-008" not in _ids('class A { Object a = Algorithm.HMAC256(key); }')


def test_jwt_hardcoded_key_fn_guard_unrelated_file():
    assert "JWT-008" not in _ids('class A { String x = "HMAC256"; void f(String s) { s.length(); } }')
