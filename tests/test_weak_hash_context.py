"""WCRYPTO-010 context heuristic: identity / integrity digests drop to LOW, credential contexts stay."""
from vulnscanner.analyzers.weak_crypto import WeakCryptoAnalyzer


def _sev(path, src):
    return sorted((f.rule_id, f.severity.name) for f in WeakCryptoAnalyzer().analyze(path, src))


# ---- FP: non-security identity / integrity helpers become LOW (still reported)

def test_csharp_hash_helper_is_low():
    src = (
        "public static class HashingExtensions {\n"
        "    public static string SHA1Hash(this string input) {\n"
        "        using var hash = SHA1.Create();\n"
        "        return GetHash(hash.ComputeHash(Encoding.UTF8.GetBytes(input)));\n"
        "    }\n"
        "}\n"
    )
    assert _sev("Ext/HashingExtensions.cs", src) == [("WCRYPTO-010", "LOW")]


def test_csharp_file_hash_provider_is_low():
    src = (
        "public class HashProvider {\n"
        "    public byte[] ComputeMd5(string path) {\n"
        "        using (var md5 = MD5.Create()) {\n"
        "            return md5.ComputeHash(File.OpenRead(path));\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    assert _sev("Crypto/HashProvider.cs", src) == [("WCRYPTO-010", "LOW")]


def test_go_md5_text_helper_is_low():
    src = (
        'import "crypto/md5"\n'
        "// MD5 creates md5 hash from the provided plain text.\n"
        "func MD5(text string) string {\n"
        "\th := md5.New()\n"
        "\th.Write([]byte(text))\n"
        '\treturn fmt.Sprintf("%x", h.Sum(nil))\n'
        "}\n"
    )
    assert _sev("tools/security/crypto.go", src) == [("WCRYPTO-010", "LOW")]


# ---- TP: credential / auth contexts keep MEDIUM or CRITICAL

def test_go_md5_in_function_with_password_stays_medium():
    src = (
        'import "crypto/md5"\n'
        "func main() {\n"
        '\tconst password = "x"\n'
        "\thash := md5.New()\n"
        '\tfmt.Printf("%x", hash.Sum(nil))\n'
        "}\n"
    )
    assert _sev("main.go", src) == [("WCRYPTO-010", "MEDIUM")]


def test_csharp_hash_helper_with_token_stays_medium():
    src = (
        "public class H {\n"
        "    public string HashToken(string token) {\n"
        "        using var md5 = MD5.Create();\n"
        "        return Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(token)));\n"
        "    }\n"
        "}\n"
    )
    assert _sev("H.cs", src) == [("WCRYPTO-010", "MEDIUM")]


def test_ruby_md5_password_still_critical():
    src = "def check(password)\n  Digest::MD5.hexdigest(password)\nend\n"
    assert _sev("app/models/user.rb", src) == [("WCRYPTO-011", "CRITICAL")]


# ---- FN guard: unrelated function in a file with a hash helper elsewhere is not demoted by name alone

def test_ruby_md5_in_signing_function_stays_medium():
    src = (
        "def sign_request(params)\n"
        "  Digest::MD5.hexdigest(params.to_s)\n"
        "end\n"
    )
    assert _sev("lib/api.rb", src) == [("WCRYPTO-010", "MEDIUM")]
