"""Weak hash / cipher / TLS / PRNG and hard-coded credential rules for Go, Ruby, Rust and C#.

Each family has a true-positive, a false-positive (must stay quiet) and a false-negative guard
(a nearby variant that must still be reported).
"""
from vulnscanner.analyzers.hardcoded_secrets import HardcodedSecretsAnalyzer
from vulnscanner.analyzers.weak_crypto import WeakCryptoAnalyzer


def _wc(path, src):
    return sorted((f.rule_id, f.line_number) for f in WeakCryptoAnalyzer().analyze(path, src))


def _sec(path, src):
    return sorted((f.rule_id, f.line_number) for f in HardcodedSecretsAnalyzer().analyze(path, src))


def _ids(path, src):
    return {r for r, _ in _wc(path, src)}


# ---------------------------------------------------------------- weak hash (CWE-328)

def test_go_md5_new_is_flagged():
    src = 'import "crypto/md5"\nfunc f() {\n\th := md5.New()\n\t_ = h\n}\n'
    assert _wc("svc/h.go", src) == [("WCRYPTO-010", 3)]


def test_go_md5_for_password_is_critical():
    src = 'import "crypto/md5"\nfunc f(password string) {\n\tsum := md5.Sum([]byte(password))\n\t_ = sum\n}\n'
    got = WeakCryptoAnalyzer().analyze("svc/h.go", src)
    assert [(f.rule_id, f.severity.name) for f in got] == [("WCRYPTO-011", "CRITICAL")]


def test_go_hmac_sha1_and_sha256_are_clean():
    src = 'func f() {\n\tm := hmac.New(sha1.New, key)\n\th := sha256.New()\n\t_, _ = m, h\n}\n'
    assert _wc("svc/h.go", src) == []


def test_go_md5_etag_is_clean():
    src = 'func f(b []byte) string {\n\treturn fmt.Sprintf("%x", md5.Sum(b)) // etag\n}\n'
    assert _wc("svc/h.go", src) == []


def test_ruby_digest_md5_on_password_is_critical():
    src = "def check(password)\n  Digest::MD5.hexdigest(password)\nend\n"
    assert _wc("app/models/user.rb", src) == [("WCRYPTO-011", 2)]


def test_ruby_openssl_digest_sha1_is_flagged():
    src = "def f(x)\n  OpenSSL::Digest::SHA1.new.digest(x)\nend\n"
    assert _wc("lib/f.rb", src) == [("WCRYPTO-010", 2)]


def test_ruby_sha256_and_gravatar_md5_are_clean():
    src = "def f(x, email)\n  Digest::SHA256.hexdigest(x)\n  Digest::MD5.hexdigest(email) # gravatar\nend\n"
    assert _wc("lib/f.rb", src) == []


def test_rust_md5_compute_is_flagged():
    src = "fn f(d: &[u8]) {\n    let h = md5::compute(d);\n}\n"
    assert _wc("src/h.rs", src) == [("WCRYPTO-010", 2)]


def test_rust_sha1_new_is_flagged_but_use_line_is_not():
    src = "use sha1::Sha1;\nfn f() {\n    let h = Sha1::new();\n}\n"
    assert _wc("src/h.rs", src) == [("WCRYPTO-010", 3)]


def test_rust_sha256_is_clean():
    src = "fn f() {\n    let h = Sha256::new();\n}\n"
    assert _wc("src/h.rs", src) == []


def test_rust_default_hasher_on_password_is_flagged():
    src = ("fn h(data: Req) {\n    let mut hasher = DefaultHasher::new();\n"
           "    data.password.hash(&mut hasher);\n    let x = hasher.finish();\n}\n")
    assert _wc("src/h.rs", src) == [("WCRYPTO-018", 2)]


def test_rust_default_hasher_for_hashmap_key_is_clean():
    src = ("fn h(name: &str) -> u64 {\n    let mut hasher = DefaultHasher::new();\n"
           "    name.hash(&mut hasher);\n    hasher.finish()\n}\n")
    assert _wc("src/h.rs", src) == []


def test_csharp_md5_create_is_flagged():
    src = "class C { void F() {\n  using var m = MD5.Create();\n} }\n"
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-010", 2)]


def test_csharp_sha1_crypto_service_provider_is_flagged():
    src = "class C { void F() {\n  var s = new SHA1CryptoServiceProvider();\n} }\n"
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-010", 2)]


def test_csharp_hmacsha1_and_sha256_are_clean():
    src = "class C { void F() {\n  var a = new HMACSHA1(k);\n  var b = SHA256.Create();\n} }\n"
    assert _wc("Svc/C.cs", src) == []


# ---------------------------------------------------------------- weak ciphers (CWE-327)

def test_go_des_and_rc4_are_flagged():
    src = "func f(k []byte) {\n\tb, _ := des.NewCipher(k)\n\tc, _ := rc4.NewCipher(k)\n\t_, _ = b, c\n}\n"
    assert _wc("svc/c.go", src) == [("WCRYPTO-012", 2), ("WCRYPTO-012", 3)]


def test_go_aes_is_clean():
    assert _wc("svc/c.go", "func f(k []byte) {\n\tb, _ := aes.NewCipher(k)\n\t_ = b\n}\n") == []


def test_ruby_openssl_cipher_des_and_rc4_are_flagged():
    src = "a = OpenSSL::Cipher.new('DES-EDE3-CBC')\nb = OpenSSL::Cipher::RC4.new\n"
    assert _wc("lib/c.rb", src) == [("WCRYPTO-012", 1), ("WCRYPTO-012", 2)]


def test_ruby_openssl_cipher_ecb_is_flagged():
    assert _wc("lib/c.rb", "c = OpenSSL::Cipher.new('aes-128-ecb')\n") == [("WCRYPTO-017", 1)]


def test_ruby_openssl_cipher_gcm_and_variable_are_clean():
    src = "a = OpenSSL::Cipher.new('aes-256-gcm')\nb = OpenSSL::Cipher.new(cipher_type)\n"
    assert _wc("lib/c.rb", src) == []


def test_csharp_des_tripledes_rc2_are_flagged():
    src = ("class C { void F() {\n  var a = DES.Create();\n  var b = new TripleDESCryptoServiceProvider();\n"
           "  var c = RC2.Create();\n} }\n")
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-012", 2), ("WCRYPTO-012", 3), ("WCRYPTO-012", 4)]


def test_csharp_cipher_mode_ecb_is_flagged_and_aes_is_clean():
    src = "class C { void F(Aes a) {\n  a.Mode = CipherMode.ECB;\n  var b = Aes.Create();\n} }\n"
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-001", 2)]


# ---------------------------------------------------------------- certificate validation (CWE-295)

def test_go_insecure_skip_verify_true_is_flagged():
    src = "func f() {\n\tc := &tls.Config{InsecureSkipVerify: true}\n\t_ = c\n}\n"
    assert _wc("svc/t.go", src) == [("WCRYPTO-013", 2)]


def test_go_insecure_skip_verify_false_is_clean():
    src = "func f() {\n\tc := &tls.Config{InsecureSkipVerify: false}\n\t_ = c\n}\n"
    assert _wc("svc/t.go", src) == []


def test_go_insecure_skip_verify_assignment_is_flagged():
    src = "func f(c *tls.Config) {\n\tc.InsecureSkipVerify = true\n}\n"
    assert _wc("svc/t.go", src) == [("WCRYPTO-013", 2)]


def test_ruby_verify_none_is_flagged():
    src = "http = Net::HTTP.new(h)\nhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
    assert _wc("lib/n.rb", src) == [("WCRYPTO-013", 2)]


def test_ruby_verify_peer_is_clean():
    assert _wc("lib/n.rb", "http.verify_mode = OpenSSL::SSL::VERIFY_PEER\n") == []


def test_rust_danger_accept_invalid_certs_is_flagged_and_false_is_clean():
    src = ("fn f() {\n    let a = reqwest::Client::builder().danger_accept_invalid_certs(true);\n"
           "    let b = reqwest::Client::builder().danger_accept_invalid_hostnames(true);\n"
           "    let c = reqwest::Client::builder().danger_accept_invalid_certs(false);\n}\n")
    assert _wc("src/n.rs", src) == [("WCRYPTO-013", 2), ("WCRYPTO-013", 3)]


def test_csharp_validation_callback_returning_true_is_flagged():
    src = ("class C { void F() {\n  ServicePointManager.ServerCertificateValidationCallback += (s, c, ch, e) => true;\n"
           "  var h = new HttpClientHandler { ServerCertificateCustomValidationCallback = "
           "HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };\n} }\n")
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-013", 2), ("WCRYPTO-013", 3)]


def test_csharp_validation_callback_with_real_check_is_clean():
    src = ("class C { void F() {\n  ServicePointManager.ServerCertificateValidationCallback = "
           "(s, c, ch, e) => e == SslPolicyErrors.None;\n} }\n")
    assert _wc("Svc/C.cs", src) == []


# ---------------------------------------------------------------- legacy TLS (CWE-326)

def test_go_min_version_old_is_flagged_and_tls12_is_clean():
    src = ("func f() {\n\ta := &tls.Config{MinVersion: tls.VersionSSL30}\n"
           "\tb := &tls.Config{MinVersion: tls.VersionTLS10}\n"
           "\tc := &tls.Config{MinVersion: tls.VersionTLS12}\n\t_, _, _ = a, b, c\n}\n")
    assert _wc("svc/t.go", src) == [("WCRYPTO-014", 2), ("WCRYPTO-014", 3)]


def test_csharp_legacy_protocols_are_flagged_and_tls12_is_clean():
    src = ("class C { void F() {\n  var a = SslProtocols.Tls | SslProtocols.Tls11;\n"
           "  var b = SslProtocols.Tls12;\n  ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;\n} }\n")
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-014", 2), ("WCRYPTO-014", 4)]


# ---------------------------------------------------------------- weak PRNG (CWE-338)

def test_go_math_rand_into_token_is_flagged():
    src = 'import "math/rand"\nfunc f() {\n\ttoken := rand.Int()\n\t_ = token\n}\n'
    assert _wc("svc/r.go", src) == [("WCRYPTO-015", 3)]


def test_go_math_rand_inside_token_generator_function_is_flagged():
    src = ('import "math/rand"\nfunc GenerateSessionToken() string {\n\tb := make([]byte, 8)\n'
           '\trand.Read(b)\n\treturn string(b)\n}\n')
    assert _wc("svc/r.go", src) == [("WCRYPTO-015", 4)]


def test_go_math_rand_for_jitter_is_clean():
    src = 'import "math/rand"\nfunc f() {\n\tdelay := rand.Intn(100)\n\t_ = delay\n}\n'
    assert _wc("svc/r.go", src) == []


def test_go_crypto_rand_is_clean():
    src = 'import "crypto/rand"\nfunc f() {\n\ttoken := make([]byte, 8)\n\trand.Read(token)\n}\n'
    assert _wc("svc/r.go", src) == []


def test_ruby_rand_into_token_is_flagged_and_securerandom_is_clean():
    src = "token = rand(10**8).to_s\napi_key = SecureRandom.hex(16)\n"
    assert _wc("lib/r.rb", src) == [("WCRYPTO-015", 1)]


def test_ruby_rand_for_non_secret_is_clean():
    assert _wc("lib/r.rb", "delay = rand(5)\n") == []


def test_rust_fastrand_into_token_is_medium_and_thread_rng_is_low():
    src = ("fn f() {\n    let token = fastrand::u64(..);\n    let mut rng = rand::thread_rng();\n"
           "    let secret: u32 = rng.gen();\n}\n")
    got = {(f.rule_id, f.line_number, f.severity.name) for f in WeakCryptoAnalyzer().analyze("src/r.rs", src)}
    assert got == {("WCRYPTO-015", 2, "MEDIUM"), ("WCRYPTO-016", 4, "LOW")}


def test_rust_rng_for_dice_and_osrng_are_clean():
    src = ("fn f() {\n    let mut rng = rand::thread_rng();\n    let roll: u32 = rng.gen_range(1..7);\n}\n")
    assert _wc("src/r.rs", src) == []
    src2 = "fn f() {\n    let mut rng = OsRng;\n    let token: u32 = rng.gen();\n}\n"
    assert _wc("src/r.rs", src2) == []


def test_csharp_new_random_into_token_is_flagged():
    src = "class C { string F() {\n  var rnd = new Random();\n  var token = rnd.Next().ToString();\n  return token;\n} }\n"
    assert _wc("Svc/C.cs", src) == [("WCRYPTO-015", 3)]


def test_csharp_random_for_shuffle_and_crypto_rng_are_clean():
    src = ("class C { void F() {\n  var i = new Random().Next(10);\n"
           "  var token = RandomNumberGenerator.GetBytes(16);\n} }\n")
    assert _wc("Svc/C.cs", src) == []


# ---------------------------------------------------------------- hard-coded credentials (CWE-798)

def test_rust_const_credentials_are_flagged():
    src = ('const JWT_SECRET: &str = "super_secret_jwt_key_12345";\n'
           'static DB_PASSWORD: &str = "password123";\n')
    assert _sec("src/main.rs", src) == [("SEC-015", 1), ("SEC-015", 2)]


def test_rust_const_labels_and_env_names_are_clean():
    src = ('const PASSWORD_FIELD: &str = "password";\n'
           'const TOKEN_HEADER: &str = "x-auth-token";\n'
           'const SECRET_ENV: &str = "APP_SECRET_KEY";\n'
           'const TOKEN_URL: &str = "https://example.org/token";\n'
           'const MAX_TOKEN: usize = 12345678;\n')
    assert _sec("src/main.rs", src) == []


def test_csharp_string_constants_are_flagged_and_name_words_are_clean():
    src = ('class C {\n  private const string ApiSecret = "s3cr3t-Value-9";\n'
           '  public static readonly string DbPassword = "Hunter2!Hunter2";\n'
           '  public const string PasswordKey = "password";\n'
           '  public const string TokenClaim = "access_token";\n}\n')
    # DbPassword is already reported by the generic SEC-001; it must not be reported twice
    assert _sec("Svc/C.cs", src) == [("SEC-001", 3), ("SEC-015", 2)]


def test_go_const_secret_is_flagged_once_without_double_report():
    src = 'package p\nconst password = "secret123"\nconst jwtSecret = "abcDEF123456xyz"\n'
    got = _sec("svc/c.go", src)
    assert got == [("SEC-001", 2), ("SEC-015", 3)]


def test_go_const_label_is_clean():
    src = 'package p\nconst secretKeyHeader = "X-Secret-Key"\nconst tokenPath = "/auth/token"\n'
    assert _sec("svc/c.go", src) == []


def test_ruby_rails_secret_key_base_literal_is_flagged():
    src = 'Railsgoat::Application.config.secret_key_base = "2f1d90a26236c3245d96f5606c201a78"\n'
    assert _sec("config/initializers/secret_token.rb", src) == [("SEC-016", 1)]


def test_ruby_secret_key_base_from_env_is_clean():
    src = 'Rails.application.config.secret_key_base = ENV["SECRET_KEY_BASE"]\n'
    assert _sec("config/initializers/secret_token.rb", src) == []


def test_ruby_constant_key_literal_is_flagged():
    src = 'KEY = "123456789101112123456789101112123456789101112"\n'
    assert _sec("config/initializers/key.rb", src) == [("SEC-015", 1)]


def test_ruby_constant_label_is_clean():
    assert _sec("lib/x.rb", 'TOKEN_KEY = "access_token"\n') == []


def test_csharp_ef_migration_seed_data_is_not_reported():
    src = 'migrationBuilder.InsertData("Users", new { Password = "Hansword123" });\n'
    assert _sec("App/Migrations/20230405_Init.cs", src) == []
    assert _sec("App/Data/Seed.cs", src) == [("SEC-001", 1)]


def test_csharp_md5_inside_gravatar_or_etag_method_is_clean():
    src = ("class C {\n  string GetGravatarUrl(string email) {\n    using (var md5 = MD5.Create())\n"
           "    { return null; }\n  }\n}\n")
    assert _wc("Svc/C.cs", src) == []


def test_rust_test_module_values_are_not_reported():
    src = ('const API_SECRET: &str = "prod-s3cret-value";\n#[cfg(test)]\nmod tests {\n'
           '    const SECRET: &str = "hunter2-s3cr3t";\n    fn f() { let h = md5::compute(b"x"); }\n}\n')
    assert _sec("src/lib.rs", src) == [("SEC-015", 1)]
    assert _wc("src/lib.rs", src) == []


def test_rust_sql_text_constant_named_password_is_clean():
    src = 'const UPDATE_USER_PASSWORD: &str = "UPDATE users SET password = ? WHERE id = ?";\n'
    assert _sec("src/db.rs", src) == []


def test_dotnet_test_project_directory_is_a_test_path():
    from vulnscanner.analyzers.file_context import is_test_path
    assert is_test_path("src/NzbDrone.Core.Test/Foo.cs")
    assert is_test_path("src/Foo.UnitTests/Bar.cs")
    assert not is_test_path("src/Foo.Common/Bar.cs")


def test_placeholder_in_parentheses_is_not_a_password():
    assert _sec("Svc/C.cs", 'class C { void F(B b) {\n  b.Password = "(removed)";\n} }\n') == []


def test_go_insecure_skip_verify_with_gosec_nosec_reason_is_clean():
    src = 'func f() {\n\tc := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in for self-signed endpoint\n\t_ = c\n}\n'
    assert _wc("svc/t.go", src) == []


def test_rust_toplevel_test_module_covers_raw_strings_with_braces():
    from vulnscanner.analyzers.file_context import rust_test_lines
    src = 'fn a() {}\n#[cfg(test)]\nmod tests {\n    const X: &str = r#"{ "a": "}" "#;\n    fn t() {}\n}\n'
    assert rust_test_lines(src) == {2, 3, 4, 5, 6}


def test_ruby_verify_none_behind_user_option_is_demoted_to_low():
    src = "if options[:no_check_certificate]\n  http.verify_mode = OpenSSL::SSL::VERIFY_NONE\nend\n"
    got = WeakCryptoAnalyzer().analyze("extra/h.rb", src)
    assert [(f.rule_id, f.severity.name) for f in got] == [("WCRYPTO-013", "LOW")]
    src2 = "http.verify_mode = OpenSSL::SSL::VERIFY_NONE\n"
    assert [f.severity.name for f in WeakCryptoAnalyzer().analyze("extra/h.rb", src2)] == ["HIGH"]
